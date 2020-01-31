// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt)	"papr-scm: " fmt

#include <linux/of.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/ndctl.h>
#include <linux/sched.h>
#include <linux/libnvdimm.h>
#include <linux/platform_device.h>
#include <linux/delay.h>

#include <asm/plpar_wrappers.h>

#define BIND_ANY_ADDR (~0ul)

#define PAPR_SCM_DIMM_CMD_MASK \
	((1ul << ND_CMD_GET_CONFIG_SIZE) | \
	 (1ul << ND_CMD_GET_CONFIG_DATA) | \
	 (1ul << ND_CMD_SET_CONFIG_DATA) | \
	 (1ul << ND_CMD_CALL))

#define PAPR_SCM_MAX_PERF_STAT 4096

/*
 * Sub commands for ND_CMD_CALL. To prevent overlap from ND_CMD_*, values for
 * these enums start at 0x10000. These values are then returned from
 * cmd_to_func() making it easy to implement the switch-case block in
 * papr_scm_ndctl()
 */
enum {
	DSM_PAPR_MIN =  0x10000,
	DSM_PAPR_SCM_HEALTH,
	DSM_PAPR_SCM_STATS,
	DSM_PAPR_MAX,
};

/* DIMM health bitmap bitmap indicators */
/* SCM device is encrypted */
#define ND_PAPR_SCM_DIMM_ENCRYPTED		(0x1ULL << 15)
/* SCM device is unable to persist memory contents */
#define ND_PAPR_SCM_DIMM_UNARMED		(0x1ULL << 7)
/* SCM device failed to persist memory contents */
#define ND_PAPR_SCM_DIMM_SHUTDOWN_DIRTY		(0x1ULL << 6)
/* SCM device contents are persisted from previous IPL */
#define ND_PAPR_SCM_DIMM_SHUTDOWN_CLEAN		(0x1ULL << 5)
/* SCM device contents are not persisted from previous IPL */
#define ND_PAPR_SCM_DIMM_EMPTY			(0x1ULL << 4)
/* SCM device memory life remaining is critically low */
#define ND_PAPR_SCM_DIMM_HEALTH_CRITICAL	(0x1ULL << 3)
/* SCM device will be garded off next IPL due to failure */
#define ND_PAPR_SCM_DIMM_HEALTH_FATAL		(0x1ULL << 2)
/* SCM contents cannot persist due to current platform health status */
#define ND_PAPR_SCM_DIMM_HEALTH_UNHEALTHY	(0x1ULL << 1)
/* SCM device is unable to persist memory contents in certain conditions */
#define ND_PAPR_SCM_DIMM_HEALTH_NON_CRITICAL	(0x1ULL << 0)

/* Bits status indicators for health bitmap indicating unarmed dimm */
#define ND_PAPR_SCM_DIMM_UNARMED_MASK (ND_PAPR_SCM_DIMM_UNARMED |	\
					ND_PAPR_SCM_DIMM_HEALTH_UNHEALTHY | \
					ND_PAPR_SCM_DIMM_HEALTH_NON_CRITICAL)

/* Bits status indicators for health bitmap indicating unflushed dimm */
#define ND_PAPR_SCM_DIMM_BAD_SHUTDOWN_MASK (ND_PAPR_SCM_DIMM_SHUTDOWN_DIRTY)

/* Bits status indicators for health bitmap indicating unrestored dimm */
#define ND_PAPR_SCM_DIMM_BAD_RESTORE_MASK  (ND_PAPR_SCM_DIMM_EMPTY)

/* Bit status indicators for smart event notification */
#define ND_PAPR_SCM_DIMM_SMART_EVENT_MASK (ND_PAPR_SCM_DIMM_HEALTH_CRITICAL | \
					   ND_PAPR_SCM_DIMM_HEALTH_FATAL | \
					   ND_PAPR_SCM_DIMM_HEALTH_UNHEALTHY | \
					   ND_PAPR_SCM_DIMM_HEALTH_NON_CRITICAL)

/* Struct as returned by kernel in response to PAPR_DSM_PAPR_SMART_HEALTH */
struct papr_scm_ndctl_health {
	__be64 health_bitmap;
	__be64 health_bitmap_valid;
} __packed;

/* Payload expected with ND_CMD_CALL ioctl from libnvdimm */
struct nd_pkg_papr_scm {
	struct nd_cmd_pkg hdr;		/* Package header containing sub-cmd */
	uint32_t cmd_status;		/* Out: Sub-cmd status returned back */
	uint32_t reserved;
	uint8_t payload[];		/* Out: Sub-cmd data buffer */
} __packed;

/* Buffer layout returned by phyp when reporting drc perf stats */
struct papr_scm_perf_stats {
	uint8_t version;		/* Should be 0x01 */
	uint8_t reserved1;
	__be16 size;			/* Size of this struct in bytes */
	uint8_t buffer[];		/* Performance matrics */
} __packed;

struct papr_scm_priv {
	struct platform_device *pdev;
	struct device_node *dn;
	uint32_t drc_index;
	uint64_t blocks;
	uint64_t block_size;
	int metadata_size;
	bool is_volatile;

	uint64_t bound_addr;

	struct nvdimm_bus_descriptor bus_desc;
	struct nvdimm_bus *bus;
	struct nvdimm *nvdimm;
	struct resource res;
	struct nd_region *region;
	struct nd_interleave_set nd_set;

	/* Health information for the dimm */
	__be64 health_bitmap;
	__be64 health_bitmap_valid;
};

static int drc_pmem_bind(struct papr_scm_priv *p)
{
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	uint64_t saved = 0;
	uint64_t token;
	int64_t rc;

	/*
	 * When the hypervisor cannot map all the requested memory in a single
	 * hcall it returns H_BUSY and we call again with the token until
	 * we get H_SUCCESS. Aborting the retry loop before getting H_SUCCESS
	 * leave the system in an undefined state, so we wait.
	 */
	token = 0;

	do {
		rc = plpar_hcall(H_SCM_BIND_MEM, ret, p->drc_index, 0,
				p->blocks, BIND_ANY_ADDR, token);
		token = ret[0];
		if (!saved)
			saved = ret[1];
		cond_resched();
	} while (rc == H_BUSY);

	if (rc)
		return rc;

	p->bound_addr = saved;
	dev_dbg(&p->pdev->dev, "bound drc 0x%x to 0x%lx\n",
		p->drc_index, (unsigned long)saved);
	return rc;
}

static void drc_pmem_unbind(struct papr_scm_priv *p)
{
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	uint64_t token = 0;
	int64_t rc;

	dev_dbg(&p->pdev->dev, "unbind drc 0x%x\n", p->drc_index);

	/* NB: unbind has the same retry requirements as drc_pmem_bind() */
	do {

		/* Unbind of all SCM resources associated with drcIndex */
		rc = plpar_hcall(H_SCM_UNBIND_ALL, ret, H_UNBIND_SCOPE_DRC,
				 p->drc_index, token);
		token = ret[0];

		/* Check if we are stalled for some time */
		if (H_IS_LONG_BUSY(rc)) {
			msleep(get_longbusy_msecs(rc));
			rc = H_BUSY;
		} else if (rc == H_BUSY) {
			cond_resched();
		}

	} while (rc == H_BUSY);

	if (rc)
		dev_err(&p->pdev->dev, "unbind error: %lld\n", rc);
	else
		dev_dbg(&p->pdev->dev, "unbind drc 0x%x complete\n",
			p->drc_index);

	return;
}

static int drc_pmem_query_n_bind(struct papr_scm_priv *p)
{
	unsigned long start_addr;
	unsigned long end_addr;
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	int64_t rc;


	rc = plpar_hcall(H_SCM_QUERY_BLOCK_MEM_BINDING, ret,
			 p->drc_index, 0);
	if (rc)
		goto err_out;
	start_addr = ret[0];

	/* Make sure the full region is bound. */
	rc = plpar_hcall(H_SCM_QUERY_BLOCK_MEM_BINDING, ret,
			 p->drc_index, p->blocks - 1);
	if (rc)
		goto err_out;
	end_addr = ret[0];

	if ((end_addr - start_addr) != ((p->blocks - 1) * p->block_size))
		goto err_out;

	p->bound_addr = start_addr;
	dev_dbg(&p->pdev->dev, "bound drc 0x%x to 0x%lx\n", p->drc_index, start_addr);
	return rc;

err_out:
	dev_info(&p->pdev->dev,
		 "Failed to query, trying an unbind followed by bind");
	drc_pmem_unbind(p);
	return drc_pmem_bind(p);
}

static int drc_pmem_query_stats(struct papr_scm_priv *p,
				struct papr_scm_perf_stats *stats)
{
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	int64_t rc;

	if (!stats)
		return -EINVAL;

	rc = plpar_hcall(H_SCM_PERFORMANCE_STATS, ret, p->drc_index,
			 __pa(stats));
	if (rc != H_SUCCESS) {
		dev_err(&p->pdev->dev,
			 "Failed to query performance stats, Err:%lld\n", rc);
		return -ENXIO;
	} else
		return 0;
}

static int drc_pmem_query_health(struct papr_scm_priv *p)
{
	unsigned long ret[PLPAR_HCALL_BUFSIZE];
	int64_t rc;

	rc = plpar_hcall(H_SCM_HEALTH, ret, p->drc_index);
	if (rc != H_SUCCESS) {
		dev_err(&p->pdev->dev,
			 "Failed to query health information, Err:%lld\n", rc);
		return -ENXIO;
	}

	/* Store the retrieved health information in dimm platform data */

	p->health_bitmap = ret[0];
	p->health_bitmap_valid = ret[1];

	dev_dbg(&p->pdev->dev,
		"Queried dimm health info. Bitmap:0x%016llx Mask:0x%016llx\n",
		be64_to_cpu(p->health_bitmap),
		be64_to_cpu(p->health_bitmap_valid));

	return 0;
}

static int papr_scm_meta_get(struct papr_scm_priv *p,
			     struct nd_cmd_get_config_data_hdr *hdr)
{
	unsigned long data[PLPAR_HCALL_BUFSIZE];
	unsigned long offset, data_offset;
	int len, read;
	int64_t ret;

	if ((hdr->in_offset + hdr->in_length) > p->metadata_size)
		return -EINVAL;

	for (len = hdr->in_length; len; len -= read) {

		data_offset = hdr->in_length - len;
		offset = hdr->in_offset + data_offset;

		if (len >= 8)
			read = 8;
		else if (len >= 4)
			read = 4;
		else if (len >= 2)
			read = 2;
		else
			read = 1;

		ret = plpar_hcall(H_SCM_READ_METADATA, data, p->drc_index,
				  offset, read);

		if (ret == H_PARAMETER) /* bad DRC index */
			return -ENODEV;
		if (ret)
			return -EINVAL; /* other invalid parameter */

		switch (read) {
		case 8:
			*(uint64_t *)(hdr->out_buf + data_offset) = be64_to_cpu(data[0]);
			break;
		case 4:
			*(uint32_t *)(hdr->out_buf + data_offset) = be32_to_cpu(data[0] & 0xffffffff);
			break;

		case 2:
			*(uint16_t *)(hdr->out_buf + data_offset) = be16_to_cpu(data[0] & 0xffff);
			break;

		case 1:
			*(uint8_t *)(hdr->out_buf + data_offset) = (data[0] & 0xff);
			break;
		}
	}
	return 0;
}

static int papr_scm_meta_set(struct papr_scm_priv *p,
			     struct nd_cmd_set_config_hdr *hdr)
{
	unsigned long offset, data_offset;
	int len, wrote;
	unsigned long data;
	__be64 data_be;
	int64_t ret;

	if ((hdr->in_offset + hdr->in_length) > p->metadata_size)
		return -EINVAL;

	for (len = hdr->in_length; len; len -= wrote) {

		data_offset = hdr->in_length - len;
		offset = hdr->in_offset + data_offset;

		if (len >= 8) {
			data = *(uint64_t *)(hdr->in_buf + data_offset);
			data_be = cpu_to_be64(data);
			wrote = 8;
		} else if (len >= 4) {
			data = *(uint32_t *)(hdr->in_buf + data_offset);
			data &= 0xffffffff;
			data_be = cpu_to_be32(data);
			wrote = 4;
		} else if (len >= 2) {
			data = *(uint16_t *)(hdr->in_buf + data_offset);
			data &= 0xffff;
			data_be = cpu_to_be16(data);
			wrote = 2;
		} else {
			data_be = *(uint8_t *)(hdr->in_buf + data_offset);
			data_be &= 0xff;
			wrote = 1;
		}

		ret = plpar_hcall_norets(H_SCM_WRITE_METADATA, p->drc_index,
					 offset, data_be, wrote);
		if (ret == H_PARAMETER) /* bad DRC index */
			return -ENODEV;
		if (ret)
			return -EINVAL; /* other invalid parameter */
	}

	return 0;
}

/*
 * Validate the input to dimm-control function and return papr_scm specific
 * commands. This does sanity validation to ND_CMD_CALL sub-command packages.
 */
static int cmd_to_func(struct nvdimm *nvdimm, unsigned int cmd, void *buf,
		       unsigned int buf_len)
{
	unsigned long cmd_mask = PAPR_SCM_DIMM_CMD_MASK;
	struct nd_pkg_papr_scm *pkg = (struct nd_pkg_papr_scm *)buf;

	/* Only dimm-specific calls are supported atm */
	if (!nvdimm)
		return -EINVAL;

	if (!test_bit(cmd, &cmd_mask)) {

		pr_debug("%s: Unsupported cmd=%u\n", __func__, cmd);
		return -EINVAL;

	} else if (cmd != ND_CMD_CALL) {

		return cmd;

	} else if (buf_len < sizeof(struct nd_pkg_papr_scm)) {

		pr_debug("%s: Invalid pkg size=%u\n", __func__, buf_len);
		return -EINVAL;

	} else if (pkg->hdr.nd_family != NVDIMM_FAMILY_PAPR) {

		pr_debug("%s: Invalid pkg family=0x%llx\n", __func__,
			 pkg->hdr.nd_family);
		return -EINVAL;

	} else if (pkg->hdr.nd_command <= DSM_PAPR_MIN ||
		   pkg->hdr.nd_command >= DSM_PAPR_MAX) {

		/* for unknown subcommands return ND_CMD_CALL */
		pr_debug("%s: Unknown sub-command=0x%llx\n", __func__,
			 pkg->hdr.nd_command);
		return ND_CMD_CALL;
	}

	/* Return the DSM_PAPR_SCM_* command */
	return pkg->hdr.nd_command;
}

/* Fetch the DIMM health info and populate it in provided papr_scm package */
static int papr_scm_get_health(struct papr_scm_priv *p,
			       struct nd_pkg_papr_scm *pkg)
{
	int rc;
	struct papr_scm_ndctl_health *health =
		(struct papr_scm_ndctl_health *)pkg->payload;

	pkg->hdr.nd_fw_size = sizeof(struct papr_scm_ndctl_health);

	if (pkg->hdr.nd_size_out < sizeof(struct papr_scm_ndctl_health)) {
		rc = -ENOSPC;
		goto out;
	}

	rc = drc_pmem_query_health(p);
	if (rc)
		goto out;

	/* Copy the health data to the payload */
	health->health_bitmap = p->health_bitmap;
	health->health_bitmap_valid = p->health_bitmap_valid;

out:
	/*
	 * Put the error in out package and return success from function
	 * so that errors if any are propogated back to userspace.
	 */
	pkg->cmd_status = rc;
	dev_dbg(&p->pdev->dev, "%s completion code = %d\n", __func__, rc);

	return 0;
}

/* Fetch the DIMM stats and populate it in provided papr_scm package */
static int papr_scm_get_stats(struct papr_scm_priv *p,
			      struct nd_pkg_papr_scm *pkg)
{
	struct papr_scm_perf_stats *retbuffer;
	int rc;
	size_t copysize;

	/* Return buffer for phyp where stats are written */
	retbuffer = kzalloc(PAPR_SCM_MAX_PERF_STAT, GFP_KERNEL);

	if (!retbuffer)
		return -ENOMEM;

	rc = drc_pmem_query_stats(p, retbuffer);
	if (rc)
		goto out;

	/*
	 * Parse the retbuffer, fetch the size returned and return the
	 * first nd_size_out bytes back to userspce.
	 */
	pkg->hdr.nd_fw_size = be16_to_cpu(retbuffer->size);
	copysize = min_t(__u32, pkg->hdr.nd_fw_size, pkg->hdr.nd_size_out);

	memcpy(pkg->payload, retbuffer, copysize);

	/* Verify if the returned buffer was copied completely */
	if (pkg->hdr.nd_fw_size > copysize) {
		rc = -ENOSPC;
		goto out;
	}

out:
	kfree(retbuffer);
	/*
	 * Put the error in out package and return success from function
	 * so that errors if any are propogated back to userspace.
	 */
	pkg->cmd_status = rc;
	dev_dbg(&p->pdev->dev, "%s completion code = %d\n", __func__, rc);

	return 0;
}

int papr_scm_ndctl(struct nvdimm_bus_descriptor *nd_desc, struct nvdimm *nvdimm,
		unsigned int cmd, void *buf, unsigned int buf_len, int *cmd_rc)
{
	struct nd_cmd_get_config_size *get_size_hdr;
	struct papr_scm_priv *p;
	struct nd_pkg_papr_scm *call_pkg = NULL;
	int cmd_in, rc;

	/* Use a local variable in case cmd_rc pointer is NULL */
	if (cmd_rc == NULL)
		cmd_rc = &rc;

	cmd_in = cmd_to_func(nvdimm, cmd, buf, buf_len);
	if (cmd_in < 0) {
		pr_debug("%s: Invalid cmd=%u. Err=%d\n", __func__, cmd, cmd_in);
		return cmd_in;
	}

	p = nvdimm_provider_data(nvdimm);

	switch (cmd_in) {
	case ND_CMD_GET_CONFIG_SIZE:
		get_size_hdr = buf;

		get_size_hdr->status = 0;
		get_size_hdr->max_xfer = 8;
		get_size_hdr->config_size = p->metadata_size;
		*cmd_rc = 0;
		break;

	case ND_CMD_GET_CONFIG_DATA:
		*cmd_rc = papr_scm_meta_get(p, buf);
		break;

	case ND_CMD_SET_CONFIG_DATA:
		*cmd_rc = papr_scm_meta_set(p, buf);
		break;

	case ND_CMD_CALL:
		/* This happens if subcommand package sanity fails */
		call_pkg = (struct nd_pkg_papr_scm *) buf;
		call_pkg->cmd_status = -ENOENT;
		*cmd_rc = 0;
		break;

	case DSM_PAPR_SCM_HEALTH:
		call_pkg = (struct nd_pkg_papr_scm *) buf;
		*cmd_rc = papr_scm_get_health(p, call_pkg);
		break;

	case DSM_PAPR_SCM_STATS:
		call_pkg = (struct nd_pkg_papr_scm *) buf;
		*cmd_rc = papr_scm_get_stats(p, call_pkg);
		break;

	default:
		dev_dbg(&p->pdev->dev, "Unknown command = %d\n", cmd_in);
		*cmd_rc = -EINVAL;
	}

	dev_dbg(&p->pdev->dev, "returned with cmd_rc = %d\n", *cmd_rc);

	return *cmd_rc;
}

static inline int papr_scm_node(int node)
{
	int min_dist = INT_MAX, dist;
	int nid, min_node;

	if ((node == NUMA_NO_NODE) || node_online(node))
		return node;

	min_node = first_online_node;
	for_each_online_node(nid) {
		dist = node_distance(node, nid);
		if (dist < min_dist) {
			min_dist = dist;
			min_node = nid;
		}
	}
	return min_node;
}

static ssize_t papr_stats_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct nvdimm *dimm = to_nvdimm(dev);
	struct papr_scm_priv *p = nvdimm_provider_data(dimm);
	struct papr_scm_perf_stats *retbuffer;
	int rc;

	/* Return buffer for phyp where stats are written */
	retbuffer = kzalloc(PAPR_SCM_MAX_PERF_STAT, GFP_KERNEL);
	if (!retbuffer)
		return -ENOMEM;

	rc = drc_pmem_query_stats(p, retbuffer);
	if (rc)
		goto out;
	else
		rc = sprintf(buf, "%d\n", retbuffer->version);

out:
	kfree(retbuffer);
	return rc;

}
DEVICE_ATTR_RO(papr_stats_version);

static ssize_t papr_health_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct nvdimm *dimm = to_nvdimm(dev);
	struct papr_scm_priv *p = nvdimm_provider_data(dimm);
	int rc;

	rc = drc_pmem_query_health(p);

	if (rc)
		return rc;
	else
		return sprintf(buf, "0x%016llX 0x%016llX\n",
			       be64_to_cpu(p->health_bitmap),
			       be64_to_cpu(p->health_bitmap_valid));
}
DEVICE_ATTR_RO(papr_health);

static ssize_t papr_flags_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct nvdimm *dimm = to_nvdimm(dev);
	struct papr_scm_priv *p = nvdimm_provider_data(dimm);
	u64 health;
	int rc;

	rc = drc_pmem_query_health(p);
	if (rc)
		return rc;

	health = be64_to_cpu(p->health_bitmap) &
		be64_to_cpu(p->health_bitmap_valid);

	/* Check for various masks in bitmap and set the buffer */
	if (health & ND_PAPR_SCM_DIMM_UNARMED_MASK)
		rc += sprintf(buf, "not_armed ");

	if (health & ND_PAPR_SCM_DIMM_BAD_SHUTDOWN_MASK)
		rc += sprintf(buf + rc, "save_fail ");

	if (health & ND_PAPR_SCM_DIMM_BAD_RESTORE_MASK)
		rc += sprintf(buf + rc, "restore_fail ");

	if (health & ND_PAPR_SCM_DIMM_ENCRYPTED)
		rc += sprintf(buf + rc, "encrypted ");

	if (health & ND_PAPR_SCM_DIMM_SMART_EVENT_MASK)
		rc += sprintf(buf + rc, "smart_notify ");

	if (rc > 0)
		rc += sprintf(buf + rc, "\n");
	return rc;
}
DEVICE_ATTR_RO(papr_flags);

/* papr_scm specific dimm attributes */
static struct attribute *papr_scm_nd_attributes[] = {
	&dev_attr_papr_health.attr,
	&dev_attr_papr_stats_version.attr,
	&dev_attr_papr_flags.attr,
	NULL,
};

static struct attribute_group papr_scm_nd_attribute_group = {
	.attrs = papr_scm_nd_attributes,
};

static const struct attribute_group *papr_scm_dimm_attr_groups[] = {
	&papr_scm_nd_attribute_group,
	NULL,
};

static int papr_scm_nvdimm_init(struct papr_scm_priv *p)
{
	struct device *dev = &p->pdev->dev;
	struct nd_mapping_desc mapping;
	struct nd_region_desc ndr_desc;
	unsigned long dimm_flags;
	int target_nid, online_nid;

	p->bus_desc.ndctl = papr_scm_ndctl;
	p->bus_desc.module = THIS_MODULE;
	p->bus_desc.of_node = p->pdev->dev.of_node;
	p->bus_desc.provider_name = kstrdup(p->pdev->name, GFP_KERNEL);

	if (!p->bus_desc.provider_name)
		return -ENOMEM;

	p->bus = nvdimm_bus_register(NULL, &p->bus_desc);
	if (!p->bus) {
		dev_err(dev, "Error creating nvdimm bus %pOF\n", p->dn);
		kfree(p->bus_desc.provider_name);
		return -ENXIO;
	}

	dimm_flags = 0;
	set_bit(NDD_ALIASING, &dimm_flags);

	p->nvdimm = nvdimm_create(p->bus, p, papr_scm_dimm_attr_groups,
				  dimm_flags, PAPR_SCM_DIMM_CMD_MASK, 0, NULL);
	if (!p->nvdimm) {
		dev_err(dev, "Error creating DIMM object for %pOF\n", p->dn);
		goto err;
	}

	if (nvdimm_bus_check_dimm_count(p->bus, 1))
		goto err;

	/* now add the region */

	memset(&mapping, 0, sizeof(mapping));
	mapping.nvdimm = p->nvdimm;
	mapping.start = 0;
	mapping.size = p->blocks * p->block_size; // XXX: potential overflow?

	memset(&ndr_desc, 0, sizeof(ndr_desc));
	target_nid = dev_to_node(&p->pdev->dev);
	online_nid = papr_scm_node(target_nid);
	ndr_desc.numa_node = online_nid;
	ndr_desc.target_node = target_nid;
	ndr_desc.res = &p->res;
	ndr_desc.of_node = p->dn;
	ndr_desc.provider_data = p;
	ndr_desc.mapping = &mapping;
	ndr_desc.num_mappings = 1;
	ndr_desc.nd_set = &p->nd_set;

	if (p->is_volatile)
		p->region = nvdimm_volatile_region_create(p->bus, &ndr_desc);
	else
		p->region = nvdimm_pmem_region_create(p->bus, &ndr_desc);
	if (!p->region) {
		dev_err(dev, "Error registering region %pR from %pOF\n",
				ndr_desc.res, p->dn);
		goto err;
	}
	if (target_nid != online_nid)
		dev_info(dev, "Region registered with target node %d and online node %d",
			 target_nid, online_nid);

	return 0;

err:	nvdimm_bus_unregister(p->bus);
	kfree(p->bus_desc.provider_name);
	return -ENXIO;
}

static int papr_scm_probe(struct platform_device *pdev)
{
	struct device_node *dn = pdev->dev.of_node;
	u32 drc_index, metadata_size;
	u64 blocks, block_size;
	struct papr_scm_priv *p;
	const char *uuid_str;
	u64 uuid[2];
	int rc;

	/* check we have all the required DT properties */
	if (of_property_read_u32(dn, "ibm,my-drc-index", &drc_index)) {
		dev_err(&pdev->dev, "%pOF: missing drc-index!\n", dn);
		return -ENODEV;
	}

	if (of_property_read_u64(dn, "ibm,block-size", &block_size)) {
		dev_err(&pdev->dev, "%pOF: missing block-size!\n", dn);
		return -ENODEV;
	}

	if (of_property_read_u64(dn, "ibm,number-of-blocks", &blocks)) {
		dev_err(&pdev->dev, "%pOF: missing number-of-blocks!\n", dn);
		return -ENODEV;
	}

	if (of_property_read_string(dn, "ibm,unit-guid", &uuid_str)) {
		dev_err(&pdev->dev, "%pOF: missing unit-guid!\n", dn);
		return -ENODEV;
	}


	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	/* optional DT properties */
	of_property_read_u32(dn, "ibm,metadata-size", &metadata_size);

	p->dn = dn;
	p->drc_index = drc_index;
	p->block_size = block_size;
	p->blocks = blocks;
	p->is_volatile = !of_property_read_bool(dn, "ibm,cache-flush-required");

	/* We just need to ensure that set cookies are unique across */
	uuid_parse(uuid_str, (uuid_t *) uuid);
	/*
	 * cookie1 and cookie2 are not really little endian
	 * we store a little endian representation of the
	 * uuid str so that we can compare this with the label
	 * area cookie irrespective of the endian config with which
	 * the kernel is built.
	 */
	p->nd_set.cookie1 = cpu_to_le64(uuid[0]);
	p->nd_set.cookie2 = cpu_to_le64(uuid[1]);

	/* might be zero */
	p->metadata_size = metadata_size;
	p->pdev = pdev;

	/* request the hypervisor to bind this region to somewhere in memory */
	rc = drc_pmem_bind(p);

	/* If phyp says drc memory still bound then force unbound and retry */
	if (rc == H_OVERLAP)
		rc = drc_pmem_query_n_bind(p);

	if (rc != H_SUCCESS) {
		dev_err(&p->pdev->dev, "bind err: %d\n", rc);
		rc = -ENXIO;
		goto err;
	}

	/* setup the resource for the newly bound range */
	p->res.start = p->bound_addr;
	p->res.end   = p->bound_addr + p->blocks * p->block_size - 1;
	p->res.name  = pdev->name;
	p->res.flags = IORESOURCE_MEM;

	rc = papr_scm_nvdimm_init(p);
	if (rc)
		goto err2;

	platform_set_drvdata(pdev, p);

	return 0;

err2:	drc_pmem_unbind(p);
err:	kfree(p);
	return rc;
}

static int papr_scm_remove(struct platform_device *pdev)
{
	struct papr_scm_priv *p = platform_get_drvdata(pdev);

	nvdimm_bus_unregister(p->bus);
	drc_pmem_unbind(p);
	kfree(p->bus_desc.provider_name);
	kfree(p);

	return 0;
}

static const struct of_device_id papr_scm_match[] = {
	{ .compatible = "ibm,pmemory" },
	{ },
};

static struct platform_driver papr_scm_driver = {
	.probe = papr_scm_probe,
	.remove = papr_scm_remove,
	.driver = {
		.name = "papr_scm",
		.of_match_table = papr_scm_match,
	},
};

module_platform_driver(papr_scm_driver);
MODULE_DEVICE_TABLE(of, papr_scm_match);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("IBM Corporation");
