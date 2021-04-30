// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright 2021, Sandipan Das, IBM Corp.
 * Interfaces to use the Hot-Cold Affinity helper
 */

#define pr_fmt(fmt) "hca: " fmt

#include <linux/bitops.h>
#include <linux/string.h>
#include <linux/memblock.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/numa.h>
#include <asm/machdep.h>
#include <asm/debugfs.h>
#include <asm/cacheflush.h>
#include <asm/opal.h>
#include <asm/hca.h>

#define CEIL_DIV(a, b)		(((b) != 0) ? ((a) + (b) - 1) / (b) : 0)

/* Keep track of units from each chip */
struct hca_chip_entry {
	struct hca_unit_entry {
		u64 monitor_base;
		u64 monitor_size;
		u64 counter_base;
		u64 counter_size;
		void *counter_data;

		bool enable;
		struct dentry *dir;
	} units[HCA_MAX_UNITS_PER_CHIP];

	u32 id;
	bool enable;
	struct dentry *dir;
};

static struct hca_chip_entry *hca_chips;
static unsigned int nr_hca_chips;

static struct dentry *hca_debugfs_dir;
static DEFINE_MUTEX(hca_debugfs_mutex);

static int hca_counter_base_init(struct hca_unit_entry *uent, int node)
{
	unsigned long pfn, start_pfn, nr_pages;
	struct page *pages;

	uent->counter_size = (uent->monitor_size / PAGE_SIZE) * HCA_ENTRY_SIZE;
	nr_pages = CEIL_DIV(uent->counter_size, PAGE_SIZE);
	pages = alloc_contig_pages(nr_pages, GFP_KERNEL | __GFP_THISNODE |
				   __GFP_NOWARN, node, NULL);
	if (!pages) {
		uent->counter_base = 0;
		uent->counter_size = 0;
		return -ENOMEM;
	}

	start_pfn = page_to_pfn(pages);
	uent->counter_base = PFN_PHYS(start_pfn);
	for (pfn = start_pfn; pfn < start_pfn + nr_pages; pfn++) {
		if (IS_ALIGNED(pfn, PAGES_PER_SECTION))
			cond_resched();
		clear_page(__va(PFN_PHYS(pfn)));
	}

	flush_dcache_range((unsigned long) __va(PFN_PHYS(start_pfn)),
			   (unsigned long) __va(PFN_PHYS(start_pfn + nr_pages)));

	pr_info("chip: %u, unit: %u counter memory init at 0x%016llx\n",
		cent->id, uidx, uent->counter_base);

	return 0;
}

static int hca_counter_base_free(struct hca_unit_entry *uent)
{
	unsigned long start_pfn, nr_pages;
	struct hca_chip_entry *cent;
	struct hca_unit_entry *uent;

	cent = &hca_chips[cidx];
	uent = &cent->units[uidx];

	pr_info("chip: %u, unit: %u counter memory free at 0x%016llx\n",
		cent->id, uidx, uent->counter_base);

	start_pfn = PHYS_PFN(uent->counter_base);
	nr_pages = CEIL_DIV(uent->counter_size, PAGE_SIZE);
	free_contig_range(start_pfn, nr_pages);
	uent->counter_base = 0;
	uent->counter_size = 0;

	return 0;
}

static int hca_unit_enable_get(void *idx, u64 *val)
{
	u32 cidx, uidx;

	cidx = ((u64) idx) >> 32;
	uidx = ((u64) idx) & U32_MAX;
	*val = hca_chips[cidx].units[uidx].enable;

	return 0;
}

static int hca_unit_enable_set(void *idx, u64 val)
{
	struct opal_hca_unit_params up;
	struct hca_chip_entry *cent;
	struct hca_unit_entry *uent;
	u32 cidx, uidx;
	int rc;

	if (val > 1)
		return -EINVAL;

	rc = -EAGAIN;
	mutex_lock(&hca_debugfs_mutex);
	cidx = ((u64) idx) >> 32;
	uidx = ((u64) idx) & U32_MAX;
	cent = &hca_chips[cidx];
	uent = &cent->units[uidx];

	/* Check if already enabled or disabled */
	if (!uent->enable && val) {
		memset(&up, 0, sizeof(up));
		rc = hca_counter_base_init(uent, cent->id);
		if (rc)
			goto err;

		up.monitor_base = cpu_to_be64(uent->monitor_base);
		up.monitor_size = cpu_to_be64(uent->monitor_size);
		up.counter_base = cpu_to_be64(uent->counter_base);
		up.decay_enable = 0;	/* TODO */
		up.decay_delay  = 0;	/* TODO */

		rc = opal_hca_unit_setup(cent->id, uidx, (void *) __pa(&up));
		if (rc != OPAL_SUCCESS) {
			hca_counter_base_free(cidx, uidx);
			rc = -EIO;
			goto err;
		}

	} else if (uent->enable && !val) {
		if (opal_hca_unit_reset(cent->id, uidx) != OPAL_SUCCESS) {
			rc = -EIO;
			goto err;
		}

		hca_counter_base_free(uent);
	}

	rc = 0;
	uent->enable = val;

err:
	mutex_unlock(&hca_debugfs_mutex);

	return rc;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_unit_enable_fops,
			hca_unit_enable_get, hca_unit_enable_set, "%llu\n");

static void hca_init_unit_debugfs(u32 cidx)
{
	struct hca_chip_entry *cent;
	struct hca_unit_entry *uent;
	char name[32];
	u32 uidx;

	cent = &hca_chips[cidx];
	for (uidx = 0; uidx < HCA_MAX_UNITS_PER_CHIP; uidx++) {
		uent = &cent->units[uidx];
		snprintf(name, sizeof(name), "unit%u", uidx);
		uent->dir = debugfs_create_dir(name, cent->dir);
		debugfs_create_file("enable", S_IRUSR | S_IWUSR, uent->dir,
				    (void *) (((u64) cidx) << 32 | uidx),
				    &hca_unit_enable_fops);
		debugfs_create_x64("monitor-base", 0600, uent->dir, &uent->monitor_base);
		debugfs_create_x64("monitor-size", 0600, uent->dir, &uent->monitor_size);
		debugfs_create_x64("counter-size", 0400, uent->dir, &uent->counter_size);
	}
}

static void hca_free_unit_debugfs(u32 cidx)
{
	struct hca_chip_entry *cent;
	u32 uidx;

	cent = &hca_chips[cidx];
	for (uidx = 0; uidx < HCA_MAX_UNITS_PER_CHIP; uidx++)
		debugfs_remove_recursive(cent->units[uidx].dir);
}

static int hca_chip_enable_get(void *idx, u64 *val)
{
	u32 cidx;

	cidx = ((u64) idx) & U32_MAX;
	*val = hca_chips[cidx].enable;

	return 0;
}

static int hca_chip_enable_set(void *idx, u64 val)
{
	struct opal_hca_chip_params cp;
	struct hca_chip_entry *cent;
	u32 cidx;
	int rc;

	if (val > 1)
		return -EINVAL;

	rc = -EAGAIN;
	mutex_lock(&hca_debugfs_mutex);
	cidx = ((u64) idx) & U32_MAX;
	cent = &hca_chips[cidx];

	/* Check if already enabled or disabled */
	if (!cent->enable && val) {
		memset(&cp, 0, sizeof(cp));
#ifdef CONFIG_PPC_4K_PAGES
		cp.page_size = cpu_to_be64(HCA_PAGE_SIZE_4KB);
#else /* CONFIG_PPC_64K_PAGES */
		cp.page_size = cpu_to_be64(HCA_PAGE_SIZE_64KB);
#endif
		cp.counter_mask = cpu_to_be64(HCA_COUNTER_MASK_DEFAULT);
		cp.cmd_sampling_rate = cpu_to_be64(HCA_CMD_SAMPLING_RATE_DEFAULT);
		cp.cmd_sampling_period = 0;	/* TODO */
		cp.upper_cmd_threshold = 0;	/* TODO */
		cp.lower_cmd_threshold = 0;	/* TODO */

		rc = opal_hca_chip_setup(cent->id, (void *) __pa(&cp));
		if (rc != OPAL_SUCCESS) {
			rc = -EIO;
			goto err;
		}

		hca_init_unit_debugfs(cidx);
	} else if (cent->enable && !val) {
		opal_hca_chip_reset(cent->id);
		hca_free_unit_debugfs(cidx);
	}

	rc = 0;
	cent->enable = val;

err:
	mutex_unlock(&hca_debugfs_mutex);

	return rc;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_chip_enable_fops,
			hca_chip_enable_get, hca_chip_enable_set, "%llu\n");

static void hca_init_chip_debugfs(void)
{
	struct hca_chip_entry *cent;
	u32 node, cidx;
	char name[32];

	hca_debugfs_dir = debugfs_create_dir("hca", powerpc_debugfs_root);
	cidx = 0;

	/* TODO: use device tree to find chip information */
	for_each_online_node(node) {
		cent = &hca_chips[cidx];
		cent->id = node;
		snprintf(name, sizeof(name), "chip%u", cent->id);
		cent->dir = debugfs_create_dir(name, hca_debugfs_dir);
		debugfs_create_file("enable", S_IRUSR | S_IWUSR, cent->dir,
				    (void *) (u64) cidx,
				    &hca_chip_enable_fops);
		cidx++;
	}
}

static int hca_init(void)
{
	if (!cpu_has_feature(CPU_FTR_ARCH_31) &&
	    PVR_VER(mfspr(SPRN_PVR)) != PVR_POWER10)
		return -ENOTSUPP;

	pr_info("hot-cold affinity init\n");

	/* TODO: use device tree to find chip information */
	nr_hca_chips = nr_online_nodes;
	hca_chips = kzalloc(nr_hca_chips * sizeof(*hca_chips), GFP_KERNEL);
	hca_init_chip_debugfs();
	return 0;
}
machine_device_initcall(powernv, hca_init);
