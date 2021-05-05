// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright 2021, Sandipan Das, IBM Corp.
 * Interfaces to use the Hot-Cold Affinity helper
 */

#define pr_fmt(fmt) "hca: " fmt

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <asm/machdep.h>
#include <asm/debugfs.h>
#include <asm/cacheflush.h>
#include <asm/opal.h>
#include <asm/hca.h>

/* Per-socket configuration */
struct socket_config {
	bool enable;
	u64 page_size;
	u64 overflow_mask;
	u64 sampling_mode;
	u64 sampling_period;
	u64 sampling_upper_thresh;
	u64 sampling_lower_thresh;
	struct dentry *root;

	/* Per-engine configuration */
	struct engine_config {
		bool enable;
		u64 monitor_base;
		u64 monitor_size;
		u64 counter_base;
		u64 counter_size;
		u64 decay_delay;
		struct dentry *root;
	} engine[HCA_ENGINES_PER_SOCKET];
};

static struct socket_config sconfig;
static DEFINE_MUTEX(hca_mutex);

static int hca_engine_setup(unsigned int engine);
static int hca_engine_reset(unsigned int engine);
static int hca_counter_base_init(unsigned int engine);
static int hca_counter_base_free(unsigned int engine);
static void hca_engine_config_debugfs_init(unsigned int engine);
static void hca_engine_config_debugfs_free(unsigned int engine);

static int hca_socket_setup(void);
static int hca_socket_reset(void);
static void hca_socket_config_debugfs_init(void);

static int hca_engine_setup(unsigned int engine)
{
	struct opal_hca_engine_params up;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	econfig = &sconfig.engine[engine];
	BUG_ON(econfig->enable);

	/* Sanitise configuration */
	econfig->monitor_base = HCA_MONITOR_BASE(econfig->monitor_base, econfig->monitor_size);
	econfig->monitor_size = HCA_MONITOR_SIZE(econfig->monitor_size);
	econfig->decay_delay = HCA_DECAY_DELAY(econfig->decay_delay);

	/* Init counter region */
	if (hca_counter_base_init(engine)) {
		/* TODO: error handling */
		hca_engine_reset(engine);
		return -EIO;
	}

	/* Setup OPAL call parameters */
	memset(&up, 0, sizeof(up));
	up.monitor_base = cpu_to_be64(econfig->monitor_base);
	up.monitor_size = cpu_to_be64(econfig->monitor_size);
	up.counter_base = cpu_to_be64(econfig->counter_base);
	up.decay_delay  = cpu_to_be64(econfig->decay_delay);

	/* TODO: better error handling */
	if (opal_hca_engine_setup(engine, (void *) __pa(&up)) != OPAL_SUCCESS) {
		/* TODO: error handling */
		hca_engine_reset(engine);
		return -EINVAL;
	}

	/* Finally, mark as enabled */
	econfig->enable = true;

	return 0;
}

static int hca_engine_reset(unsigned int engine)
{
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	econfig = &sconfig.engine[engine];

	/* TODO: error handling */
	opal_hca_engine_reset(engine);

	/* Free counter region if engine is enabled */
	if (econfig->counter_size)
		hca_counter_base_free(engine);

	/* Reset engine configuration */
	econfig->enable = false;
	econfig->monitor_base = HCA_MONITOR_BASE_DEFAULT;
	econfig->monitor_size = HCA_MONITOR_SIZE_DEFAULT;
	econfig->counter_base = HCA_COUNTER_BASE_DEFAULT;
	econfig->counter_size = HCA_COUNTER_SIZE_DEFAULT;
	econfig->decay_delay = HCA_DECAY_DELAY_DEFAULT;

	return 0;
}

static int hca_socket_setup(void)
{
	struct opal_hca_socket_params cp;
	unsigned int engine;

	BUG_ON(sconfig.enable);

	/* Sanitise configuration */
	sconfig.page_size = HCA_PAGE_SIZE;
	sconfig.overflow_mask = HCA_OVERFLOW_MASK(sconfig.overflow_mask);
	sconfig.sampling_mode = HCA_SAMPLING_MODE(sconfig.sampling_mode);
	sconfig.sampling_period = HCA_SAMPLING_PERIOD(sconfig.sampling_period);
	sconfig.sampling_upper_thresh = HCA_SAMPLING_THRESH(sconfig.sampling_upper_thresh);
	sconfig.sampling_lower_thresh = HCA_SAMPLING_THRESH(sconfig.sampling_lower_thresh);

	/* Setup OPAL call parameters */
	memset(&cp, 0, sizeof(cp));
	cp.page_size = cpu_to_be64(HCA_PAGE_SIZE);
	cp.overflow_mask = cpu_to_be64(sconfig.overflow_mask);
	cp.sampling_mode = cpu_to_be64(sconfig.sampling_mode);
	cp.sampling_period = cpu_to_be64(sconfig.sampling_period);
	cp.sampling_upper_thresh = cpu_to_be64(sconfig.sampling_upper_thresh);
	cp.sampling_lower_thresh = cpu_to_be64(sconfig.sampling_lower_thresh);

	/* TODO: better error handling */
	if (opal_hca_socket_setup((void *) __pa(&cp)) != OPAL_SUCCESS) {
		/* TODO: error handling */
		opal_hca_socket_reset();
		return -EINVAL;
	}

	/* Setup engine sconfiguration */
	for (engine = 0; engine < HCA_ENGINES_PER_SOCKET; engine++)
		hca_engine_config_debugfs_init(engine);

	/* Finally, mark as enabled */
	sconfig.enable = true;

	return 0;
}

static int hca_socket_reset(void)
{
	unsigned int engine;

	/* TODO: error handling */
	opal_hca_socket_reset();

	/* Reset socket configuration */
	sconfig.enable = false;
	sconfig.page_size = HCA_PAGE_SIZE;
	sconfig.overflow_mask = HCA_OVERFLOW_MASK_DEFAULT;
	sconfig.sampling_mode = HCA_SAMPLING_MODE_DEFAULT;
	sconfig.sampling_period = HCA_SAMPLING_PERIOD_DEFAULT;
	sconfig.sampling_upper_thresh = HCA_SAMPLING_THRESH_DEFAULT;
	sconfig.sampling_lower_thresh = HCA_SAMPLING_THRESH_DEFAULT;

	/* Reset engine configuration */
	for (engine = 0; engine < HCA_ENGINES_PER_SOCKET; engine++) {
		/* TODO: error handling */
		hca_engine_reset(engine);
		hca_engine_config_debugfs_free(engine);
	}

	return 0;
}

static int hca_counter_base_init(unsigned int engine)
{
	unsigned long pfn, start_pfn, nr_pages;
	struct engine_config *econfig;
	struct page *page;
	int nid;

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	econfig = &sconfig.engine[engine];
	BUG_ON(!econfig->monitor_size);
	BUG_ON(econfig->counter_base != HCA_COUNTER_BASE_DEFAULT);
	BUG_ON(econfig->counter_size != HCA_COUNTER_SIZE_DEFAULT);

	nid = pfn_to_nid(PFN_PHYS(econfig->monitor_base));
	econfig->counter_size = HCA_COUNTER_SIZE(econfig->monitor_size);
	nr_pages = econfig->counter_size / HCA_PAGE_SIZE;
	page = alloc_contig_pages(nr_pages, GFP_KERNEL | __GFP_NOWARN,
				  nid, NULL);
	if (!page) {
		econfig->counter_base = HCA_COUNTER_BASE_DEFAULT;
		econfig->counter_size = HCA_COUNTER_SIZE_DEFAULT;
		return -ENOMEM;
	}

	start_pfn = page_to_pfn(page);
	econfig->counter_base = PFN_PHYS(start_pfn);
	for (pfn = start_pfn; pfn < start_pfn + nr_pages; pfn++) {
		if (IS_ALIGNED(pfn, PAGES_PER_SECTION))
			cond_resched();
		clear_page(__va(PFN_PHYS(pfn)));
	}

	flush_dcache_range((unsigned long) __va(PFN_PHYS(start_pfn)),
			   (unsigned long) __va(PFN_PHYS(start_pfn + nr_pages)));

	for (pfn = start_pfn; pfn < start_pfn + nr_pages; pfn++)
		__SetPageOffline(pfn_to_page(pfn));

	pr_info("engine %u counter region init at 0x%016llx\n", engine, econfig->counter_base);

	return 0;
}

static int hca_counter_base_free(unsigned int engine)
{
	unsigned long pfn, start_pfn, nr_pages;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	econfig = &sconfig.engine[engine];
	BUG_ON(econfig->counter_base == HCA_COUNTER_BASE_DEFAULT);
	BUG_ON(econfig->counter_size == HCA_COUNTER_SIZE_DEFAULT);

	start_pfn = PHYS_PFN(econfig->counter_base);
	nr_pages = econfig->counter_size / HCA_PAGE_SIZE;

	for (pfn = start_pfn; pfn < start_pfn + nr_pages; pfn++)
		__ClearPageOffline(pfn_to_page(pfn));

	free_contig_range(start_pfn, nr_pages);

	pr_info("engine %u counter region free at 0x%016llx\n", engine, econfig->counter_base);

	return 0;
}

static ssize_t hca_engine_counter_data_read(struct file *file, char __user *ubuf,
					  size_t count, loff_t *ppos)
{
	unsigned int engine = (u64) file->private_data;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	econfig = &sconfig.engine[engine];
	BUG_ON(!econfig->counter_base);
	BUG_ON(!econfig->counter_size);

	if (!econfig->enable)
		return -ENXIO;

	return simple_read_from_buffer(ubuf, count, ppos,
				       __va(econfig->counter_base),
				       econfig->counter_size);
}

static int hca_engine_counter_data_mmap(struct file *file,
				      struct vm_area_struct *vma)
{
	unsigned int engine = (u64) file->private_data;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	econfig = &sconfig.engine[engine];
	BUG_ON(!econfig->counter_base);
	BUG_ON(!econfig->counter_size);

	if (!econfig->enable)
		return -ENXIO;

	if ((econfig->counter_size < (vma->vm_end - vma->vm_start)) ||
	    (econfig->counter_size <= (vma->vm_pgoff << PAGE_SHIFT)))
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start,
			       PHYS_PFN(econfig->counter_base) + vma->vm_pgoff,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static const struct file_operations hca_engine_counter_data_fops = {
	.llseek = default_llseek,
	.read   = hca_engine_counter_data_read,
	.open   = simple_open,
	.mmap   = hca_engine_counter_data_mmap,
};

static int hca_engine_enable_get(void *data, u64 *val)
{
	unsigned int engine = (u64) data;

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	*val = sconfig.engine[engine].enable;

	return 0;
}

static int hca_engine_enable_set(void *data, u64 val)
{
	unsigned int engine = (u64) data;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	econfig = &sconfig.engine[engine];
	mutex_lock(&hca_mutex);

	/* Check if not already enabled or disabled */
	if (!econfig->enable && val)
		/* TODO: error handling */
		hca_engine_setup(engine);
	else if (econfig->enable && !val)
		/* TODO: error handling */
		hca_engine_reset(engine);

	econfig->enable = (val > 0);
	mutex_unlock(&hca_mutex);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_engine_enable_fops,
			hca_engine_enable_get, hca_engine_enable_set, "%llu\n");

static int hca_socket_enable_get(void *data __always_unused, u64 *val)
{
	*val = sconfig.enable;
	return 0;
}

static int hca_socket_enable_set(void *data __always_unused, u64 val)
{
	mutex_lock(&hca_mutex);

	/* Check if not already enabled or disabled */
	if (!sconfig.enable && val)
		/* TODO: error handling */
		hca_socket_setup();
	else if (sconfig.enable && !val)
		/* TODO: error handling */
		hca_socket_reset();

	sconfig.enable = (val > 0);
	mutex_unlock(&hca_mutex);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_socket_enable_fops,
			hca_socket_enable_get, hca_socket_enable_set, "%llu\n");

static void hca_engine_config_debugfs_init(unsigned int engine)
{
	struct engine_config *econfig;
	char name[32];

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	econfig = &sconfig.engine[engine];
	BUG_ON(econfig->enable);
	BUG_ON(sconfig.enable);

	snprintf(name, sizeof(name), "engine%u", engine);
	econfig->root = debugfs_create_dir(name, sconfig.root);
	debugfs_create_file("enable", 0600, econfig->root, (void *)(u64) engine, &hca_engine_enable_fops);
	debugfs_create_x64("monitor-base", 0600, econfig->root, &econfig->monitor_base);
	debugfs_create_u64("monitor-size", 0600, econfig->root, &econfig->monitor_size);
	debugfs_create_u64("counter-size", 0400, econfig->root, &econfig->counter_size);
	debugfs_create_file_unsafe("counter-data", 0400, econfig->root, (void *)(u64) engine, &hca_engine_counter_data_fops);
	debugfs_create_u64("decay-delay", 0600, econfig->root, &econfig->decay_delay);
}

static void hca_engine_config_debugfs_free(unsigned int engine)
{
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_SOCKET);
	econfig = &sconfig.engine[engine];
	BUG_ON(econfig->enable);
	BUG_ON(sconfig.enable);

	debugfs_remove_recursive(econfig->root);
	econfig->root = NULL;
}

static void hca_socket_config_debugfs_init(void)
{
	/* Setup socket configuration debugfs entries */
	sconfig.root = debugfs_create_dir("hca", powerpc_debugfs_root);
	debugfs_create_file("enable", 0600, sconfig.root, NULL, &hca_socket_enable_fops);
	debugfs_create_u64("overflow-mask", 0600, sconfig.root, &sconfig.overflow_mask);
	debugfs_create_u64("sampling-mode", 0600, sconfig.root, &sconfig.sampling_mode);
	debugfs_create_u64("sampling-period", 0600, sconfig.root, &sconfig.sampling_period);
	debugfs_create_u64("sampling-thresh-upper", 0600, sconfig.root, &sconfig.sampling_upper_thresh);
	debugfs_create_u64("sampling-thresh-lower", 0600, sconfig.root, &sconfig.sampling_lower_thresh);
}

static int hca_init(void)
{
	if (!cpu_has_feature(CPU_FTR_ARCH_31) &&
	    PVR_VER(mfspr(SPRN_PVR)) != PVR_POWER10)
		return -ENOTSUPP;

	pr_info("hot-cold affinity init\n");
	memset(&sconfig, 0, sizeof(sconfig));
	/* TODO: error handling */
	hca_socket_reset();
	hca_socket_config_debugfs_init();

	return 0;
}
machine_device_initcall(powernv, hca_init);
