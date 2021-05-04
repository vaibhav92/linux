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

/* Per-chip configuration */
struct chip_config {
	bool enable;
	u64 page_size;
	u64 overflow_mask;
	u64 sampling_mode;
	u64 sampling_period;
	u64 sampling_upper_thresh;
	u64 sampling_lower_thresh;
	struct dentry *root;

	/* Per-unit configuration */
	struct unit_config {
		bool enable;
		u64 monitor_base;
		u64 monitor_size;
		u64 counter_base;
		u64 counter_size;
		u64 decay_delay;
		struct dentry *root;
	} unit[HCA_UNITS_PER_CHIP];
};

static struct chip_config config;
static DEFINE_MUTEX(hca_mutex);

static int hca_unit_setup(unsigned int unit);
static int hca_unit_reset(unsigned int unit);
static int hca_counter_base_init(unsigned int unit);
static int hca_counter_base_free(unsigned int unit);
static void hca_unit_config_debugfs_init(unsigned int unit);
static void hca_unit_config_debugfs_free(unsigned int unit);

static int hca_chip_setup(void);
static int hca_chip_reset(void);
static void hca_chip_config_debugfs_init(void);

static int hca_unit_setup(unsigned int unit)
{
	struct opal_hca_unit_params up;
	struct unit_config *uconfig;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uconfig = &config.unit[unit];
	BUG_ON(uconfig->enable);

	/* Sanitise configuration */
	uconfig->monitor_base = HCA_MONITOR_BASE(uconfig->monitor_base, uconfig->monitor_size);
	uconfig->monitor_size = HCA_MONITOR_SIZE(uconfig->monitor_size);
	uconfig->decay_delay = HCA_DECAY_DELAY(uconfig->decay_delay);

	/* Init counter region */
	if (hca_counter_base_init(unit))
		/* TODO: error handling */
		hca_unit_reset(unit);

	/* Setup OPAL call parameters */
	memset(&up, 0, sizeof(up));
	up.monitor_base = cpu_to_be64(uconfig->monitor_base);
	up.monitor_size = cpu_to_be64(uconfig->monitor_size);
	up.counter_base = cpu_to_be64(uconfig->counter_base);
	up.decay_delay  = cpu_to_be64(uconfig->decay_delay);

	/* TODO: better error handling */
	if (opal_hca_unit_setup(unit, (void *) __pa(&up)) != OPAL_SUCCESS) {
		/* TODO: error handling */
		hca_unit_reset(unit);
		return -EINVAL;
	}

	/* Finally, mark as enabled */
	uconfig->enable = true;

	return 0;
}

static int hca_unit_reset(unsigned int unit)
{
	struct unit_config *uconfig;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uconfig = &config.unit[unit];

	/* TODO: error handling */
	opal_hca_unit_reset(unit);

	/* Free counter region if unit is enabled */
	if (uconfig->enable)
		hca_counter_base_free(unit);

	/* Reset unit configuration */
	uconfig->enable = false;
	uconfig->monitor_base = HCA_MONITOR_BASE_DEFAULT;
	uconfig->monitor_size = HCA_MONITOR_SIZE_DEFAULT;
	uconfig->counter_base = HCA_COUNTER_BASE_DEFAULT;
	uconfig->counter_size = HCA_COUNTER_SIZE_DEFAULT;
	uconfig->decay_delay = HCA_DECAY_DELAY_DEFAULT;

	return 0;
}

static int hca_chip_setup(void)
{
	struct opal_hca_chip_params cp;
	unsigned int unit;

	BUG_ON(config.enable);

	/* Sanitise configuration */
	config.page_size = HCA_PAGE_SIZE;
	config.overflow_mask = HCA_OVERFLOW_MASK(config.overflow_mask);
	config.sampling_mode = HCA_SAMPLING_MODE(config.sampling_mode);
	config.sampling_period = HCA_SAMPLING_PERIOD(config.sampling_period);
	config.sampling_upper_thresh = HCA_SAMPLING_THRESH(config.sampling_upper_thresh);
	config.sampling_lower_thresh = HCA_SAMPLING_THRESH(config.sampling_lower_thresh);

	/* Setup OPAL call parameters */
	memset(&cp, 0, sizeof(cp));
	cp.page_size = cpu_to_be64(HCA_PAGE_SIZE);
	cp.overflow_mask = cpu_to_be64(config.overflow_mask);
	cp.sampling_mode = cpu_to_be64(config.sampling_mode);
	cp.sampling_period = cpu_to_be64(config.sampling_period);
	cp.sampling_upper_thresh = cpu_to_be64(config.sampling_upper_thresh);
	cp.sampling_lower_thresh = cpu_to_be64(config.sampling_lower_thresh);

	/* TODO: better error handling */
	if (opal_hca_chip_setup((void *) __pa(&cp)) != OPAL_SUCCESS) {
		/* TODO: error handling */
		opal_hca_chip_reset();
		return -EINVAL;
	}

	/* Setup unit configuration */
	for (unit = 0; unit < HCA_UNITS_PER_CHIP; unit++)
		hca_unit_config_debugfs_init(unit);

	/* Finally, mark as enabled */
	config.enable = true;

	return 0;
}

static int hca_chip_reset(void)
{
	unsigned int unit;

	/* TODO: error handling */
	opal_hca_chip_reset();

	/* Reset chip configuration */
	config.enable = false;
	config.page_size = HCA_PAGE_SIZE;
	config.overflow_mask = HCA_OVERFLOW_MASK_DEFAULT;
	config.sampling_mode = HCA_SAMPLING_MODE_DEFAULT;
	config.sampling_period = HCA_SAMPLING_PERIOD_DEFAULT;
	config.sampling_upper_thresh = HCA_SAMPLING_THRESH_DEFAULT;
	config.sampling_lower_thresh = HCA_SAMPLING_THRESH_DEFAULT;

	/* Reset unit configuration */
	for (unit = 0; unit < HCA_UNITS_PER_CHIP; unit++) {
		/* TODO: error handling */
		hca_unit_reset(unit);
		hca_unit_config_debugfs_free(unit);
	}

	return 0;
}

static int hca_counter_base_init(unsigned int unit)
{
	unsigned long pfn, start_pfn, nr_pages;
	struct unit_config *uconfig;
	struct page *page;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uconfig = &config.unit[unit];
	BUG_ON(!uconfig->monitor_size);
	BUG_ON(uconfig->counter_base != HCA_COUNTER_BASE_DEFAULT);
	BUG_ON(uconfig->counter_size != HCA_COUNTER_SIZE_DEFAULT);

	uconfig->counter_size = HCA_COUNTER_SIZE(uconfig->monitor_size);
	nr_pages = uconfig->counter_size / HCA_PAGE_SIZE;
	page = alloc_contig_pages(nr_pages, GFP_KERNEL | __GFP_NOWARN,
				  pfn_to_nid(PFN_PHYS(uconfig->monitor_base)),
				  NULL);
	if (!page) {
		uconfig->counter_base = HCA_COUNTER_BASE_DEFAULT;
		uconfig->counter_size = HCA_COUNTER_SIZE_DEFAULT;
		return -ENOMEM;
	}

	start_pfn = page_to_pfn(page);
	uconfig->counter_base = PFN_PHYS(start_pfn);
	for (pfn = start_pfn; pfn < start_pfn + nr_pages; pfn++) {
		if (IS_ALIGNED(pfn, PAGES_PER_SECTION))
			cond_resched();
		clear_page(pfn_to_kaddr(pfn));
	}

	flush_dcache_range((unsigned long) pfn_to_kaddr(start_pfn),
			   (unsigned long) pfn_to_kaddr(start_pfn + nr_pages));

	pr_info("unit %u counter region init at 0x%016llx\n", unit, uconfig->counter_base);

	return 0;
}

static int hca_counter_base_free(unsigned int unit)
{
	unsigned long start_pfn, nr_pages;
	struct unit_config *uconfig;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uconfig = &config.unit[unit];
	BUG_ON(uconfig->counter_base == HCA_COUNTER_BASE_DEFAULT);
	BUG_ON(uconfig->counter_size == HCA_COUNTER_SIZE_DEFAULT);

	start_pfn = PHYS_PFN(uconfig->counter_base);
	nr_pages = uconfig->counter_size / HCA_PAGE_SIZE;
	free_contig_range(start_pfn, nr_pages);

	pr_info("unit %u counter region free at 0x%016llx\n", unit, uconfig->counter_base);

	return 0;
}

static ssize_t hca_unit_counter_data_read(struct file *file, char __user *ubuf,
					  size_t count, loff_t *ppos)
{
	unsigned int unit = (u64) file->private_data;
	struct unit_config *uconfig;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uconfig = &config.unit[unit];
	BUG_ON(!uconfig->counter_base);
	BUG_ON(!uconfig->counter_size);

	if (!uconfig->enable)
		return -ENXIO;

	return simple_read_from_buffer(ubuf, count, ppos,
				       __va(uconfig->counter_base),
				       uconfig->counter_size);
}

static int hca_unit_counter_data_mmap(struct file *file,
				      struct vm_area_struct *vma)
{
	unsigned int unit = (u64) file->private_data;
	struct unit_config *uconfig;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uconfig = &config.unit[unit];
	BUG_ON(!uconfig->counter_base);
	BUG_ON(!uconfig->counter_size);

	if (!uconfig->enable)
		return -ENXIO;

	if ((uconfig->counter_size < (vma->vm_end - vma->vm_start)) ||
	    (uconfig->counter_size <= (vma->vm_pgoff << PAGE_SHIFT)))
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start,
			       PHYS_PFN(uconfig->counter_base) + vma->vm_pgoff,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static const struct file_operations hca_unit_counter_data_fops = {
	.llseek = default_llseek,
	.read   = hca_unit_counter_data_read,
	.open   = simple_open,
	.mmap   = hca_unit_counter_data_mmap,
};

static int hca_unit_enable_get(void *data, u64 *val)
{
	unsigned int unit = (u64) data;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	*val = config.unit[unit].enable;

	return 0;
}

static int hca_unit_enable_set(void *data, u64 val)
{
	unsigned int unit = (u64) data;
	struct unit_config *uconfig;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uconfig = &config.unit[unit];
	mutex_lock(&hca_mutex);

	/* Check if not already enabled or disabled */
	if (!uconfig->enable && val)
		/* TODO: error handling */
		hca_unit_setup(unit);
	else if (uconfig->enable && !val)
		/* TODO: error handling */
		hca_unit_reset(unit);

	uconfig->enable = (val > 0);
	mutex_unlock(&hca_mutex);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_unit_enable_fops,
			hca_unit_enable_get, hca_unit_enable_set, "%llu\n");

static int hca_chip_enable_get(void *data __always_unused, u64 *val)
{
	*val = config.enable;
	return 0;
}

static int hca_chip_enable_set(void *data __always_unused, u64 val)
{
	mutex_lock(&hca_mutex);

	/* Check if not already enabled or disabled */
	if (!config.enable && val)
		/* TODO: error handling */
		hca_chip_setup();
	else if (config.enable && !val)
		/* TODO: error handling */
		hca_chip_reset();

	config.enable = (val > 0);
	mutex_unlock(&hca_mutex);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_chip_enable_fops,
			hca_chip_enable_get, hca_chip_enable_set, "%llu\n");

static void hca_unit_config_debugfs_init(unsigned int unit)
{
	struct unit_config *uconfig;
	char name[32];

	uconfig = &config.unit[unit];
	snprintf(name, sizeof(name), "unit%u", unit);
	uconfig->root = debugfs_create_dir(name, config.root);
	debugfs_create_file("enable", 0600, uconfig->root, (void *)(u64) unit, &hca_unit_enable_fops);
	debugfs_create_x64("monitor-base", 0600, uconfig->root, &uconfig->monitor_base);
	debugfs_create_u64("monitor-size", 0600, uconfig->root, &uconfig->monitor_size);
	debugfs_create_u64("counter-size", 0400, uconfig->root, &uconfig->counter_size);
	debugfs_create_file_unsafe("counter-data", 0400, uconfig->root, (void *)(u64) unit, &hca_unit_counter_data_fops);
}

static void hca_unit_config_debugfs_free(unsigned int unit)
{
	debugfs_remove_recursive(config.unit[unit].root);
}

static void hca_chip_config_debugfs_init(void)
{
	/* Setup chip configuration debugfs entries */
	config.root = debugfs_create_dir("hca", powerpc_debugfs_root);
	debugfs_create_file("enable", 0600, config.root, NULL, &hca_chip_enable_fops);
	debugfs_create_u64("overflow-mask", 0600, config.root, &config.overflow_mask);
	debugfs_create_u64("sampling-mode", 0600, config.root, &config.sampling_mode);
	debugfs_create_u64("sampling-period", 0600, config.root, &config.sampling_period);
	debugfs_create_u64("sampling-thresh-upper", 0600, config.root, &config.sampling_upper_thresh);
	debugfs_create_u64("sampling-thresh-lower", 0600, config.root, &config.sampling_lower_thresh);
}

static int hca_init(void)
{
	if (!cpu_has_feature(CPU_FTR_ARCH_31) &&
	    PVR_VER(mfspr(SPRN_PVR)) != PVR_POWER10)
		return -ENOTSUPP;

	pr_info("hot-cold affinity init\n");
	memset(&config, 0, sizeof(config));
	/* TODO: error handling */
	hca_chip_reset();
	hca_chip_config_debugfs_init();

	return 0;
}
machine_device_initcall(powernv, hca_init);
