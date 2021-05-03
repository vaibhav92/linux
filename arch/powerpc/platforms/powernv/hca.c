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

/* Keep track of units from each chip */
struct hca_chip_entry {
	struct hca_unit_entry {
		u64 monitor_base;
		u64 monitor_size;
		u64 counter_base;
		u64 counter_size;
		bool enable;
		struct dentry *dir;
	} unit[HCA_UNITS_PER_CHIP];

	bool enable;
	struct dentry *dir;
} chip;

static struct dentry *hca_debugfs_dir;
static DEFINE_MUTEX(hca_debugfs_mutex);

static int hca_counter_base_init(unsigned int unit)
{
	unsigned long pfn, start_pfn, nr_pages;
	struct hca_unit_entry *uent;
	struct page *page;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uent = &chip.unit[unit];
	BUG_ON(uent->counter_base);
	BUG_ON(uent->counter_size);
	BUG_ON(!IS_ALIGNED(uent->monitor_size, PAGE_SIZE));

	uent->counter_size = (uent->monitor_size / PAGE_SIZE) * HCA_ENTRY_SIZE;
	uent->counter_size = ALIGN(uent->counter_size, PAGE_SIZE);
	nr_pages = uent->counter_size / PAGE_SIZE;
	page = alloc_contig_pages(nr_pages, GFP_KERNEL | __GFP_NOWARN,
				  pfn_to_nid(PFN_PHYS(uent->monitor_base)),
				  NULL);
	if (!page) {
		uent->counter_base = 0;
		uent->counter_size = 0;
		return -ENOMEM;
	}

	start_pfn = page_to_pfn(page);
	uent->counter_base = PFN_PHYS(start_pfn);
	for (pfn = start_pfn; pfn < start_pfn + nr_pages; pfn++) {
		if (IS_ALIGNED(pfn, PAGES_PER_SECTION))
			cond_resched();
		clear_page(__va(PFN_PHYS(pfn)));
	}

	flush_dcache_range((unsigned long) pfn_to_kaddr(start_pfn),
			   (unsigned long) pfn_to_kaddr(start_pfn + nr_pages));

	pr_info("unit: %u counter memory init at 0x%016llx\n",
		unit, uent->counter_base);

	return 0;
}

static int hca_counter_base_free(unsigned int unit)
{
	unsigned long start_pfn, nr_pages;
	struct hca_unit_entry *uent;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uent = &chip.unit[unit];
	BUG_ON(!uent->counter_base);
	BUG_ON(!uent->counter_size);

	start_pfn = PHYS_PFN(uent->counter_base);
	nr_pages = uent->counter_size / PAGE_SIZE;
	free_contig_range(start_pfn, nr_pages);

	pr_info("unit: %u counter memory free at 0x%016llx\n",
		unit, uent->counter_base);

	uent->counter_base = 0;
	uent->counter_size = 0;

	return 0;
}

static int hca_unit_enable_get(void *data, u64 *val)
{
	unsigned int unit = (u64) data;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	*val = chip.unit[unit].enable;

	return 0;
}

static int hca_unit_enable_set(void *data, u64 val)
{
	struct opal_hca_unit_params up;
	unsigned int unit = (u64) data;
	struct hca_unit_entry *uent;
	int rc = -EAGAIN;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);

	if (val > 1)
		return -EINVAL;

	uent = &chip.unit[unit];
	mutex_lock(&hca_debugfs_mutex);

	/* Check if already enabled or disabled */
	if (!uent->enable && val) {
		memset(&up, 0, sizeof(up));
		rc = hca_counter_base_init(unit);
		if (rc)
			goto out;

		up.monitor_base = cpu_to_be64(uent->monitor_base);
		up.monitor_size = cpu_to_be64(uent->monitor_size);
		up.counter_base = cpu_to_be64(uent->counter_base);
		up.decay_enable = 0;	/* TODO */
		up.decay_delay  = 0;	/* TODO */

		rc = opal_hca_unit_setup(unit, (void *) __pa(&up));
		if (rc != OPAL_SUCCESS) {
			hca_counter_base_free(unit);
			rc = -EIO;
			goto out;
		}

	} else if (uent->enable && !val) {
		if (opal_hca_unit_reset(unit) != OPAL_SUCCESS) {
			rc = -EIO;
			goto out;
		}

		hca_counter_base_free(unit);
	}

	rc = 0;
	uent->enable = val;

out:
	mutex_unlock(&hca_debugfs_mutex);

	return rc;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_unit_enable_fops,
			hca_unit_enable_get, hca_unit_enable_set, "%llu\n");

static ssize_t hca_counter_data_read(struct file *file, char __user *ubuf,
				     size_t count, loff_t *ppos)
{
	unsigned int unit = (u64) file->private_data;
	struct hca_unit_entry *uent;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uent = &chip.unit[unit];
	if (!uent->enable)
		return -ENXIO;

	return simple_read_from_buffer(ubuf, count, ppos,
				       __va(uent->counter_base),
				       uent->counter_size);
}

static int hca_counter_data_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned int unit = (u64) file->private_data;
	struct hca_unit_entry *uent;

	BUG_ON(unit >= HCA_UNITS_PER_CHIP);
	uent = &chip.unit[unit];
	if (!uent->enable)
		return -ENXIO;

	if ((uent->counter_size < (vma->vm_end - vma->vm_start)) ||
	    (uent->counter_size <= (vma->vm_pgoff << PAGE_SHIFT)))
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start,
			       PHYS_PFN(uent->counter_base) + vma->vm_pgoff,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static const struct file_operations hca_counter_data_fops = {
	.llseek = default_llseek,
	.read   = hca_counter_data_read,
	.open   = simple_open,
	.mmap   = hca_counter_data_mmap,
};

static void hca_init_unit_debugfs(void)
{
	struct hca_unit_entry *uent;
	unsigned int unit;
	char name[32];

	for (unit = 0; unit < HCA_UNITS_PER_CHIP; unit++) {
		uent = &chip.unit[unit];
		snprintf(name, sizeof(name), "unit%u", unit);
		uent->dir = debugfs_create_dir(name, hca_debugfs_dir);
		debugfs_create_file("enable", 0600, uent->dir,
				    (void *)(u64) unit,
				    &hca_unit_enable_fops);
		debugfs_create_x64("monitor-base", 0600, uent->dir,
				   &uent->monitor_base);
		debugfs_create_x64("monitor-size", 0600, uent->dir,
				   &uent->monitor_size);
		debugfs_create_x64("counter-size", 0400, uent->dir,
				   &uent->counter_size);
		debugfs_create_file_unsafe("counter-data", 0400, uent->dir,
					   (void *)(u64) unit,
					   &hca_counter_data_fops);
	}
}

static void hca_free_unit_debugfs(void)
{
	unsigned int unit;

	for (unit = 0; unit < HCA_UNITS_PER_CHIP; unit++)
		debugfs_remove_recursive(chip.unit[unit].dir);
}

static int hca_chip_enable_get(void *data __always_unused, u64 *val)
{
	*val = chip.enable;
	return 0;
}

static int hca_chip_enable_set(void *data __always_unused, u64 val)
{
	struct opal_hca_chip_params cp;
	int rc = -EAGAIN;

	if (val > 1)
		return -EINVAL;

	mutex_lock(&hca_debugfs_mutex);

	/* Check if already enabled or disabled */
	if (!chip.enable && val) {
		memset(&cp, 0, sizeof(cp));
		cp.page_size = cpu_to_be64(PAGE_SIZE);
		cp.counter_mask = cpu_to_be64(HCA_COUNTER_MASK_DEFAULT);
		cp.cmd_sampling_rate = cpu_to_be64(HCA_CMD_SAMPLING_RATE_DEFAULT);
		cp.cmd_sampling_period = 0;	/* TODO */
		cp.upper_cmd_threshold = 0;	/* TODO */
		cp.lower_cmd_threshold = 0;	/* TODO */

		rc = opal_hca_chip_setup((void *) __pa(&cp));
		if (rc != OPAL_SUCCESS) {
			rc = -EIO;
			goto out;
		}

		hca_init_unit_debugfs();
	} else if (chip.enable && !val) {
		opal_hca_chip_reset();
		hca_free_unit_debugfs();
	}

	rc = 0;
	chip.enable = val;

out:
	mutex_unlock(&hca_debugfs_mutex);

	return rc;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_chip_enable_fops,
			hca_chip_enable_get, hca_chip_enable_set, "%llu\n");

static void hca_init_chip_debugfs(void)
{
	hca_debugfs_dir = debugfs_create_dir("hca", powerpc_debugfs_root);
	debugfs_create_file("enable", 0600, hca_debugfs_dir, NULL,
			    &hca_chip_enable_fops);
}

static int hca_init(void)
{
	if (!cpu_has_feature(CPU_FTR_ARCH_31) &&
	    PVR_VER(mfspr(SPRN_PVR)) != PVR_POWER10)
		return -ENOTSUPP;

	pr_info("hot-cold affinity init\n");
	hca_init_chip_debugfs();

	return 0;
}
machine_device_initcall(powernv, hca_init);
