// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright 2021, Sandipan Das, IBM Corp.
 * Interfaces to use the Hot-Cold Affinity helper.
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

static void hca_init_unit_debugfs(struct hca_chip_entry *cent)
{
	struct hca_unit_entry *uent;
	char name[32];
	int i;

	for (i = 0; i < HCA_MAX_UNITS_PER_CHIP; i++) {
		uent = &cent->units[i];
		snprintf(name, sizeof(name), "unit%u", i);
		uent->dir = debugfs_create_dir(name, cent->dir);
		debugfs_create_bool("enable", 0600, uent->dir, &uent->enable);
		debugfs_create_x64("monitor-base", 0600, uent->dir, &uent->monitor_base);
		debugfs_create_x64("monitor-size", 0600, uent->dir, &uent->monitor_size);
		debugfs_create_x64("counter-size", 0400, uent->dir, &uent->counter_size);
	}
}

static void hca_free_unit_debugfs(struct hca_chip_entry *cent)
{
	int i;

	for (i = 0; i < HCA_MAX_UNITS_PER_CHIP; i++)
		debugfs_remove_recursive(cent->units[i].dir);
}

static int hca_chip_enable_get(void *id, u64 *val)
{
	*val = hca_chips[(size_t) id].enable;
	return 0;
}

static int hca_chip_enable_set(void *id, u64 val)
{
	struct opal_hca_chip_params cp;
	struct hca_chip_entry *cent;
	int rc = -EAGAIN;

	if (val > 1)
		return -EINVAL;

	mutex_lock(&hca_debugfs_mutex);
	cent = &hca_chips[(size_t) id];

	/* Check if already enabled or disabled */
	if (!cent->enable && val) {
		memset(&cp, 0, sizeof(cp));
		cp.page_size = cpu_to_be64(HCA_PAGE_SIZE_DEFAULT);
		cp.overflow_mask = cpu_to_be64(HCA_OVERFLOW_MASK_DEFAULT);
		cp.sampling_rate = cpu_to_be64(HCA_SAMPLING_RATE_DEFAULT);

		if (opal_hca_chip_setup(cent->id, &cp) != OPAL_SUCCESS) {
			rc = -EIO;
			goto err;
		}

		hca_init_unit_debugfs(cent);
	} else if (cent->enable && !val) {
		opal_hca_chip_reset(cent->id);
		hca_free_unit_debugfs(cent);
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
	char name[32];
	int chip, i;

	hca_debugfs_dir = debugfs_create_dir("hca", powerpc_debugfs_root);
	i = 0;

	/* TODO: use device tree to find chip information */
	for_each_online_node(chip) {
		cent = &hca_chips[i];
		cent->id = chip;
		snprintf(name, sizeof(name), "chip%u", cent->id);
		cent->dir = debugfs_create_dir(name, hca_debugfs_dir);
		debugfs_create_file("enable", S_IRUSR | S_IWUSR, cent->dir,
				    (void *) (unsigned long) i,
				    &hca_chip_enable_fops);
		i++;
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
