// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright 2021, Sandipan Das, IBM Corp.
 * Interfaces to use the Hot-Cold Affinity helper
 */

#define pr_fmt(fmt) "hca: " fmt

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/kstrtox.h>
#include <linux/prandom.h>
#include <linux/workqueue.h>
#include <linux/pfn.h>

#include <asm/machdep.h>
#include <asm/cacheflush.h>
#include <asm/opal.h>
#include <asm/hca.h>


/* Hold stats for a specific hca engine */
struct hca_engine_stats {
	ulong max_hotness;
	ulong min_hotness;

        unsigned long  max_hotness_pfn;
	unsigned long min_hotness_pfn;

	u64 next_span_scan;


	struct delayed_work scan_work;
};

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

	/* Per-engine configuration */
	struct engine_config {
		bool enable;
		u64 monitor_base;
		u64 monitor_size;
		u64 counter_base;
		u64 counter_size;
		u64 decay_delay;
		struct dentry *root;
		struct hca_engine_stats stats;
	} engine[HCA_ENGINES_PER_CHIP];
	
};

struct hca_entry {
	u16 count;
	u8 age:3;
	bool gen:1;
	u16 prev_count:12;
	u8 socket_ids[4];
} __packed;


static struct chip_config cconfig = {0};
static DEFINE_MUTEX(hca_mutex);

static ulong scan_span __read_mostly = 10;
static ulong scan_ttl __read_mostly = 60 * HZ;


static int hca_engine_setup(unsigned int engine);
static int hca_engine_reset(unsigned int engine);
static int hca_counter_base_init(unsigned int engine);
static int hca_counter_base_free(unsigned int engine);
static void hca_engine_config_debugfs_init(unsigned int engine);
static void hca_engine_config_debugfs_free(unsigned int engine);

static int hca_chip_setup(void);
static int hca_chip_reset(void);
static void hca_chip_config_debugfs_init(void);

static inline unsigned int node_to_chip(unsigned int node)
{
	unsigned int cpu = cpumask_first(cpumask_of_node(node));
	return cpu_to_chip_id(cpu);
}

static inline unsigned int phys_to_chip(unsigned long addr)
{
	unsigned int node = pfn_to_nid(PHYS_PFN(addr));
	return node_to_chip(node);
}

static int hca_engine_setup(unsigned int engine)
{
	struct opal_hca_engine_params up;
	struct engine_config *econfig;
	unsigned int chip;
	int rc;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];
	BUG_ON(econfig->enable);

	/* Sanitise configuration */
	econfig->monitor_base = HCA_MONITOR_BASE(econfig->monitor_base,
						 econfig->monitor_size);
	econfig->monitor_size = HCA_MONITOR_SIZE(econfig->monitor_size);
	econfig->decay_delay = HCA_DECAY_DELAY(econfig->decay_delay);

	/* Init counter region */
	rc = hca_counter_base_init(engine);
	if (rc) {
		hca_engine_reset(engine);
		return rc;
	}

	/* Setup OPAL call parameters */
	memset(&up, 0, sizeof(up));
	up.monitor_base = cpu_to_be64(econfig->monitor_base);
	up.monitor_size = cpu_to_be64(econfig->monitor_size);
	up.counter_base = cpu_to_be64(econfig->counter_base);
	up.decay_delay  = cpu_to_be64(econfig->decay_delay);

	/*
	 * Use an engine from the chip behind which the physical
	 * memory range specified by the monitor region lies
	 */
	chip = phys_to_chip(econfig->monitor_base);
	rc = opal_hca_engine_setup(chip, engine, (void *) __pa(&up));
	if (rc != OPAL_SUCCESS) {
		hca_engine_reset(engine);
		if (rc == OPAL_PARAMETER)
			return -EINVAL;
		return -EIO;
	}
	pr_info("HCA: Chip %d Engine %d Enabled \n",
		chip, engine);
	/* Finally, mark as enabled */
	econfig->enable = true;

	return 0;
}


static void hca_scan_activity_area(struct work_struct *work)
{

	/* TODO for future */
}


static int hca_engine_reset(unsigned int engine)
{
	struct engine_config *econfig;
	unsigned int node, chip;
	int rc;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];

	/* Reset engine configuration */
	for_each_node(node) {
		chip = node_to_chip(node);
		rc = opal_hca_engine_reset(chip, engine);
		if (rc == OPAL_PARAMETER)
			return -EINVAL;
		else if (rc != OPAL_SUCCESS)
			return -EIO;
	}

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

	econfig->stats.max_hotness = 0;
	econfig->stats.min_hotness = 0;
	econfig->stats.max_hotness_pfn = 0;
	econfig->stats.min_hotness_pfn = 0;
	econfig->stats.next_span_scan = 0;

	INIT_DEFERRABLE_WORK(&econfig->stats.scan_work, hca_scan_activity_area);
	return 0;
}

static int hca_chip_setup(void)
{
	unsigned int node, chip, engine;
	struct opal_hca_chip_params cp;
	int rc;

	BUG_ON(cconfig.enable);

	/* Sanitise configuration */
	cconfig.page_size = HCA_PAGE_SIZE;
	cconfig.overflow_mask = HCA_OVERFLOW_MASK(cconfig.overflow_mask);
	cconfig.sampling_mode = HCA_SAMPLING_MODE(cconfig.sampling_mode);
	cconfig.sampling_period = HCA_SAMPLING_PERIOD(cconfig.sampling_period);
	cconfig.sampling_upper_thresh = HCA_SAMPLING_THRESH(cconfig.sampling_upper_thresh);
	cconfig.sampling_lower_thresh = HCA_SAMPLING_THRESH(cconfig.sampling_lower_thresh);

	/* Setup OPAL call parameters */
	memset(&cp, 0, sizeof(cp));
	cp.page_size = cpu_to_be64(HCA_PAGE_SIZE);
	cp.overflow_mask = cpu_to_be64(cconfig.overflow_mask);
	cp.sampling_mode = cpu_to_be64(cconfig.sampling_mode);
	cp.sampling_period = cpu_to_be64(cconfig.sampling_period);
	cp.sampling_upper_thresh = cpu_to_be64(cconfig.sampling_upper_thresh);
	cp.sampling_lower_thresh = cpu_to_be64(cconfig.sampling_lower_thresh);

	/* Reset chip configuration */
	for_each_node(node) {
		chip = node_to_chip(node);
		rc = opal_hca_chip_setup(chip, (void *) __pa(&cp));
		if (rc != OPAL_SUCCESS) {
			opal_hca_chip_reset(chip);
			if (rc == OPAL_PARAMETER)

				return -EINVAL;
			return -EIO;
		}
	}

	/* Reset engine configuration */
	for (engine = 0; engine < HCA_ENGINES_PER_CHIP; engine++)
		hca_engine_config_debugfs_init(engine);

	/* Finally, mark as enabled */
	cconfig.enable = true;

	return 0;
}

static int hca_chip_reset(void)
{
	unsigned int node, chip, engine;
	int rc;

	/* Reset chip configuration */
	for_each_node(node) {
		chip = node_to_chip(node);
		rc = opal_hca_chip_reset(chip);
		if (rc == OPAL_PARAMETER)
			return -EINVAL;
		else if (rc != OPAL_SUCCESS)
			return -EIO;
	}

	cconfig.enable = false;
	cconfig.page_size = HCA_PAGE_SIZE;
	cconfig.overflow_mask = HCA_OVERFLOW_MASK_DEFAULT;
	cconfig.sampling_mode = HCA_SAMPLING_MODE_DEFAULT;
	cconfig.sampling_period = HCA_SAMPLING_PERIOD_DEFAULT;
	cconfig.sampling_upper_thresh = HCA_SAMPLING_THRESH_DEFAULT;
	cconfig.sampling_lower_thresh = HCA_SAMPLING_THRESH_DEFAULT;

	/* Reset engine configuration */
	for (engine = 0; engine < HCA_ENGINES_PER_CHIP; engine++) {
		rc = hca_engine_reset(engine);
		if (rc)
			return rc;

		hca_engine_config_debugfs_free(engine);
	}

	return 0;
}

static int hca_counter_base_init(unsigned int engine)
{
	unsigned long pfn, start_pfn, nr_pages;
	struct engine_config *econfig;
	struct page *page;
	int node;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];
	BUG_ON(!econfig->monitor_size);
	BUG_ON(econfig->counter_base != HCA_COUNTER_BASE_DEFAULT);
	BUG_ON(econfig->counter_size != HCA_COUNTER_SIZE_DEFAULT);

	/*
	 * Allocate memory from the node (chip) behind which the physical
	 * memory range specified by the monitor region lies
	 */
	node = pfn_to_nid(PHYS_PFN(econfig->monitor_base));
	econfig->counter_size = HCA_COUNTER_SIZE(econfig->monitor_size);
	nr_pages = econfig->counter_size / HCA_PAGE_SIZE;
	page = alloc_contig_pages(nr_pages, GFP_KERNEL | __GFP_THISNODE |
				  __GFP_NOWARN, node, NULL);
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

	pr_info("engine %u counter region init at 0x%016llx\n",
		engine, econfig->counter_base);

	return 0;
}

static int hca_counter_base_free(unsigned int engine)
{
	unsigned long pfn, start_pfn, nr_pages;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];
	BUG_ON(econfig->counter_base == HCA_COUNTER_BASE_DEFAULT);
	BUG_ON(econfig->counter_size == HCA_COUNTER_SIZE_DEFAULT);

	start_pfn = PHYS_PFN(econfig->counter_base);
	nr_pages = econfig->counter_size / HCA_PAGE_SIZE;

	for (pfn = start_pfn; pfn < start_pfn + nr_pages; pfn++)
		__ClearPageOffline(pfn_to_page(pfn));

	free_contig_range(start_pfn, nr_pages);

	pr_info("engine %u counter region free at 0x%016llx\n",
		engine, econfig->counter_base);

	return 0;
}

static ssize_t hca_engine_counter_data_read(struct file *file,
					    char __user *ubuf,
					    size_t count, loff_t *ppos)
{
	unsigned int engine = (u64) file->private_data;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];

	if (!econfig->enable || !econfig->counter_size)
		return -ENXIO;

	return simple_read_from_buffer(ubuf, count, ppos,
				       __va(econfig->counter_base),
				       econfig->counter_size);
}

static ssize_t hca_engine_counter_data_write(struct file *file,
					    const char __user *ubuf,
					    size_t count, loff_t *ppos)
{
	unsigned int engine = (u64) file->private_data;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];

	if (!econfig->enable || !econfig->counter_size)
		return -ENXIO;

	return simple_write_to_buffer(__va(econfig->counter_base),
				       econfig->counter_size, ppos,
				       ubuf, count);
}

static int hca_engine_counter_data_mmap(struct file *file,
					struct vm_area_struct *vma)
{
	unsigned int engine = (u64) file->private_data;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];

	if (!econfig->enable || !econfig->counter_size)
		return -ENXIO;

	if ((econfig->counter_size < (vma->vm_end - vma->vm_start)) ||
	    (econfig->counter_size <= (vma->vm_pgoff << PAGE_SHIFT)))
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start,
			       PHYS_PFN(econfig->counter_base) + vma->vm_pgoff,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot);
}

static loff_t hca_engine_counter_data_llseek(struct file *file, loff_t offset,
					     int whence)
{
	unsigned int engine = (u64) file->private_data;
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];

	if (!econfig->enable || !econfig->counter_size)
		return -ENXIO;

	if ((file->f_pos + offset) >= econfig->counter_size)
		return -EINVAL;

	return default_llseek(file, offset, whence);
}

static const struct file_operations hca_engine_counter_data_fops = {
	.llseek = hca_engine_counter_data_llseek,
	.read   = hca_engine_counter_data_read,
	.write   = hca_engine_counter_data_write,
	.open   = simple_open,
	.mmap   = hca_engine_counter_data_mmap,
};

static int hca_engine_enable_get(void *data, u64 *val)
{
	unsigned int engine = (u64) data;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	*val = cconfig.engine[engine].enable;

	return 0;
}

static int hca_engine_enable_set(void *data, u64 val)
{
	unsigned int engine = (u64) data;
	struct engine_config *econfig;
	int rc = 0;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];
	mutex_lock(&hca_mutex);

	/* Check if not already enabled or disabled */
	if (!econfig->enable && val)
		rc = hca_engine_setup(engine);
	else if (econfig->enable && !val)
		rc = hca_engine_reset(engine);

	if (!rc)
		econfig->enable = (val > 0);

	mutex_unlock(&hca_mutex);

	return rc;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_engine_enable_fops,
			hca_engine_enable_get, hca_engine_enable_set,
			"%llu\n");

static int hca_chip_enable_get(void *data __always_unused, u64 *val)
{
	*val = cconfig.enable;
	return 0;
}

static int hca_chip_enable_set(void *data __always_unused, u64 val)
{
	int rc = 0;

	mutex_lock(&hca_mutex);

	/* Check if not already enabled or disabled */
	if (!cconfig.enable && val)
		rc = hca_chip_setup();
	else if (cconfig.enable && !val)
		rc = hca_chip_reset();

	if (!rc)
		cconfig.enable = (val > 0);

	mutex_unlock(&hca_mutex);

	return rc;
}

DEFINE_SIMPLE_ATTRIBUTE(hca_chip_enable_fops,
			hca_chip_enable_get, hca_chip_enable_set,
			"%llu\n");

static void hca_engine_config_debugfs_init(unsigned int engine)
{
	struct engine_config *econfig;
	char name[32];

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];
	BUG_ON(econfig->enable);
	BUG_ON(cconfig.enable);

	snprintf(name, sizeof(name), "engine%u", engine);
	econfig->root = debugfs_create_dir(name, cconfig.root);
	debugfs_create_file("enable", 0600, econfig->root,
			    (void *)(u64) engine, &hca_engine_enable_fops);
	debugfs_create_x64("monitor-base", 0600, econfig->root,
			   &econfig->monitor_base);
	debugfs_create_u64("monitor-size", 0600, econfig->root,
			   &econfig->monitor_size);
	debugfs_create_u64("counter-size", 0400, econfig->root,
			   &econfig->counter_size);
	debugfs_create_file_unsafe("counter-data", 0400, econfig->root,
				   (void *)(u64) engine,
				   &hca_engine_counter_data_fops);
	debugfs_create_u64("decay-delay", 0600, econfig->root,
			   &econfig->decay_delay);

	/* Expose Engine Stats */
	debugfs_create_ulong("max-hotness", 0400, econfig->root,
			   &econfig->stats.max_hotness);
	debugfs_create_ulong("max-hotness-pfn", 0400, econfig->root,
			   &econfig->stats.max_hotness_pfn);

	debugfs_create_ulong("min-hotness", 0400, econfig->root,
			     &econfig->stats.min_hotness);
	debugfs_create_ulong("min-hotness-pfn", 0400, econfig->root,
			   &econfig->stats.min_hotness_pfn);

	debugfs_create_ulong("scan-span", 0600, econfig->root,
			     &scan_span);

	debugfs_create_ulong("scan-ttl", 0600, econfig->root,
			     &scan_ttl);
}

static struct hca_entry *hca_entry(off_t entry_off)
{
	return &((struct hca_entry *)__va(cconfig.engine[0].counter_base))[entry_off];
}

static struct hca_entry * folio_hca_entry(struct folio *folio)
{
	/* TOOD: Fetch this value from the hca activity region */
	unsigned long pfn, pfn_start;
	struct engine_config *econfig = &cconfig.engine[0];
	off_t entry_off;

	/* if the hca engine is not enabled */
	if (!cconfig.enable)
		return NULL;

	/* Calculate the PFN relative to start of the monitor area */
	pfn_start = cconfig.engine[0].monitor_base << PAGE_SHIFT;
	pfn = folio_pfn(folio);

	/* Minor sanity check */
	BUG_ON(pfn_start > pfn);
	entry_off = (pfn - pfn_start);

	/* Check out of bounds */
	if (entry_off * sizeof (struct hca_entry) > econfig->monitor_size)
		return NULL;

	return hca_entry(entry_off);
}


static void hca_engine_config_debugfs_free(unsigned int engine)
{
	struct engine_config *econfig;

	BUG_ON(engine >= HCA_ENGINES_PER_CHIP);
	econfig = &cconfig.engine[engine];
	BUG_ON(econfig->enable);
	BUG_ON(cconfig.enable);

	debugfs_remove_recursive(econfig->root);
	econfig->root = NULL;
}

static void hca_chip_config_debugfs_init(void)
{
	/* Setup chip configuration debugfs entries */
	cconfig.root = debugfs_create_dir("hca", arch_debugfs_dir);
	debugfs_create_file("enable", 0600, cconfig.root, NULL,
			    &hca_chip_enable_fops);
	debugfs_create_u64("overflow-mask", 0600, cconfig.root,
			   &cconfig.overflow_mask);
	debugfs_create_u64("sampling-mode", 0600, cconfig.root,
			   &cconfig.sampling_mode);
	debugfs_create_u64("sampling-period", 0600, cconfig.root,
			   &cconfig.sampling_period);
	debugfs_create_u64("sampling-thresh-upper", 0600, cconfig.root,
			   &cconfig.sampling_upper_thresh);
	debugfs_create_u64("sampling-thresh-lower", 0600, cconfig.root,
			   &cconfig.sampling_lower_thresh);
}

static inline unsigned long long unpack_access_count(u16 packed_count)
{
	const unsigned int exponent = (packed_count & 0xF);
	const unsigned int mantissa = ((packed_count >> 4) & 0xFFF);

	return (1UL << 2 * exponent) * mantissa;
}


static unsigned long hca_scops_folio_referenced(struct folio *folio, int is_locked,
					  struct mem_cgroup *memcg,
					  unsigned long *vm_flags)
{
	struct hca_entry * entry = folio_hca_entry(folio);
	u16 packed_count;

	if (!entry) {
		WARN_ON(1);
		return 0;
	}

	/* Unpack and return the access count */
	packed_count = entry->count;
	return unpack_access_count(packed_count);
}

static int hca_scops_folio_test_clear_referenced(struct folio *folio)
{

	struct hca_entry * entry = folio_hca_entry(folio);
	u16 packed_count;

	if (!entry) {
		WARN_ON(1);
		return 0;
	}

	packed_count = entry->count;
	entry->count = 0;

	return packed_count != 0;
}

/* Update max/min hotness of an engine */
static void update_engine_stats(struct engine_config *engine, struct folio *folio,
				ulong hotness)
{
	struct hca_engine_stats *stats = &engine->stats;
	int current_hotness;
	bool success;

	current_hotness = READ_ONCE(stats->max_hotness);

	/* TODO: handle possible race */
	/* Update the stats */
	if (hotness > current_hotness) {
		success = (cmpxchg64(&stats->max_hotness,
				     current_hotness, hotness) == current_hotness);
		if (success) {
			WRITE_ONCE(stats->max_hotness, hotness);
			WRITE_ONCE(stats->max_hotness_pfn, folio_pfn(folio));
		}
	}

	current_hotness = READ_ONCE(stats->min_hotness);

	/* TODO: handle possible race */
	/* Update the stats */
	if (hotness < current_hotness || !current_hotness) {
		success = (cmpxchg64(&stats->min_hotness,
				     current_hotness, hotness) == current_hotness);
		if (success) {
			WRITE_ONCE(stats->min_hotness, hotness);
			WRITE_ONCE(stats->min_hotness_pfn, folio_pfn(folio));
		}
	}
}


static u64 hotness_score(struct hca_entry * entry) {
	u64 hotness;

	/* The absolute hotness metric */
	hotness = unpack_access_count(entry->prev_count) +
		unpack_access_count(entry->count) / (entry->age + 1);

	return hotness;
}

/* Return the hotness of the specific folio  */
static int hca_scops_folio_hotness(struct folio *folio)
{
	struct hca_entry *folio_hca = folio_hca_entry(folio);
	struct engine_config *engine = &cconfig.engine[0];
	u64 hotness = 0, current_hotness, treshhold, max_hotness = 0, min_hotness = 0;

	if (!folio_hca) {
		WARN_ON_ONCE(1);
		return 0;
	}

	if (!engine->enable)
		return 0;

	hotness = hotness_score(folio_hca);

	/* Look around 'scan_span' number of pfns randomly selected */
	if (time_is_after_jiffies(engine->stats.next_span_scan)) {
		for (int index = 0; index < scan_span; index++) {
			unsigned long pfn =prandom_u32_max((u32)
							   (engine->monitor_size >> PAGE_SHIFT));
			struct hca_entry *entry = hca_entry(pfn);
			WARN_ON(!entry);
			if (!entry)
				continue;
			current_hotness = hotness_score(entry);
			if (current_hotness > max_hotness)
				max_hotness = current_hotness;

			if ((current_hotness < min_hotness) || !min_hotness)
				min_hotness = current_hotness;
		}

		engine->stats.next_span_scan = jiffies + span_ttl;
		engine->stats.max_hotness =  max_hotness;
		engine->stats.min_hotness =  min_hotness;
	}

	/* Update stat with 50% probablity */
	/* Todo: this is better done in an async context */
	/* Dead code for now as max(100) wont give a value beyond 99*/
	if (prandom_u32_max(100) >= 100) {
		update_engine_stats(&cconfig.engine[0], folio, hotness);
	}

	treshhold = (max_hotness  - min_hotness) >> 1;

	return (hotness >= treshhold) ? 1 : -1;
}

static struct vmscan_ops hca_scops = {
	/* Return number of references for a single folio */
	.folio_referenced = hca_scops_folio_referenced,
	.folio_test_clear_referenced = hca_scops_folio_test_clear_referenced,
	.folio_hotness = &hca_scops_folio_hotness,
};

struct vmscan_ops *arch_vmscan_ops(int nid)
{
	if (cconfig.enable)
		return &hca_scops;
	else
		return NULL;
}

/* Enable hca on boot ? */
static bool hca_enabled = true;

static int parse_hca_param(char *arg)
{
        return strtobool(arg, &hca_enabled);
}
early_param("hca", parse_hca_param);

static int hca_powernv_init(void)
{
	int rc;

	/* Validate hardware support */
	if (!cpu_has_feature(CPU_FTR_ARCH_31) ||
	    PVR_VER(mfspr(SPRN_PVR)) != PVR_POWER10) {
		pr_info("HCA not supported on this arch");
		return -ENODEV;
	}

	/* Validate firmware support */
	if (!opal_check_token(OPAL_HCA_CHIP_SETUP) ||
	    !opal_check_token(OPAL_HCA_CHIP_RESET) ||
	    !opal_check_token(OPAL_HCA_ENGINE_SETUP) ||
	    !opal_check_token(OPAL_HCA_ENGINE_RESET)) {
		pr_info("Firmware doesnt support HCA");
		return -ENOTSUPP;
	}

	pr_info("hot-cold affinity init\n");
	memset(&cconfig, 0, sizeof(cconfig));
	rc = hca_chip_reset();
	if (rc)
		goto out;

	hca_chip_config_debugfs_init();

	/* Pre init HCA if requested */
	if (hca_enabled) {
		struct pglist_data * node=first_online_pgdat();
		struct engine_config *econfig = &cconfig.engine[0];

		rc = hca_chip_setup();
		if (rc) {
			goto out;
		}
		/* TODO: Get the first online node right now and setup the monitor for that region */
		econfig->monitor_base = PFN_PHYS(node->node_start_pfn);
		econfig->monitor_size = PFN_PHYS(node->node_spanned_pages);
		cconfig.enable = true;
		hca_engine_setup(0);
		
		if (!rc)
			econfig->enable = true;
	}
out:
	return rc;
}

machine_device_initcall(powernv, hca_powernv_init);
