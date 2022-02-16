/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LINUX_MM_INLINE_H
#define LINUX_MM_INLINE_H

#include <linux/atomic.h>
#include <linux/huge_mm.h>
#include <linux/swap.h>
#include <linux/string.h>

/**
 * folio_is_file_lru - Should the folio be on a file LRU or anon LRU?
 * @folio: The folio to test.
 *
 * We would like to get this info without a page flag, but the state
 * needs to survive until the folio is last deleted from the LRU, which
 * could be as far down as __page_cache_release.
 *
 * Return: An integer (not a boolean!) used to sort a folio onto the
 * right LRU list and to account folios correctly.
 * 1 if @folio is a regular filesystem backed page cache folio
 * or a lazily freed anonymous folio (e.g. via MADV_FREE).
 * 0 if @folio is a normal anonymous folio, a tmpfs folio or otherwise
 * ram or swap backed folio.
 */
static inline int folio_is_file_lru(struct folio *folio)
{
	return !folio_test_swapbacked(folio);
}

static inline int page_is_file_lru(struct page *page)
{
	return folio_is_file_lru(page_folio(page));
}

static __always_inline void update_lru_size(struct lruvec *lruvec,
				enum lru_list lru, enum zone_type zid,
				long nr_pages)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	__mod_lruvec_state(lruvec, NR_LRU_BASE + lru, nr_pages);
	__mod_zone_page_state(&pgdat->node_zones[zid],
				NR_ZONE_LRU_BASE + lru, nr_pages);
#ifdef CONFIG_MEMCG
	mem_cgroup_update_lru_size(lruvec, lru, zid, nr_pages);
#endif
}

/**
 * __folio_clear_lru_flags - Clear page lru flags before releasing a page.
 * @folio: The folio that was on lru and now has a zero reference.
 */
static __always_inline void __folio_clear_lru_flags(struct folio *folio)
{
	VM_BUG_ON_FOLIO(!folio_test_lru(folio), folio);

	__folio_clear_lru(folio);

	/* this shouldn't happen, so leave the flags to bad_page() */
	if (folio_test_active(folio) && folio_test_unevictable(folio))
		return;

	__folio_clear_active(folio);
	__folio_clear_unevictable(folio);
}

static __always_inline void __clear_page_lru_flags(struct page *page)
{
	__folio_clear_lru_flags(page_folio(page));
}

/**
 * folio_lru_list - Which LRU list should a folio be on?
 * @folio: The folio to test.
 *
 * Return: The LRU list a folio should be on, as an index
 * into the array of LRU lists.
 */
static __always_inline enum lru_list folio_lru_list(struct folio *folio)
{
	enum lru_list lru;

	VM_BUG_ON_FOLIO(folio_test_active(folio) && folio_test_unevictable(folio), folio);

	if (folio_test_unevictable(folio))
		return LRU_UNEVICTABLE;

	lru = folio_is_file_lru(folio) ? LRU_INACTIVE_FILE : LRU_INACTIVE_ANON;
	if (folio_test_active(folio))
		lru += LRU_ACTIVE;

	return lru;
}

#ifdef CONFIG_LRU_GEN

static inline bool lru_gen_enabled(void)
{
	return true;
}

static inline bool lru_gen_in_fault(void)
{
	return current->in_lru_fault;
}

static inline int lru_gen_from_seq(unsigned long seq)
{
	return seq % MAX_NR_GENS;
}

static inline bool lru_gen_is_active(struct lruvec *lruvec, int gen)
{
	unsigned long max_seq = lruvec->lrugen.max_seq;

	VM_BUG_ON(gen >= MAX_NR_GENS);

	/* see the comment on MIN_NR_GENS */
	return gen == lru_gen_from_seq(max_seq) || gen == lru_gen_from_seq(max_seq - 1);
}

static inline void lru_gen_update_size(struct lruvec *lruvec, enum lru_list lru,
				       int zone, long delta)
{
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);

	lockdep_assert_held(&lruvec->lru_lock);
	WARN_ON_ONCE(delta != (int)delta);

	__mod_lruvec_state(lruvec, NR_LRU_BASE + lru, delta);
	__mod_zone_page_state(&pgdat->node_zones[zone], NR_ZONE_LRU_BASE + lru, delta);
}

static inline void lru_gen_balance_size(struct lruvec *lruvec, struct folio *folio,
					int old_gen, int new_gen)
{
	int type = folio_is_file_lru(folio);
	int zone = folio_zonenum(folio);
	int delta = folio_nr_pages(folio);
	enum lru_list lru = type * LRU_INACTIVE_FILE;
	struct lru_gen_struct *lrugen = &lruvec->lrugen;

	VM_BUG_ON(old_gen != -1 && old_gen >= MAX_NR_GENS);
	VM_BUG_ON(new_gen != -1 && new_gen >= MAX_NR_GENS);
	VM_BUG_ON(old_gen == -1 && new_gen == -1);

	if (old_gen >= 0)
		WRITE_ONCE(lrugen->nr_pages[old_gen][type][zone],
			   lrugen->nr_pages[old_gen][type][zone] - delta);
	if (new_gen >= 0)
		WRITE_ONCE(lrugen->nr_pages[new_gen][type][zone],
			   lrugen->nr_pages[new_gen][type][zone] + delta);

	if (old_gen < 0) {
		if (lru_gen_is_active(lruvec, new_gen))
			lru += LRU_ACTIVE;
		lru_gen_update_size(lruvec, lru, zone, delta);
		return;
	}

	if (new_gen < 0) {
		if (lru_gen_is_active(lruvec, old_gen))
			lru += LRU_ACTIVE;
		lru_gen_update_size(lruvec, lru, zone, -delta);
		return;
	}

	if (!lru_gen_is_active(lruvec, old_gen) && lru_gen_is_active(lruvec, new_gen)) {
		lru_gen_update_size(lruvec, lru, zone, -delta);
		lru_gen_update_size(lruvec, lru + LRU_ACTIVE, zone, delta);
	}

	/* Promotion is legit while a page is on an LRU list, but demotion isn't. */
	VM_BUG_ON(lru_gen_is_active(lruvec, old_gen) && !lru_gen_is_active(lruvec, new_gen));
}

static inline bool lru_gen_add_folio(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	int gen;
	unsigned long old_flags, new_flags;
	int type = folio_is_file_lru(folio);
	int zone = folio_zonenum(folio);
	struct lru_gen_struct *lrugen = &lruvec->lrugen;

	if (folio_test_unevictable(folio) || !lrugen->enabled)
		return false;
	/*
	 * There are three common cases for this page:
	 * 1) If it shouldn't be evicted, e.g., it was just faulted in, add it
	 *    to the youngest generation.
	 * 2) If it can't be evicted immediately, i.e., it's an anon page and
	 *    not in swapcache, or a dirty page pending writeback, add it to the
	 *    second oldest generation.
	 * 3) If it may be evicted immediately, e.g., it's a clean page, add it
	 *    to the oldest generation.
	 */
	if (folio_test_active(folio))
		gen = lru_gen_from_seq(lrugen->max_seq);
	else if ((!type && !folio_test_swapcache(folio)) ||
		 (folio_test_reclaim(folio) &&
		  (folio_test_dirty(folio) || folio_test_writeback(folio))))
		gen = lru_gen_from_seq(lrugen->min_seq[type] + 1);
	else
		gen = lru_gen_from_seq(lrugen->min_seq[type]);

	do {
		new_flags = old_flags = READ_ONCE(folio->flags);
		VM_BUG_ON_FOLIO(new_flags & LRU_GEN_MASK, folio);

		new_flags &= ~(LRU_GEN_MASK | BIT(PG_active));
		new_flags |= (gen + 1UL) << LRU_GEN_PGOFF;
	} while (cmpxchg(&folio->flags, old_flags, new_flags) != old_flags);

	lru_gen_balance_size(lruvec, folio, -1, gen);
	/* for folio_rotate_reclaimable() */
	if (reclaiming)
		list_add_tail(&folio->lru, &lrugen->lists[gen][type][zone]);
	else
		list_add(&folio->lru, &lrugen->lists[gen][type][zone]);

	return true;
}

static inline bool lru_gen_del_folio(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	int gen;
	unsigned long old_flags, new_flags;

	do {
		new_flags = old_flags = READ_ONCE(folio->flags);
		if (!(new_flags & LRU_GEN_MASK))
			return false;

		VM_BUG_ON_FOLIO(folio_test_active(folio), folio);
		VM_BUG_ON_FOLIO(folio_test_unevictable(folio), folio);

		gen = ((new_flags & LRU_GEN_MASK) >> LRU_GEN_PGOFF) - 1;

		new_flags &= ~LRU_GEN_MASK;
		/* for shrink_page_list() */
		if (reclaiming)
			new_flags &= ~(BIT(PG_referenced) | BIT(PG_reclaim));
		else if (lru_gen_is_active(lruvec, gen))
			new_flags |= BIT(PG_active);
	} while (cmpxchg(&folio->flags, old_flags, new_flags) != old_flags);

	lru_gen_balance_size(lruvec, folio, gen, -1);
	list_del(&folio->lru);

	return true;
}

#else

static inline bool lru_gen_enabled(void)
{
	return false;
}

static inline bool lru_gen_in_fault(void)
{
	return false;
}

static inline bool lru_gen_add_folio(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	return false;
}

static inline bool lru_gen_del_folio(struct lruvec *lruvec, struct folio *folio, bool reclaiming)
{
	return false;
}

#endif /* CONFIG_LRU_GEN */

static __always_inline
void lruvec_add_folio(struct lruvec *lruvec, struct folio *folio)
{
	enum lru_list lru = folio_lru_list(folio);

	if (lru_gen_add_folio(lruvec, folio, false))
		return;

	update_lru_size(lruvec, lru, folio_zonenum(folio),
			folio_nr_pages(folio));
	list_add(&folio->lru, &lruvec->lists[lru]);
}

static __always_inline void add_page_to_lru_list(struct page *page,
				struct lruvec *lruvec)
{
	lruvec_add_folio(lruvec, page_folio(page));
}

static __always_inline
void lruvec_add_folio_tail(struct lruvec *lruvec, struct folio *folio)
{
	enum lru_list lru = folio_lru_list(folio);

	if (lru_gen_add_folio(lruvec, folio, true))
		return;

	update_lru_size(lruvec, lru, folio_zonenum(folio),
			folio_nr_pages(folio));
	list_add_tail(&folio->lru, &lruvec->lists[lru]);
}

static __always_inline void add_page_to_lru_list_tail(struct page *page,
				struct lruvec *lruvec)
{
	lruvec_add_folio_tail(lruvec, page_folio(page));
}

static __always_inline
void lruvec_del_folio(struct lruvec *lruvec, struct folio *folio)
{
	if (lru_gen_del_folio(lruvec, folio, false))
		return;

	list_del(&folio->lru);
	update_lru_size(lruvec, folio_lru_list(folio), folio_zonenum(folio),
			-folio_nr_pages(folio));
}

static __always_inline void del_page_from_lru_list(struct page *page,
				struct lruvec *lruvec)
{
	lruvec_del_folio(lruvec, page_folio(page));
}

#ifdef CONFIG_ANON_VMA_NAME
/*
 * mmap_lock should be read-locked when calling vma_anon_name() and while using
 * the returned pointer.
 */
extern const char *vma_anon_name(struct vm_area_struct *vma);

/*
 * mmap_lock should be read-locked for orig_vma->vm_mm.
 * mmap_lock should be write-locked for new_vma->vm_mm or new_vma should be
 * isolated.
 */
extern void dup_vma_anon_name(struct vm_area_struct *orig_vma,
			      struct vm_area_struct *new_vma);

/*
 * mmap_lock should be write-locked or vma should have been isolated under
 * write-locked mmap_lock protection.
 */
extern void free_vma_anon_name(struct vm_area_struct *vma);

/* mmap_lock should be read-locked */
static inline bool is_same_vma_anon_name(struct vm_area_struct *vma,
					 const char *name)
{
	const char *vma_name = vma_anon_name(vma);

	/* either both NULL, or pointers to same string */
	if (vma_name == name)
		return true;

	return name && vma_name && !strcmp(name, vma_name);
}
#else /* CONFIG_ANON_VMA_NAME */
static inline const char *vma_anon_name(struct vm_area_struct *vma)
{
	return NULL;
}
static inline void dup_vma_anon_name(struct vm_area_struct *orig_vma,
			      struct vm_area_struct *new_vma) {}
static inline void free_vma_anon_name(struct vm_area_struct *vma) {}
static inline bool is_same_vma_anon_name(struct vm_area_struct *vma,
					 const char *name)
{
	return true;
}
#endif  /* CONFIG_ANON_VMA_NAME */

static inline void init_tlb_flush_pending(struct mm_struct *mm)
{
	atomic_set(&mm->tlb_flush_pending, 0);
}

static inline void inc_tlb_flush_pending(struct mm_struct *mm)
{
	atomic_inc(&mm->tlb_flush_pending);
	/*
	 * The only time this value is relevant is when there are indeed pages
	 * to flush. And we'll only flush pages after changing them, which
	 * requires the PTL.
	 *
	 * So the ordering here is:
	 *
	 *	atomic_inc(&mm->tlb_flush_pending);
	 *	spin_lock(&ptl);
	 *	...
	 *	set_pte_at();
	 *	spin_unlock(&ptl);
	 *
	 *				spin_lock(&ptl)
	 *				mm_tlb_flush_pending();
	 *				....
	 *				spin_unlock(&ptl);
	 *
	 *	flush_tlb_range();
	 *	atomic_dec(&mm->tlb_flush_pending);
	 *
	 * Where the increment if constrained by the PTL unlock, it thus
	 * ensures that the increment is visible if the PTE modification is
	 * visible. After all, if there is no PTE modification, nobody cares
	 * about TLB flushes either.
	 *
	 * This very much relies on users (mm_tlb_flush_pending() and
	 * mm_tlb_flush_nested()) only caring about _specific_ PTEs (and
	 * therefore specific PTLs), because with SPLIT_PTE_PTLOCKS and RCpc
	 * locks (PPC) the unlock of one doesn't order against the lock of
	 * another PTL.
	 *
	 * The decrement is ordered by the flush_tlb_range(), such that
	 * mm_tlb_flush_pending() will not return false unless all flushes have
	 * completed.
	 */
}

static inline void dec_tlb_flush_pending(struct mm_struct *mm)
{
	/*
	 * See inc_tlb_flush_pending().
	 *
	 * This cannot be smp_mb__before_atomic() because smp_mb() simply does
	 * not order against TLB invalidate completion, which is what we need.
	 *
	 * Therefore we must rely on tlb_flush_*() to guarantee order.
	 */
	atomic_dec(&mm->tlb_flush_pending);
}

static inline bool mm_tlb_flush_pending(struct mm_struct *mm)
{
	/*
	 * Must be called after having acquired the PTL; orders against that
	 * PTLs release and therefore ensures that if we observe the modified
	 * PTE we must also observe the increment from inc_tlb_flush_pending().
	 *
	 * That is, it only guarantees to return true if there is a flush
	 * pending for _this_ PTL.
	 */
	return atomic_read(&mm->tlb_flush_pending);
}

static inline bool mm_tlb_flush_nested(struct mm_struct *mm)
{
	/*
	 * Similar to mm_tlb_flush_pending(), we must have acquired the PTL
	 * for which there is a TLB flush pending in order to guarantee
	 * we've seen both that PTE modification and the increment.
	 *
	 * (no requirement on actually still holding the PTL, that is irrelevant)
	 */
	return atomic_read(&mm->tlb_flush_pending) > 1;
}


#endif
