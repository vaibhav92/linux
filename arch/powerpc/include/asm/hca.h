// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright 2021, Sandipan Das, IBM Corp.
 * Configuration helpers for the Hot-Cold Affinity helper
 */

#ifndef _ASM_POWERPC_HCA_H
#define _ASM_POWERPC_HCA_H

#include <linux/bitops.h>
#include <linux/minmax.h>

#define KB	(1024UL)
#define MB	(1024 * KB)
#define GB	(1024 * MB)
#define TB	(1024 * GB)

#define HCA_ENGINES_PER_CHIP	2
#define HCA_ENTRY_SIZE		8

#ifdef CONFIG_PPC_4K_PAGES
#define HCA_PAGE_SIZE		(4 * KB)
#else  /* CONFIG_PPC_64K_PAGES */
#define HCA_PAGE_SIZE		(64 * KB)
#endif /* CONFIG_PPC_4K_PAGES  */

/*
 * @m: The counter overflow mask
 *
 * Supported overflow masks are 16, 32, 64 ... 4096. The page stats in
 * the HCA cache are written back to memory once the count reaches @m.
 */
#define HCA_OVERFLOW_MASK(m)		min((u64)4096, max((u64)16, (u64)roundup_pow_of_two(m)))
#define HCA_OVERFLOW_MASK_DEFAULT	4096

/*
 * @m: The command sampling mode
 *
 * Supported command sampling modes are
 * 	0 -> No sampling (capture all commands)
 * 	1 -> Sample 1 of 16 commands
 * 	2 -> Sample 1 of 32 commands
 * 	3 -> Dynamic sampling (configured separately)
 *
 * The HCA fabric update traffic is reduced at the cost of accuracy. The
 * counts are scaled based on the sampling rate, i.e. if a single command
 * is seen when 1 of 16 mode is used, the corresponding page count will be
 * incremented by 16.
 */
#define HCA_SAMPLING_MODE(m)		min((u64)3, max((u64)0, (u64)(m) & 0x3))
#define HCA_SAMPLING_MODE_DEFAULT	0

/*
 * @p: The command sampling period (in cycles)
 *
 * Supported command sampling periods are 256, 512, 1024 ... 65536 cycles.
 * HCA update commands sent to the fabric are counted every @p cycles.
 *
 * Only used when dynamic sampling is enabled.
 */
#define HCA_SAMPLING_PERIOD(p)		min((u64)65536, max((u64)256, (u64)roundup_pow_of_two(p)))
#define HCA_SAMPLING_PERIOD_DEFAULT	0

/*
 * @t: The command threshold
 *
 * Supported command thresholds are 0, 1, 2 ... 255 commands.
 *
 * With the upper command threshold, the sampling rate will reduce when
 * more than @t number of update commands are detected within a sampling
 * period.
 *
 * With the lower command threshold, the sampling rate will increase when
 * fewer than @t number of update commands are detected within a sampling
 * period.
 *
 * Only used when dynamic sampling is enabled.
 */
#define HCA_SAMPLING_THRESH(t)		min((u64)255, (u64)(t))
#define HCA_SAMPLING_THRESH_DEFAULT	0UL

/*
 * @s: The monitor region size (in bytes)
 *
 * Supported monitor region sizes are 16GB, 32GB, 64GB ... 512TB. The
 * minimum and maximum region sizes are always guaranteed to be 16GB
 * and 512TB respectively if the specified value is out of bounds.
 */
#define HCA_MONITOR_SIZE(s)		min((u64)512 * TB, max((u64)16 * GB, (u64)roundup_pow_of_two(s)))
#define HCA_MONITOR_SIZE_DEFAULT	(16 * GB)

/*
 * @b: The monitor region base
 * @s: The monitor region size (in bytes)
 *
 * The monitor region base address must be aligned to its size.
 */
#define HCA_MONITOR_BASE(b, s)		ALIGN((u64)(b), HCA_MONITOR_SIZE(s))
#define HCA_MONITOR_BASE_DEFAULT	0

/*
 * @s: The monitor region size
 *
 * The counter region size is directly derived from the monitor region
 * size and the page size.
 */
#define HCA_COUNTER_SIZE(s)		((HCA_MONITOR_SIZE(s) * (u64)HCA_ENTRY_SIZE) / PAGE_SIZE)
#define HCA_COUNTER_SIZE_DEFAULT	0
#define HCA_COUNTER_BASE_DEFAULT	0

/*
 * @d: The decay delay (in ns)
 *
 * If the delay is set to 0, the decay feature is disabled. Otherwise,
 * supported decay delay periods are 32ns, 64ns, 128ns ... 2048ns. The
 * minimum and maximum decay delays are always guaranteed to be 32ns
 * and 2048ns respectively if the specified value is out of bounds.
 */
#define HCA_DECAY_DELAY(d)		((d) ? min((u64)2048, max((u64)32, (u64)roundup_pow_of_two(d))) : (u64)0)
#define HCA_DECAY_DELAY_DEFAULT		0

#define BMASK(s)			(((s) >= 64) ? -1UL : ((1UL << (s)) - 1))
#define FMASK(s, n)			(-1UL & (BMASK((s) + (n)) & ~BMASK((s))))

#define GET_FIELD(v, s, n)		(((v) >> (s)) & BMASK((n)))
#define SET_FIELD(v, s, n, b)		(((v) & ~FMASK((s), (n))) | (((unsigned long) (b) << (s)) & FMASK((s), (n))))

#define HCA_ENTRY_COUNT_EXP_LENGTH	4
#define HCA_ENTRY_COUNT_EXP_START	HCA_ENTRY_BIT(0)
#define HCA_ENTRY_COUNT_EXP_MAX		BMASK(HCA_ENTRY_COUNT_EXP_LENGTH)

#define HCA_ENTRY_GET_COUNT_EXP(e)	GET_FIELD((e), HCA_ENTRY_COUNT_EXP_START, HCA_ENTRY_COUNT_EXP_LENGTH)
#define HCA_ENTRY_SET_COUNT_EXP(e, x)	SET_FIELD((e), HCA_ENTRY_COUNT_EXP_START, HCA_ENTRY_COUNT_EXP_LENGTH, (x))

#define HCA_ENTRY_COUNT_MNT_LENGTH	12
#define HCA_ENTRY_COUNT_MNT_START	HCA_ENTRY_BIT(4)
#define HCA_ENTRY_COUNT_MNT_MAX		BMASK(HCA_ENTRY_COUNT_MNT_LENGTH)

#define HCA_ENTRY_GET_COUNT_MNT(e)	GET_FIELD((e), HCA_ENTRY_COUNT_MNT_START, HCA_ENTRY_COUNT_MNT_LENGTH)
#define HCA_ENTRY_SET_COUNT_MNT(e, m)	SET_FIELD((e), HCA_ENTRY_COUNT_MNT_START, HCA_ENTRY_COUNT_MNT_LENGTH, (m))

#define HCA_ENTRY_GET_COUNT(e)		((1UL << (2 * HCA_ENTRY_GET_COUNT_EXP(e))) * HCA_ENTRY_GET_COUNT_MNT(e))
#define HCA_ENTRY_SET_COUNT(e, x, m)	HCA_ENTRY_SET_COUNT_EXP((e), (x)) | HCA_ENTRY_SET_COUNT_MNT((e), (m))


#define HCA_ENTRY_AGE_LENGTH		3
#define HCA_ENTRY_AGE_START		HCA_ENTRY_BIT(16)
#define HCA_ENTRY_AGE_MAX		BMASK(HCA_ENTRY_AGE_LENGTH)

#define HCA_ENTRY_GET_AGE(e)		GET_FIELD((e), HCA_ENTRY_AGE_START, HCA_ENTRY_AGE_LENGTH)
#define HCA_ENTRY_SET_AGE(e, a)		SET_FIELD((e), HCA_ENTRY_AGE_START, HCA_ENTRY_AGE_LENGTH, (a))


#define HCA_ENTRY_GEN_LENGTH		1
#define HCA_ENTRY_GEN_START		HCA_ENTRY_BIT(19)
#define HCA_ENTRY_GEN_MAX		BMASK(HCA_ENTRY_GEN_LENGTH)

#define HCA_ENTRY_GET_GEN(e)		GET_FIELD((e), HCA_ENTRY_GEN_START, HCA_ENTRY_GEN_LENGTH)
#define HCA_ENTRY_SET_GEN(e, g)		SET_FIELD((e), HCA_ENTRY_GEN_START, HCA_ENTRY_GEN_LENGTH, (g))


#define HCA_ENTRY_PREV_COUNT_EXP_LENGTH	4
#define HCA_ENTRY_PREV_COUNT_EXP_START	HCA_ENTRY_BIT(20)
#define HCA_ENTRY_PREV_COUNT_EXP_MAX	BMASK(HCA_ENTRY_PREV_COUNT_EXP_LENGTH)

#define HCA_ENTRY_GET_PREV_COUNT_EXP(e)		\
					GET_FIELD((e), HCA_ENTRY_PREV_COUNT_EXP_START, HCA_ENTRY_PREV_COUNT_EXP_LENGTH)
#define HCA_ENTRY_SET_PREV_COUNT_EXP(e, x)	\
					SET_FIELD((e), HCA_ENTRY_PREV_COUNT_EXP_START, HCA_ENTRY_PREV_COUNT_EXP_LENGTH, (x))

#define HCA_ENTRY_PREV_COUNT_MNT_LENGTH	8
#define HCA_ENTRY_PREV_COUNT_MNT_START	HCA_ENTRY_BIT(24)
#define HCA_ENTRY_PREV_COUNT_MNT_MAX	BMASK(HCA_ENTRY_PREV_COUNT_MNT_LENGTH)

#define HCA_ENTRY_GET_PREV_COUNT_MNT(e)		\
					GET_FIELD((e), HCA_ENTRY_PREV_COUNT_MNT_START, HCA_ENTRY_PREV_COUNT_MNT_LENGTH)
#define HCA_ENTRY_SET_PREV_COUNT_MNT(e, m)	\
					SET_FIELD((e), HCA_ENTRY_PREV_COUNT_MNT_START, HCA_ENTRY_PREV_COUNT_MNT_LENGTH, (m))

#define HCA_ENTRY_GET_PREV_COUNT(e)	((1UL << (2 * HCA_ENTRY_GET_PREV_COUNT_EXP(e))) * HCA_ENTRY_GET_PREV_COUNT_MNT(e))
#define HCA_ENTRY_SET_PREV_COUNT(e, x, m)	\
					HCA_ENTRY_SET_PREV_COUNT_EXP((e), (x)) | HCA_ENTRY_SET_PREV_COUNT_MNT((e), (m))



#define HCA_ENTRY_TIMELOG_LENGTH	7
#define HCA_ENTRY_TIMELOG_START		HCA_ENTRY_BIT(32)
#define HCA_ENTRY_TIMELOG_MAX		BMASK(HCA_ENTRY_TIMELOG_LENGTH)

#define HCA_ENTRY_GET_TIMELOG(e)	GET_FIELD((e), HCA_ENTRY_TIMELOG_START, HCA_ENTRY_TIMELOG_LENGTH)
#define HCA_ENTRY_SET_TIMELOG(e, t)	SET_FIELD((e), HCA_ENTRY_TIMELOG_START, HCA_ENTRY_TIMELOG_LENGTH, (t))


#define HCA_ENTRY_SOCKETID_COUNT	5
#define HCA_ENTRY_SOCKETID_LENGTH	5
#define HCA_ENTRY_SOCKETID_MAX		BMASK(HCA_ENTRY_SOCKETID_LENGTH)

#define HCA_ENTRY_SOCKETID_START(s)	(HCA_ENTRY_BIT(39) + (s) * HCA_ENTRY_SOCKETID_LENGTH)
#define HCA_ENTRY_GET_SOCKETID(e, s)	GET_FIELD((e), HCA_ENTRY_SOCKETID_START(s), HCA_ENTRY_SOCKETID_LENGTH)
#define HCA_ENTRY_SET_SOCKETID(e, s, i)	SET_FIELD((e), HCA_ENTRY_SOCKETID_START(s), HCA_ENTRY_SOCKETID_LENGTH, (i))

#endif /* _ASM_POWERPC_HCA_H */
