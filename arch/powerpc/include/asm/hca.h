// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright 2021, Sandipan Das, IBM Corp.
 * Configuration encodings that go with the Hot-Cold Affinity helper
 */

#ifndef _ASM_POWERPC_HCA_H
#define _ASM_POWERPC_HCA_H

#define KB	(1024UL)
#define MB	(1024 * KB)
#define GB	(1024 * MB)
#define TB	(1024 * TB)

#define HCA_UNITS_PER_CHIP		2

#define HCA_ENTRY_SIZE			8

#define HCA_COUNTER_MASK_DEFAULT	16
#define HCA_CMD_SAMPLING_RATE_DEFAULT	0
#define HCA_MONITOR_SIZE_DEFAULT	(16 * GB)

#endif /* _ASM_POWERPC_HCA_H */
