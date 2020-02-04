/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * PAPR SCM Device specific methods for libndctl and ndctl
 *
 * (C) Copyright IBM 2020
 *
 * Author: Vaibhav Jain <vaibhav at linux.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _UAPI_ASM_POWERPC_PAPR_SCM_DSM_H_
#define _UAPI_ASM_POWERPC_PAPR_SCM_DSM_H_

#include <linux/types.h>
#include <asm/bitsperlong.h>

#ifdef __KERNEL__
#include <linux/ndctl.h>
#include <linux/stringify.h>
#else
#include <ndctl.h>
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef PPC_BITLSHIFT
/* PPC bit number conversion */
#define PPC_BITLSHIFT(be)	(__BITS_PER_LONG - 1 - (be))
#endif

#ifndef PPC_BIT
#define PPC_BIT(bit)		(1UL << PPC_BITLSHIFT(bit))
#endif

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
/* SCM device is unable to persist memory contents */
#define ND_PAPR_SCM_DIMM_UNARMED		PPC_BIT(0)
/* SCM device failed to persist memory contents */
#define ND_PAPR_SCM_DIMM_SHUTDOWN_DIRTY		PPC_BIT(1)
/* SCM device contents are persisted from previous IPL */
#define ND_PAPR_SCM_DIMM_SHUTDOWN_CLEAN		PPC_BIT(2)
/* SCM device contents are not persisted from previous IPL */
#define ND_PAPR_SCM_DIMM_EMPTY			PPC_BIT(3)
/* SCM device memory life remaining is critically low */
#define ND_PAPR_SCM_DIMM_HEALTH_CRITICAL	PPC_BIT(4)
/* SCM device will be garded off next IPL due to failure */
#define ND_PAPR_SCM_DIMM_HEALTH_FATAL		PPC_BIT(5)
/* SCM contents cannot persist due to current platform health status */
#define ND_PAPR_SCM_DIMM_HEALTH_UNHEALTHY	PPC_BIT(6)
/* SCM device is unable to persist memory contents in certain conditions */
#define ND_PAPR_SCM_DIMM_HEALTH_NON_CRITICAL	PPC_BIT(7)
/* SCM device is encrypted */
#define ND_PAPR_SCM_DIMM_ENCRYPTED		PPC_BIT(8)

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

/* Payload expected with ND_CMD_CALL ioctl from libnvdimm */
struct nd_pkg_papr_scm {
	struct nd_cmd_pkg hdr;		/* Package header containing sub-cmd */
	uint32_t cmd_status;		/* Out: Sub-cmd status returned back */
	uint32_t reserved;
	uint8_t payload[];		/* Out: Sub-cmd data buffer */
} __packed;

/* Helpers to evaluate the size of PAPR_SCM envelope */
#define ND_PAPR_SCM_ENVELOPE_CONTENT_HDR_SIZE \
	(sizeof (struct nd_pkg_papr_scm) - sizeof (struct nd_cmd_pkg))

#define ND_PAPR_SCM_ENVELOPE_SIZE(_type_)	\
	(sizeof (_type_) + sizeof (struct nd_pkg_papr_scm))

#define ND_PAPR_SCM_ENVELOPE_CONTENT_SIZE(_type_)	\
	(sizeof (_type_) + ND_PAPR_SCM_ENVELOPE_CONTENT_HDR_SIZE)

/* Struct as returned by kernel in response to PAPR_DSM_PAPR_SMART_HEALTH */
struct papr_scm_ndctl_health {
	__be64 health_bitmap;
	__be64 health_bitmap_valid;
} __packed;

#ifndef __stringify
#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)
#endif

#define ND_PAPR_SCM_PERF_STATS_EYECATCHER __stringify(SCMSTATS)

/* Buffer layout returned by phyp when reporting drc perf stats */
struct papr_scm_perf_stats {
	uint8_t eye_catcher[8];
	__be32 stats_version;		/* Should be 0x01 */
	__be32 num_statistics;		/* Number of stats following */

	struct {
		__be64 statistic_id;
		__be64 statistic_value;
	} scm_statistics[];		/* Performance matrics */
} __packed;

static struct nd_pkg_papr_scm * nd_to_papr_cmd_pkg(struct nd_cmd_pkg * cmd)
{
	return ((struct nd_pkg_papr_scm *) cmd);
}

#endif /* _UAPI_ASM_POWERPC_PAPR_SCM_DSM_H_ */
