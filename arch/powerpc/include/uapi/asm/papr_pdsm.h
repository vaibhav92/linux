/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * PAPR nvDimm Specific Methods (PDSM) and structs for libndctl
 *
 * (C) Copyright IBM 2020
 *
 * Author: Vaibhav Jain <vaibhav at linux.ibm.com>
 */

#ifndef _UAPI_ASM_POWERPC_PAPR_PDSM_H_
#define _UAPI_ASM_POWERPC_PAPR_PDSM_H_

#include <linux/types.h>

/*
 * PDSM Envelope:
 *
 * The ioctl ND_CMD_CALL transfers data between user-space and kernel via
 * envelope which consists of a header and user-defined payload sections.
 * The header is described by 'struct nd_pdsm_cmd_pkg' which expects a
 * payload following it and accessible via 'nd_pdsm_cmd_pkg.payload' field.
 * There is reserved field that can used to introduce new fields to the
 * structure in future. It also tries to ensure that 'nd_pdsm_cmd_pkg.payload'
 * lies at a 8-byte boundary.
 *
 *  +-------------+---------------------+---------------------------+
 *  |   64-Bytes  |       8-Bytes       |       Max 184-Bytes       |
 *  +-------------+---------------------+---------------------------+
 *  |               nd_pdsm_cmd_pkg     |                           |
 *  |-------------+                     |                           |
 *  |  nd_cmd_pkg |                     |                           |
 *  +-------------+---------------------+---------------------------+
 *  | nd_family   |                     |                           |
 *  | nd_size_out | cmd_status          |                           |
 *  | nd_size_in  | reserved            |     payload               |
 *  | nd_command  |                     |                           |
 *  | nd_fw_size  |                     |                           |
 *  +-------------+---------------------+---------------------------+
 *
 * PDSM Header:
 *
 * The header is defined as 'struct nd_pdsm_cmd_pkg' which embeds a
 * 'struct nd_cmd_pkg' instance. The PDSM command is assigned to member
 * 'nd_cmd_pkg.nd_command'. Apart from size information of the envelope which is
 * contained in 'struct nd_cmd_pkg', the header also has members following
 * members:
 *
 * 'cmd_status'		: (Out) Errors if any encountered while servicing PDSM.
 * 'reserved'		: Not used, reserved for future and should be set to 0.
 *
 * PDSM Payload:
 *
 * The layout of the PDSM Payload is defined by various structs shared between
 * papr_scm and libndctl so that contents of payload can be interpreted. During
 * servicing of a PDSM the papr_scm module will read input args from the payload
 * field by casting its contents to an appropriate struct pointer based on the
 * PDSM command. Similarly the output of servicing the PDSM command will be
 * copied to the payload field using the same struct.
 *
 * 'libnvdimm' enforces a hard limit of 256 bytes on the envelope size, which
 * leaves around 184 bytes for the envelope payload (ignoring any padding that
 * the compiler may silently introduce).
 *
 */

/* PDSM-header + payload expected with ND_CMD_CALL ioctl from libnvdimm */
struct nd_pdsm_cmd_pkg {
	struct nd_cmd_pkg hdr;	/* Package header containing sub-cmd */
	__s32 cmd_status;	/* Out: Sub-cmd status returned back */
	__u16 reserved[2];	/* Ignored and to be used in future */
	__u8 payload[];		/* In/Out: Sub-cmd data buffer */
} __packed;

/*
 * Methods to be embedded in ND_CMD_CALL request. These are sent to the kernel
 * via 'nd_pdsm_cmd_pkg.hdr.nd_command' member of the ioctl struct
 */
enum papr_pdsm {
	PAPR_PDSM_MIN = 0x0,
	PAPR_PDSM_MAX,
};

/* Convert a libnvdimm nd_cmd_pkg to pdsm specific pkg */
static inline struct nd_pdsm_cmd_pkg *nd_to_pdsm_cmd_pkg(struct nd_cmd_pkg *cmd)
{
	return (struct nd_pdsm_cmd_pkg *)cmd;
}

/* Return the payload pointer for a given pcmd */
static inline void *pdsm_cmd_to_payload(struct nd_pdsm_cmd_pkg *pcmd)
{
	if (pcmd->hdr.nd_size_in == 0 && pcmd->hdr.nd_size_out == 0)
		return NULL;
	else
		return (void *)(pcmd->payload);
}

#endif /* _UAPI_ASM_POWERPC_PAPR_PDSM_H_ */
