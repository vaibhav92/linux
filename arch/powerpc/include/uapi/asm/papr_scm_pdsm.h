/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * PAPR-SCM Dimm specific methods (PDSM) and structs for libndctl
 *
 * (C) Copyright IBM 2020
 *
 * Author: Vaibhav Jain <vaibhav at linux.ibm.com>
 */

#ifndef _UAPI_ASM_POWERPC_PAPR_SCM_PDSM_H_
#define _UAPI_ASM_POWERPC_PAPR_SCM_PDSM_H_

#include <linux/types.h>

/*
 * PDSM Envelope:
 *
 * The ioctl ND_CMD_CALL transfers data between user-space and kernel via
 * 'envelopes' which consists of a header and user-defined payload sections.
 * The header is described by 'struct nd_pdsm_cmd_pkg' which expects a
 * payload following it and offset of which relative to the struct is provided
 * by 'nd_pdsm_cmd_pkg.payload_offset'. *
 *
 *  +-------------+---------------------+---------------------------+
 *  |   64-Bytes  |       8-Bytes       |       Max 184-Bytes       |
 *  +-------------+---------------------+---------------------------+
 *  |               nd_pdsm_cmd_pkg |                           |
 *  |-------------+                     |                           |
 *  |  nd_cmd_pkg |                     |                           |
 *  +-------------+---------------------+---------------------------+
 *  | nd_family   |			|			    |
 *  | nd_size_out | cmd_status          |			    |
 *  | nd_size_in  | payload_version     |      PAYLOAD		    |
 *  | nd_command  | payload_offset ----->			    |
 *  | nd_fw_size  |                     |			    |
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
 * 'payload_version'	: (In/Out) Version number associated with the payload.
 * 'payload_offset'	: (In)Relative offset of payload from start of envelope.
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
 * Payload Version:
 *
 * A 'payload_version' field is present in PDSM header that indicates a specific
 * version of the structure present in PDSM Payload for a given PDSM command.
 * This provides backward compatibility in case the PDSM Payload structure
 * evolves and different structures are supported by 'papr_scm' and 'libndctl'.
 *
 * When sending a PDSM Payload to 'papr_scm', 'libndctl' should send the version
 * of the payload struct it supports via 'payload_version' field. The 'papr_scm'
 * module when servicing the PDSM envelope checks the 'payload_version' and then
 * uses 'payload struct version' == MIN('payload_version field',
 * 'max payload-struct-version supported by papr_scm') to service the PDSM.
 * After servicing the PDSM, 'papr_scm' put the negotiated version of payload
 * struct in returned 'payload_version' field.
 *
 * Libndctl on receiving the envelope back from papr_scm again checks the
 * 'payload_version' field and based on it use the appropriate version dsm
 * struct to parse the results.
 *
 * Backward Compatibility:
 *
 * Above scheme of exchanging different versioned PDSM struct between libndctl
 * and papr_scm should provide backward compatibility until following two
 * assumptions/conditions when defining new PDSM structs hold:
 *
 * Let T(X) = { set of attributes in PDSM struct 'T' versioned X }
 *
 * 1. T(X) is a proper subset of T(Y) if X > Y.
 *    i.e Each new version of PDSM struct should retain existing struct
 *    attributes from previous version
 *
 * 2. If an entity (libndctl or papr_scm) supports a PDSM struct T(X) then
 *    it should also support T(1), T(2)...T(X - 1).
 *    i.e When adding support for new version of a PDSM struct, libndctl
 *    and papr_scm should retain support of the existing PDSM struct
 *    version they support.
 */

/* Papr-scm-header + payload expected with ND_CMD_CALL ioctl from libnvdimm */
struct nd_pdsm_cmd_pkg {
	struct nd_cmd_pkg hdr;	/* Package header containing sub-cmd */
	__s32 cmd_status;	/* Out: Sub-cmd status returned back */
	__u16 payload_offset;	/* In: offset from start of struct */
	__u16 payload_version;	/* In/Out: version of the payload */
	__u8 payload[];		/* In/Out: Sub-cmd data buffer */
} __packed;

/*
 * Methods to be embedded in ND_CMD_CALL request. These are sent to the kernel
 * via 'nd_pdsm_cmd_pkg.hdr.nd_command' member of the ioctl struct
 */
enum papr_scm_pdsm {
	PAPR_SCM_PDSM_MIN = 0x0,
	PAPR_SCM_PDSM_MAX,
};

/* Convert a libnvdimm nd_cmd_pkg to pdsm specific pkg */
static inline struct nd_pdsm_cmd_pkg *nd_to_pdsm_cmd_pkg(struct nd_cmd_pkg *cmd)
{
	return (struct nd_pdsm_cmd_pkg *) cmd;
}

/* Return the payload pointer for a given pcmd */
static inline void *pdsm_cmd_to_payload(struct nd_pdsm_cmd_pkg *pcmd)
{
	if (pcmd->hdr.nd_size_in == 0 && pcmd->hdr.nd_size_out == 0)
		return NULL;
	else
		return (void *)((__u8 *) pcmd + pcmd->payload_offset);
}

#endif /* _UAPI_ASM_POWERPC_PAPR_SCM_PDSM_H_ */
