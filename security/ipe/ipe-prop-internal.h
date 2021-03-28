/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe-property.h"

#include <linux/types.h>

#ifndef IPE_PROPERTY_INTERNAL_H
#define IPE_PROPERTY_INTERNAL_H

/* built-in tokens */
#define IPE_HEADER_POLICY_NAME		"policy_name"
#define IPE_HEADER_POLICY_VERSION	"policy_version"
#define IPE_PROPERTY_OPERATION		"op"
#define IPE_PROPERTY_DEFAULT		"DEFAULT"
#define IPE_PROPERTY_ACTION		"action"

/* Version strings for built-in tokens */
#define IPE_PROPERTY_OPERATION_VER	IPE_PROPERTY_OPERATION		"=1"
#define IPE_PROPERTY_ACTION_VER		IPE_PROPERTY_ACTION		"=1"
#define IPE_PROPERTY_DEFAULT_VER	IPE_PROPERTY_DEFAULT		"=1"
#define IPE_HEADER_POLICY_NAME_VER	IPE_HEADER_POLICY_NAME		"=1"
#define IPE_HEADER_POLICY_VERSION_VER	IPE_HEADER_POLICY_VERSION	"=1"

#define IPE_OP_EXECUTE		"EXECUTE"
#define IPE_OP_FIRMWARE		"FIRMWARE"
#define IPE_OP_KEXEC_IMAGE	"KEXEC_IMAGE"
#define IPE_OP_KEXEC_INITRAMFS	"KEXEC_INITRAMFS"
#define IPE_OP_X509_CERTIFICATE	"X509_CERT"
#define IPE_OP_POLICY		"POLICY"
#define IPE_OP_KMODULE		"KMODULE"
#define IPE_OP_READ		"READ"
#define IPE_OP_KERNEL_READ	"KERNEL_READ"

#define IPE_UNKNOWN		"UNKNOWN"

struct ipe_prop_reg {
	struct rb_node node;
	const struct ipe_property *prop;
};

int ipe_for_each_prop(int (*view)(const struct ipe_property *prop,
				  void *ctx),
		      void *ctx);

const struct ipe_property *ipe_lookup_prop(const char *key);

#endif /* IPE_PROPERTY_INTERNAL_H */
