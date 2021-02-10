/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#ifndef IPE_H
#define IPE_H

#define pr_fmt(fmt) "IPE " fmt "\n"

#include <linux/types.h>
#include <linux/fs.h>

#define IPE_MODE_ENFORCE	"enforce"
#define IPE_MODE_PERMISSIVE	"permissive"

extern bool ipe_enforce;
extern bool ipe_success_audit;

#endif /* IPE_H */
