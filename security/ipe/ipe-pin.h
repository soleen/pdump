/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_PIN_H
#define IPE_PIN_H

#include <linux/types.h>
#include <linux/fs.h>

#ifdef CONFIG_IPE_BOOT_PROP

bool ipe_is_from_pinned_sb(const struct file *file);

void ipe_pin_superblock(const struct file *file);

void ipe_invalidate_pinned_sb(const struct super_block *mnt_sb);

#else /* CONFIG_IPE_BOOT_PROP */

static inline bool ipe_is_from_pinned_sb(const struct file *file)
{
	return false;
}

static inline void ipe_pin_superblock(const struct file *file)
{
}

static inline void ipe_invalidate_pinned_sb(const struct super_block *mnt_sb)
{
}

#endif /* !CONFIG_IPE_BOOT_PROP */

#endif /* IPE_PIN_H */
