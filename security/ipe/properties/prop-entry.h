/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/types.h>

#ifndef IPE_PROP_ENTRY_H
#define IPE_PROP_ENTRY_H

#ifndef CONFIG_IPE_BOOT_PROP
static inline int __init ipe_init_bootv(void)
{
	return 0;
}
#else
int __init ipe_init_bootv(void);
#endif /* CONFIG_IPE_BOOT_PROP */

#ifndef CONFIG_IPE_DM_VERITY_SIGNATURE
static inline int __init ipe_init_dm_verity_signature(void)
{
	return 0;
}
#else
int __init ipe_init_dm_verity_signature(void);
#endif /* CONFIG_IPE_DM_VERITY_SIGNATURE */

#ifndef CONFIG_IPE_DM_VERITY_ROOTHASH
static inline int __init ipe_init_dm_verity_rh(void)
{
	return 0;
}
#else
int __init ipe_init_dm_verity_rh(void);
#endif /* CONFIG_IPE_DM_VERITY_ROOTHASH */

#endif /* IPE_PROP_ENTRY_H */

#ifndef CONFIG_IPE_INTENDED_PATHNAME
static inline int __init ipe_init_intended_pathname(void)
{
	return 0;
}
#else
int __init ipe_init_intended_pathname(void);
#endif /* CONFIG_IPE_INTENDED_PATHNAME */
