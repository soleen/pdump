/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_PDUMP_H
#define __ASM_PDUMP_H

#ifdef CONFIG_PDUMP

int pdump_save(void);
#else
static inline int pdump_save(void)
{
	return 0;
}
#endif

#ifdef CONFIG_PDUMP_FIRMWARE_ASSISTED
void pdump_reboot(void);
#else
static inline void pdump_reboot(void)
{
}
#endif



#endif /* __ASM_PDUMP_H */
