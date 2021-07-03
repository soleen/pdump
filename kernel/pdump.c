#include <linux/crash_dump.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/memblock.h>
#include <linux/pdump.h>
#include <linux/reboot.h>
#include <linux/uaccess.h>
#include <asm/sections.h>

/* Align section to the largest page */
#define PDUMP_ALIGN	0x10000

/*
 * Determine nhdr size based on name size, description size, and 4 byte aliment
 * requirement
 */
#define PDUMP_NHDR_SIZE(nhdr)	(sizeof(Elf64_Nhdr) +			\
				(((u64)(nhdr)->n_namesz + 3) & ~3) +	\
			    (((u64)(nhdr)->n_descsz + 3) & ~3))

/* FIXME: this should be set dynamically via kernel parameter or device tree */
static unsigned long pdump_addr = 0x980000000;
static unsigned long pdump_size = 0x80000000;

/* Save up-to a page to pdump */
static ssize_t pdump_save_page(unsigned long offset, char *buf, size_t size)
{
	unsigned long poff = offset_in_page(offset);
	phys_addr_t pa = pdump_addr + offset - poff;
	void *vaddr;

	size = min(PAGE_SIZE - poff, size);
	if (!size)
		return 0;

	/* Differentiate end of pdump device error */
	if (pa + poff + size > pdump_addr + pdump_size)
		return -ENXIO;

	vaddr = memremap(pa, PAGE_SIZE, MEMREMAP_WB);
	if (!vaddr) {
		pr_err("%s: memramp failed, pdump is not saved\n", __func__);
		return -ENOMEM;
	}
	memcpy(vaddr + poff, buf, size);
	memunmap(vaddr);

	return size;
}

/* Save buffer to pdump */
static ssize_t pdump_save_buf(unsigned long offset, char *buf, size_t size)
{
	size_t orig_size = size;
	ssize_t rc = 0;

	while (size > 0) {
		rc = pdump_save_page(offset, buf, size);
		if (rc <= 0)
			break;
		offset += rc;
		size -= rc;
		buf += rc;
	}

	if (rc < 0 && rc != -ENXIO)
		return rc;

	return orig_size - size;
}

/*
 * Save memory range to pdump, and also save program header for this
 * range.
 * Return offset to where next range should be stored, and also return
 * offset to the next program header.
 */
static int pdump_save_range(unsigned long *phdr_offset,
			    unsigned long *data_offset,
			    phys_addr_t start, phys_addr_t end)
{
	Elf64_Phdr phdr;
	ssize_t rc;

	memset(&phdr, 0, sizeof (phdr));
	phdr.p_type = PT_LOAD;
	phdr.p_flags = PF_R|PF_W|PF_X;
	phdr.p_vaddr = (unsigned long) __va(start);
	phdr.p_filesz = phdr.p_memsz = end - start;
	phdr.p_offset = *data_offset;
	phdr.p_paddr = start;

	rc = pdump_save_buf(*phdr_offset, (char *)&phdr, sizeof(phdr));
	if (rc < 0)
		return (int)rc;

	rc = pdump_save_buf(*data_offset, __va(start), phdr.p_memsz);
	if (rc < 0)
		return (int)rc;

	if (rc < phdr.p_memsz) {
		pr_warn("pdump: range truncated [%llx %llx]\n",
			start + rc, end -1);
	}
	*phdr_offset += sizeof(Elf64_Phdr);
	*data_offset += rc;

	return 0;
}

/*
 * Loop through all memory ranges, and save them to pdump.
 */
static int pdump_save_data(unsigned long phdr_offset, unsigned long data_offset)
{
	phys_addr_t start, end;
	int rc;
	u64 i;

	/* text is added twice to match vmcore structure. */
	rc = pdump_save_range(&phdr_offset, &data_offset,
			      __pa_symbol(_text),
			      __pa_symbol(_end));
	if (rc < 0)
		return rc;

	for_each_mem_range(i, &start, &end) {
#ifdef CONFIG_KEXEC_CORE
		/* Omit crash kernel reserved area */
		if (crashk_res.start >= start && crashk_res.end  < end) {
			phys_addr_t kstart = crashk_res.start;
			phys_addr_t kend = crashk_res.end + 1;

			if (kstart == start && kend == end)
				continue;
			else if (kstart == start) {
				start = kend;
			} else if (kend == end) {
				end = kstart;
			} else {
				rc = pdump_save_range(&phdr_offset,
						      &data_offset,
						      start, kstart);
				if (rc < 0)
					return rc;
				start = kend;
			}
		}
#endif
		rc = pdump_save_range(&phdr_offset, &data_offset, start, end);
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int pdump_get_phnum(void)
{
	phys_addr_t start, end;
	int phnum;
	u64 i;

	/* program header for NOTE, and kernel TEXT sections */
	phnum = 2;

	for_each_mem_range(i, &start, &end) {
#ifdef CONFIG_KEXEC_CORE
		/* crash kernel is in the middle of a memory range */
		if (crashk_res.start > start && crashk_res.end + 1 < end)
			phnum++;
		else if (crashk_res.start == start && crashk_res.end + 1 == end)
			phnum--;
#endif
		phnum++;
	}

	return phnum;
}

/*
 * Save ehdr to pdump, and returns offsets to the beginning of
 * phdr section and to the beginning of notes section.
 */
static int pdump_save_elf_header(unsigned long *phdr_offset,
				 unsigned long *notes_offset)
{
	Elf64_Ehdr ehdr;
	ssize_t rc;

	memset(&ehdr, 0, sizeof (ehdr));
	memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ELFCLASS64;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELF_OSABI;
	ehdr.e_type = ET_CORE;
	ehdr.e_machine = ELF_ARCH;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_phoff = sizeof(Elf64_Ehdr);
	ehdr.e_ehsize = sizeof(Elf64_Ehdr);
	ehdr.e_phentsize = sizeof(Elf64_Phdr);
	ehdr.e_phnum = pdump_get_phnum();
	rc = pdump_save_buf(0, (char *)&ehdr, sizeof (ehdr));
	if (rc < 0)
		return (int)rc;

	*phdr_offset = sizeof(ehdr);
	*notes_offset = ALIGN(sizeof(ehdr) + sizeof(Elf64_Phdr) * ehdr.e_phnum,
			      PDUMP_ALIGN);

	return 0;
}

/*
 * Save notes program header, and notes section. The notes section includes the
 * prstatus register saves per-cpu, and vminfo. Return offset to the beginning
 * of data section, and offset to the next program header.
 */
static int pdump_save_notes(unsigned long notes_offset,
			    unsigned long *phdr_offset,
			    unsigned long *data_offset)
{
	unsigned long orig_notes_offset = notes_offset;
	unsigned int cpu;
	Elf64_Nhdr *buf;
	Elf64_Phdr phdr;
	ssize_t rc;

	/* Save per-cpu notes */
	for_each_present_cpu(cpu) {
		/* FIXME: crash_notes available via KEXEC, remove dependency */
		buf = (Elf64_Nhdr *)per_cpu_ptr(crash_notes, cpu);

		rc = pdump_save_buf(notes_offset, (char *)buf,
				    PDUMP_NHDR_SIZE(buf));
		if (rc < 0)
			return (int)rc;
		notes_offset += rc;
	}

	/* save vminfo note */
	buf = (Elf64_Nhdr *)vmcoreinfo_note;
	rc = pdump_save_buf(notes_offset, (char *)buf, PDUMP_NHDR_SIZE(buf));
	if (rc < 0)
		return (int)rc;
	notes_offset += rc;

	memset(&phdr, 0, sizeof (phdr));
	phdr.p_type = PT_NOTE;
	phdr.p_offset = orig_notes_offset;
	phdr.p_filesz = phdr.p_memsz = notes_offset - orig_notes_offset;

	rc = pdump_save_buf(*phdr_offset, (char *)&phdr, sizeof(phdr));
	if (rc < 0)
		return (int)rc;

	*phdr_offset += sizeof(phdr);
	*data_offset += ALIGN(notes_offset, PDUMP_ALIGN);

	return 0;
}

int pdump_save(void)
{
	unsigned long notes_offset, phdr_offset, data_offset;
	int rc;

	rc = pdump_save_elf_header(&phdr_offset, &notes_offset);
	if (rc)
		return rc;

	rc = pdump_save_notes(notes_offset, &phdr_offset, &data_offset);
	if (rc)
		return rc;

	rc = pdump_save_data(phdr_offset, data_offset);
	if (rc)
		return rc;

	return 0;
}

#ifdef CONFIG_PDUMP_FIRMWARE_ASSISTED
void pdump_reboot(void)
{
	/*
	 * FIXME: during boot we should init some stuff for easier
	 * re-creation of core
	 */
	if (panic_reboot_mode == REBOOT_UNDEFINED)
		reboot_mode = REBOOT_CRASH;
	else
		reboot_mode = panic_reboot_mode;
	emergency_restart();
}

void reboot_crash_get_cookie(unsigned long *cookie)
{
	unsigned long last_epfn = 0;
	struct zone *zone;

	for_each_populated_zone(zone) {
		if (zone_idx(zone) < ZONE_MOVABLE) {
			unsigned long epfn = zone_end_pfn(zone);

			if (epfn > last_epfn)
				last_epfn = epfn;
		}
	}
	*cookie =  PFN_PHYS(last_epfn);
	/* XXX hardcode cookie for testing */
	*cookie = 0xfc800000;
}
EXPORT_SYMBOL(reboot_crash_get_cookie);
#endif
