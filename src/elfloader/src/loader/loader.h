#ifndef __LOADER_H
#define __LOADER_H

#include <elf.h>
#include "../../inc/log.h"

void print_elf_header(Elf64_Ehdr *elf_header)
{
	log_info("%s: version %d, OS abi %d. entry 0x%lx", __func__,
			elf_header->e_version, elf_header->e_ident[7], elf_header->e_entry);
}

/**
 * Verify the correctness of ELF header.
 * */
int verify_elf(Elf64_Ehdr * elf_header)
{
	if (elf_header->e_ident[0] != 0x7f || elf_header->e_ident[1] != 'E'
			|| elf_header->e_ident[2] != 'L' || elf_header->e_ident[3] != 'F') {
		log_error("Invalid ELF header!");
		return 1;
	}

	if (elf_header->e_ident[4] != ELFCLASS64 ||
		elf_header->e_ident[5] != ELFDATA2LSB)
	{
		log_error("This file is not 64bit little endian.");
		return 1;
	}
	print_elf_header(elf_header);

	return 0;
}

/**
 * Read ELF section header and program (segment) header.
 * */
int read_seg_headers(FILE *obj, Elf64_Ehdr * elf_header, Elf64_Shdr **elf_section_headers,
		Elf64_Phdr **elf_program_headers)
{
	size_t section_header_size = sizeof(Elf64_Shdr);
	size_t program_header_size = sizeof(Elf64_Phdr);
	size_t section_num;
	size_t segment_num;

	// allocate the ELF section/program header table in memory
	section_num = elf_header->e_shnum;
	segment_num = elf_header->e_phnum;
	*elf_section_headers = malloc(section_header_size * section_num);
	*elf_program_headers = malloc(program_header_size * segment_num);
	log_info("section num %lu, size %lu; segment num %lu, size %lu",
			section_num, section_header_size * section_num,
			segment_num, program_header_size * segment_num);

	// read ELF section header table from binary
	fseek(obj, elf_header->e_shoff, SEEK_SET);
	fread(*elf_section_headers, section_header_size, section_num, obj);

	// read ELF segment (program) header table
	fseek(obj, elf_header->e_phoff, SEEK_SET);
	fread(*elf_program_headers, program_header_size, segment_num, obj);

	return 0;
}

/**
 * Read section header strtab.
 * */
int read_sh_strtab(FILE *obj, Elf64_Ehdr * elf_header, Elf64_Shdr *elf_section_headers,
		char **sh_strtab)
{
	Elf64_Shdr *sh_strtab_header = NULL;		// .shstrtab

	sh_strtab_header = elf_section_headers + elf_header->e_shstrndx;
	*sh_strtab = malloc(sh_strtab_header->sh_size);
	fseek(obj, sh_strtab_header->sh_offset, SEEK_SET);
	fread(*sh_strtab, sh_strtab_header->sh_size, 1, obj);

	return 0;
}

void *load_code_segment(FILE *obj, Elf64_Phdr *phdr)
{
	int fd = fileno(obj);
	void *ret = NULL;
	Elf64_Off offset = phdr->p_offset;
	Elf64_Xword filesz = phdr->p_filesz;
//	Elf64_Xword memsz = phdr->p_memsz;
//	Elf64_Xword align = phdr->p_align;
//	Elf64_Word flag = phdr->p_flags;
//	Elf64_Xword real_memsz = (memsz+4096)/4096 * 4096;

	log_info("fd %d", fd);
	ret = mmap(NULL, filesz, PROT_EXEC|PROT_READ, MAP_PRIVATE, fd, offset);
	if (ret == MAP_FAILED) log_error("mmap failed %d: %s", errno, strerror(errno));
	log_debug("ret %p", ret);

	return ret;
}

void *load_data_segment(FILE *obj, Elf64_Phdr *phdr, void *data_loc)
{
	int fd = fileno(obj);
	void *ret = NULL;
	Elf64_Off offset = phdr->p_offset;
	Elf64_Xword filesz = phdr->p_filesz;

	Elf64_Xword memsz = phdr->p_memsz;
	Elf64_Xword align = phdr->p_align;
	Elf64_Word flag = phdr->p_flags;

	log_debug("fd %d. offset %x, filesz %x, memsz %x, align %x, flag %x. %p",
			fd, offset, filesz, memsz, align, flag, data_loc);

	ret = mmap(data_loc, filesz, PROT_WRITE|PROT_READ, MAP_PRIVATE, fd, 0);
	if (ret == MAP_FAILED) log_error("mmap failed %d: %s", errno, strerror(errno));
	log_debug("ret %p", ret);

	return ret;
}

static inline int is_code_seg(Elf64_Phdr *phdr)
{
	if ((phdr->p_type == PT_LOAD) && (phdr->p_flags & PF_X)) {
		return 1;
	}
	return 0;
}

static inline int is_data_seg(Elf64_Phdr *phdr)
{
	if ((phdr->p_type == PT_LOAD) && (phdr->p_flags & PF_W)) {
		return 1;
	}
	return 0;
}

int load_segments(FILE *obj, Elf64_Ehdr * elf_header, Elf64_Phdr *phdr, void **text_base)
{
	int i = 0;
	Elf64_Phdr *cseg = NULL;
	Elf64_Phdr *dseg = NULL;

	for (i = 0; i < elf_header->e_phnum; i++) {
		if (is_code_seg(phdr + i)) {
			cseg = phdr + i;
			log_debug("code seg: off 0x%x, FileSiz 0x%x", cseg->p_offset, cseg->p_filesz);
		}
		if (is_data_seg(phdr + i)) {
			dseg = phdr + i;
			log_debug("data seg: off 0x%x, FileSiz 0x%x", dseg->p_offset, dseg->p_filesz);
		}
	}

	if (cseg == NULL || dseg == NULL) return 1;

	/* load code segment. */
	*text_base = load_code_segment(obj, cseg);

	/* load data segment. */
	load_data_segment(obj, dseg, *text_base + dseg->p_vaddr);

	return 0;
}

#endif
