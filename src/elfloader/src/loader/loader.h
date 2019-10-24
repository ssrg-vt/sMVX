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
int read_headers(FILE *obj, Elf64_Ehdr * elf_header, Elf64_Shdr **elf_section_headers,
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
int read_sh_strtab(FILE *obj,Elf64_Ehdr * elf_header, Elf64_Shdr *elf_section_headers,
		char **sh_strtab)
{
	Elf64_Shdr *sh_strtab_header = NULL;		// .shstrtab

	sh_strtab_header = elf_section_headers + elf_header->e_shstrndx;
	*sh_strtab = malloc(sh_strtab_header->sh_size);
	fseek(obj, sh_strtab_header->sh_offset, SEEK_SET);
	fread(*sh_strtab, sh_strtab_header->sh_size, 1, obj);

	return 0;
}

#endif
