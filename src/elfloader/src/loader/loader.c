/**
 * A simple ELF loader that loads a duplicated .text into memory.
 *
 * Usage:
 *   $ BIN=<binary-variant> CONF=conf/<func.conf> LD_PRELOAD=./loader.so ./<binary-vanilla> param1 param2 ...
 * Note: the two binaries could be different; the conf file is a list of function names,
 * each in a separate line.
 * 
 * Reference:
 *   http://man7.org/linux/man-pages/man5/elf.5.html
 *
 * Author: Xiaoguang Wang
 * */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>

#include "../../inc/lmvx.h"
#include "../../inc/log.h"

/*
 * --- ELF64 header defination (/usr/include/elf.h) ---
 * typedef struct
 * {
 *  unsigned char	e_ident[EI_NIDENT];	// Magic number and other info. | u64*2
 *  Elf64_Half	e_type;			// Object file type. u16
 *  Elf64_Half	e_machine;		// Architecture. u16 
 *  Elf64_Word	e_version;		// Object file version. u32 | u64
 *  Elf64_Addr	e_entry;		// Entry point virtual address. | u64
 *  Elf64_Off	e_phoff;		// Program header table file offset. | u64 
 *  Elf64_Off	e_shoff;		// Section header table file offset. | u64 
 *  Elf64_Word	e_flags;		// Processor-specific flags. u32 
 *  Elf64_Half	e_ehsize;		// ELF header size in bytes. u16
 *  Elf64_Half	e_phentsize;	// Program header table entry size. u16 | u64 
 *  Elf64_Half	e_phnum;		// Program header table entry count. u16 
 *  Elf64_Half	e_shentsize;	// Section header table entry size. u16
 *  Elf64_Half	e_shnum;		// Section header table entry count. u16
 *  Elf64_Half	e_shstrndx;		// Section header string table index. u16 | u64
 * } Elf64_Ehdr;			// u64*8 = 8*8 bytes = 64 bytes
 * */

#define WARN_BIN	 "No variant binary specified."
#define WARN_CONF	 "No conf file specified."
#define USAGE 		 "Use: $ BIN=<binary-variant> CONF=<func.conf> LD_PRELOAD=./loader.so ./<binary-vanilla> p1 p2 ..."

int init(void) __attribute__ ((constructor));
//int load_conf(const char *conf_filename);
int init_conf(const char *conf_filename, tbl_entry_t *ind_tbl, const char *conf_tbl_addr);
int load_elf(const char *bin_filename);

/**
 * Entry function of the LD_PRELOAD library.
 * */
int init(void)
{
	// get env file names
	const char *bin_filename = getenv("BIN");
	const char *conf_filename = getenv("CONF");
	if (bin_filename == NULL) {
		log_error(WARN_BIN);
		log_error(USAGE);
		exit(1);
	}
	if (conf_filename == NULL) {
		log_error(WARN_CONF);
		log_error(USAGE);
		exit(1);
	}

	// initialize ind_table (<name,addr> table)
	ind_table = malloc(TAB_SIZE*sizeof(tbl_entry_t));
	log_info("LD_PRELOAD init function. BIN %s. CONF %s. ind_tbl %p, ind_table[0].p %p",
			bin_filename, conf_filename, ind_table, &(ind_table[0].func_addr));

	// load conf file
	if (init_conf(conf_filename, ind_table, CONF_TAB_ADDR_FILE)) {
		log_error("Failed to load conf file.");
		exit(1);
	}

	// load ELF .text section
	if (load_elf(bin_filename)) {
		log_error("Failed to load ELF binary.");
		exit(1);
	}

	return 0;
}

void print_elf_header(Elf64_Ehdr *elf_header)
{
	log_info("%s: version %d, OS abi %d. entry 0x%lx", __func__,
			elf_header->e_version, elf_header->e_ident[7], elf_header->e_entry);
}

/**
 * Loading ELF .text section into memory.
 * */
int load_elf(const char *bin_filename)
{
	int i;
	Elf64_Ehdr *elf_header = malloc(sizeof(Elf64_Ehdr));
	Elf64_Shdr *elf_section_headers = NULL;
	Elf64_Shdr *sh_strtab_header = NULL;
	char *sh_strtab = NULL;
	size_t sections;
	size_t section_header_size = sizeof(Elf64_Shdr);

	FILE *obj = fopen(bin_filename, "rb");

	// retrieve ELF header
	if (obj == NULL) {
		log_error("Unable to open file.");
		return 1;
	}
	fread(elf_header, sizeof(Elf64_Ehdr), 1, obj);

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

	// allocate the ELF section header table in memory
	sections = elf_header->e_shnum;
	elf_section_headers = malloc(section_header_size * sections);
	log_info("sections %lu, section header size %lu",
			sections, section_header_size * sections);

	// read ELF section header table from binary
	fseek(obj, elf_header->e_shoff, SEEK_SET);
	fread(elf_section_headers, section_header_size, sections, obj);

	// retrieve sh_strtab header
	sh_strtab_header = elf_section_headers + elf_header->e_shstrndx;
	sh_strtab = malloc(sh_strtab_header->sh_size);
	fseek(obj, sh_strtab_header->sh_offset, SEEK_SET);
	fread(sh_strtab, sh_strtab_header->sh_size, 1, obj);

	for (i = 0; i < sections; i++) {
		Elf64_Shdr *section = elf_section_headers + i;
		if (strcmp(".text", sh_strtab + section->sh_name)) continue;
		log_info("section[%2d] addr 0x%lx, size 0x%lx. flag 0x%lx. name idx %u. name %s.",
				i, section->sh_addr, section->sh_size, section->sh_flags, section->sh_name,
				sh_strtab + section->sh_name);

		// allocate .text memory, using offset+size(end) as the memory block size.
		if ((section->sh_flags & (SHF_ALLOC | SHF_EXECINSTR))
				&& (section->sh_size > 0)) {
			uint64_t offset = section->sh_offset;
			uint64_t mem_size = offset + section->sh_size;
			char *mem = mmap(NULL, mem_size,
					PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

			log_info("alloc mem: %p, off 0x%lx, .text size 0x%lx, mem size 0x%lx",
					mem, offset, section->sh_size, mem_size);
			fseek(obj, offset, SEEK_SET);
			fread(mem + offset, section->sh_size, 1, obj);
			log_info("mem[0] %p, char in hex: 0x%x", mem + offset, mem[offset]);
		}
#if 0
		if (section->sh_type == SHT_SYMTAB || section->sh_type == SHT_STRTAB) {
			Elf64_Sym *table = malloc(section->sh_size);
			fseek(obj, section->sh_offset, SEEK_SET);
			fread(table, section->sh_size, 1, obj);
			section->sh_addr = (uint64_t)table;
			printf("type %d\n", section->sh_type);
		}
#endif
	}

	return 0;
}

/**
 * Loading the configuration files (list of duplicated functions).
 * */
//int load_conf(const char *conf_filename, tbl_entry_t *ind_tbl)
int init_conf(const char *conf_filename, tbl_entry_t *ind_tbl, const char *conf_tbl_addr)
{
	FILE *conf = fopen(conf_filename, "r");
	FILE *conf_tbl = fopen(conf_tbl_addr, "w");
	char func_name[128];
	int idx = 0;

	if (conf == NULL) {
		log_error("Unable to open file.");
		return 1;
	}
	while (fscanf(conf, "%s", func_name) != EOF) {
		ind_tbl[idx].func_name = malloc(strlen(func_name) + 1);
		strcpy(ind_tbl[idx].func_name, func_name);
		log_info("%d: %s. %s. %u/%u", idx, func_name, ind_tbl[idx].func_name, strlen(func_name), sizeof(func_name));
		idx++;
	}
	fclose(conf);

	fprintf(conf_tbl, "%p", ind_tbl);
	fclose(conf_tbl);

	return 0;
}
