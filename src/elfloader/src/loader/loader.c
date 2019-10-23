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
int init_conf(const char *conf_filename, tbl_entry_t *ind_tbl, const char *conf_tbl_addr);
int load_elf(const char *bin_filename, tbl_entry_t *ind_tbl);

int func_num = 0;
void *text_base = NULL;

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
		exit(EXIT_FAILURE);
	}
	if (conf_filename == NULL) {
		log_error(WARN_CONF);
		log_error(USAGE);
		exit(EXIT_FAILURE);
	}

	// initialize ind_table (<name,addr> table)
	ind_table = malloc(TAB_SIZE*sizeof(tbl_entry_t));
	log_info("LD_PRELOAD init function. BIN %s. CONF %s.", bin_filename, conf_filename);
	log_info("--> ind_tbl %p, ind_table[0].p %p", ind_table, &(ind_table[0].func_addr));

	// load conf file
	if (init_conf(conf_filename, ind_table, CONF_TAB_ADDR_FILE)) {
		log_error("Failed to load conf file.");
		exit(EXIT_FAILURE);
	}

	// load ELF .text section
	if (load_elf(bin_filename, ind_table)) {
		log_error("Failed to load ELF binary.");
		exit(EXIT_FAILURE);
	}

	return 0;
}

/**
 * Loading the configuration files (list of duplicated functions).
 * */
int init_conf(const char *conf_filename, tbl_entry_t *ind_tbl, const char *conf_tbl_addr)
{
	FILE *conf = fopen(conf_filename, "r");
	FILE *conf_tbl = fopen(conf_tbl_addr, "w");
	char func_name[128];

	if (conf == NULL) {
		log_error("Unable to open file.");
		return 1;
	}

	// zero out the indirection table and the number of table entries (func num).
	memset(ind_tbl, 0, TAB_SIZE * sizeof(tbl_entry_t));
	func_num = 0;

	while (fscanf(conf, "%s", func_name) != EOF) {
		ind_tbl[func_num].func_name = malloc(strlen(func_name) + 1);
		strcpy(ind_tbl[func_num].func_name, func_name);
		log_info("%d: %s. %s. %u/%u", func_num, func_name, ind_tbl[func_num].func_name,
				strlen(func_name), sizeof(func_name));
		func_num++;
	}
	fclose(conf);
	log_info("num of functions %d", func_num);

	// print out the indirection table location in memory.
	fprintf(conf_tbl, "%p", ind_tbl);
	fclose(conf_tbl);

	return 0;
}

void print_elf_header(Elf64_Ehdr *elf_header)
{
	log_info("%s: version %d, OS abi %d. entry 0x%lx", __func__,
			elf_header->e_version, elf_header->e_ident[7], elf_header->e_entry);
}

/**
 * Process the .text section:
 * 	- alloc memory for variant's .text with mmap
 * 	- copy binary's .text to memory
 * */
void* process_text_section(FILE *obj, Elf64_Shdr *section)
{
	uint64_t offset = 0, mem_size = 0;
	char *mem = NULL;

	// allocate .text memory, using offset+size(end) as the memory block size.
	if ((section->sh_flags & (SHF_ALLOC | SHF_EXECINSTR))
			&& (section->sh_size > 0)) {
		offset = section->sh_offset;
		mem_size = offset + section->sh_size;
		mem = mmap(NULL, mem_size,
				PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
		// TODO: permission not W xor E

		log_info("alloc mem: %p, off 0x%lx, .text size 0x%lx, mem size 0x%lx",
				mem, offset, section->sh_size, mem_size);
		fseek(obj, offset, SEEK_SET);
		fread(mem + offset, section->sh_size, 1, obj);
		log_info("mem[0] %p, char in hex: 0x%x", mem + offset, mem[offset]);
	}
	return mem;
}

int sym_in_table(char *symbol, tbl_entry_t *ind_tbl)
{
	int i;
	tbl_entry_t *entry;
	for (i = 0; i < TAB_SIZE; i++) {
		entry = ind_tbl + i;
		if (entry->func_name == NULL) break;
		if (strcmp(entry->func_name, symbol) == 0)
			return i;
	}
	return -1;
}

/**
 * Process the .symtab (symbol table) section
 * */
void process_symtab_section(FILE *obj, Elf64_Shdr *section, tbl_entry_t *ind_tbl,
		char *strtab, void *base)
{
	uint64_t offset = 0, size = 0;
	int i;
	int idx = 0;
	int ret = 0;
	int entry_num;
	Elf64_Sym *symtab;
	Elf64_Sym *entry;

	offset = section->sh_offset;
	size = section->sh_size;
	entry_num = size / sizeof(Elf64_Sym);
	symtab = (Elf64_Sym *) malloc(size);
	log_info("symtab offset %lu, size %lu, entry num %d", offset, size, entry_num);

	fseek(obj, offset, SEEK_SET);
	fread(symtab, size, 1, obj);

	for (i = 0; i < entry_num; i++) {
		entry = symtab + i;
		idx = entry->st_name;
		if (entry->st_name == 0) continue;
		if ((ret = sym_in_table(strtab + idx, ind_tbl)) != -1) {
			log_info("symtab[%2d] %s. ret %d. st_value 0x%lx", i, strtab + idx, ret, entry->st_value);
			(ind_tbl+ret)->func_addr = base + entry->st_value;
		}
	}
}

/**
 * Loading ELF .text section into memory.
 * */
int load_elf(const char *bin_filename, tbl_entry_t *ind_tbl)
{
	int i;
	Elf64_Ehdr *elf_header = malloc(sizeof(Elf64_Ehdr));
	Elf64_Shdr *elf_section_headers = NULL;
	Elf64_Shdr *strtab_header = NULL;			// .strtab section header
	Elf64_Shdr *symtab_header = NULL;			// .symtab section header
	Elf64_Shdr *sh_strtab_header = NULL;		// .shstrtab
	char *strtab = NULL;
	char *sh_strtab = NULL;
	size_t section_num;
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
	section_num = elf_header->e_shnum;
	elf_section_headers = malloc(section_header_size * section_num);
	log_info("section_num %lu, section header size %lu",
			section_num, section_header_size * section_num);

	// read ELF section header table from binary
	fseek(obj, elf_header->e_shoff, SEEK_SET);
	fread(elf_section_headers, section_header_size, section_num, obj);

	// retrieve sh_strtab header (section header string table)
	sh_strtab_header = elf_section_headers + elf_header->e_shstrndx;
	sh_strtab = malloc(sh_strtab_header->sh_size);
	fseek(obj, sh_strtab_header->sh_offset, SEEK_SET);
	fread(sh_strtab, sh_strtab_header->sh_size, 1, obj);

	for (i = 0; i < section_num; i++) {
		Elf64_Shdr *section = elf_section_headers + i;

		// load .text section into memory space
		if (strcmp(".text", sh_strtab + section->sh_name) == 0) {
			text_base = process_text_section(obj, elf_section_headers + i);
			if (text_base == NULL)
				log_error("variant .text allocation error");
		}

		if (strcmp(".symtab", sh_strtab + section->sh_name) == 0) {
			symtab_header = elf_section_headers + i;
		}

		// read .strtab from ELF binary
		if (strcmp(".strtab", sh_strtab + section->sh_name) == 0) {
			strtab_header = elf_section_headers + i;
			strtab = malloc(strtab_header->sh_size);
			fseek(obj, strtab_header->sh_offset, SEEK_SET);
			fread(strtab, strtab_header->sh_size, 1, obj);
		}
	}
	
	// process .symtab section
	process_symtab_section(obj, symtab_header, ind_tbl, strtab, text_base);

	return 0;
}


