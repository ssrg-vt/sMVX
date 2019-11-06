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

#include "../inc/lmvx.h"
#include "../inc/log.h"
#include "../inc/env.h"
#include "loader.h"

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

#define WARN_CONF	 "No conf file specified."
#define USAGE 		 "Use: $ CONF=<func.conf> LD_PRELOAD=./loader.so ./<binary-vanilla> p1 p2 ..."

#define TAB_SIZE	16
/* num of func_desc_t, and the array of func_desc_t */
int g_func_num = 0;
func_desc_t g_func[TAB_SIZE];

/* describe the proc info */
static proc_info_t pinfo;

static void *new_text_base = NULL;

/**
 * Entry function of the LD_PRELOAD library.
 * */
int init(int argc, char** argv, char** env)
{
	// get env file names
	const char *conf_filename = getenv("CONF");
	printf("%x. %s\n", argc, getenv("LOG_LEVEL"));
	init_env();

	if (conf_filename == NULL) {
		log_error(WARN_CONF);
		log_error(USAGE);
		exit(EXIT_FAILURE);
	}
//	log_info("LD_PRELOAD init function. CONF: %s. binary: %s.",
//			conf_filename, argv[0]);

	// load conf file
	if (init_conf(conf_filename, g_func)) {
		log_error("Failed to load conf file.");
		exit(EXIT_FAILURE);
	}

	// read proc, find .text base
	//read_proc(argv[0] + 2, &pinfo);
	read_proc("test.bin", &pinfo);

	// dup proc mem
	new_text_base = dup_proc(&pinfo);

	// rewrite first (several) instructions to redirect control to clone
	rewrite_insn(&pinfo, g_func);

	//log_debug("code 0x%lx/0x%lx. new text base %p", pinfo.code_start,
	//		pinfo.code_end, new_text_base);
	gen_conf(g_func, new_text_base, CONF_TAB_ADDR_FILE);

	return 0;
}

/**
 * Loading the config files (a list of sensitive functions <name,offset>)
 *   into an in-memory func_desc_t array.
 * Log the in-memory array address.
 * */
int init_conf(const char *conf_filename, func_desc_t *func)
{
	FILE *conf = fopen(conf_filename, "r");		// conf of function list.
	char func_name[128];
	int len = 0;
	uint32_t func_off = 0;

	if (conf == NULL) {
		log_error("Unable to open conf file: %s.", conf_filename);
		return 1;
	}

	g_func_num = 0;
	while (fscanf(conf, "%s %x", func_name, &func_off) != EOF) {
		len = strlen(func_name);
		// name
		func[g_func_num].name = malloc(len + 1);
		//func[g_func_num].name[len] = 0;
		//strncpy(func[g_func_num].name, func_name, len);
		strcpy(func[g_func_num].name, func_name);
		// offset + flag
		func[g_func_num].offset = func_off;
		func[g_func_num].flag = 0;
		log_debug("[%2d] %s: offset 0x%x. name len %d", g_func_num, func_name, func_off, len);
		g_func_num++;
	}
	fclose(conf);

	return 0;
}

void gen_conf(func_desc_t *func, void *base, const char *CONF_TBL_ADDR)
{
	FILE *conf_tbl = fopen(CONF_TBL_ADDR, "w");	// conf file of ind_tbl address

	fprintf(conf_tbl, "%p %p", func, base);
	fclose(conf_tbl);
}

#if 0
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
	Elf64_Phdr *elf_program_headers = NULL;
	char *sh_strtab = NULL;
	char *strtab = NULL;

	FILE *obj = fopen(bin_filename, "rb");

	/* read ELF header; verify ELF correctness */
	if (obj == NULL) {
		log_error("Unable to open file.");
		return 1;
	}
	fread(elf_header, sizeof(Elf64_Ehdr), 1, obj);
	if (verify_elf(elf_header)) return 1;

	/* read section and program headers from binary */
	read_seg_headers(obj, elf_header, &elf_section_headers, &elf_program_headers);

	/* read section header string table, retrieve sh_strtab */
	read_sh_strtab(obj, elf_header, elf_section_headers, &sh_strtab);

	/* load code and data segment */
	load_segments(obj, elf_header, elf_program_headers, &text_base);

	for (i = 0; i < elf_header->e_shnum; i++) {
		Elf64_Shdr *section = elf_section_headers + i;

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
#endif

#if 0
static int retrieve_args(int argc, char** argv, char** env) {
  log_debug("print args:");
  for (int i = 0; i < argc; ++i)
	  log_debug("  Arg %d (%p) '%s'\n", i, (void*)argv[i], argv[i]);
  return 0;
}

void f1()
{
	printf("1");
}

void f2()
{
	printf("2");
}

__attribute__((section(".preinit_array"))) static void *c1 = &f1;
__attribute__((section(".init_array"))) static void *ctr = &retrieve_args;
__attribute__((section(".fini_array"))) static void *c2 = &f2;
#endif