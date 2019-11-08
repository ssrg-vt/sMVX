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

#define WARN_CONF	 "No bin file specified."
#define WARN_BIN	 "No conf file specified."
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
	const char *bin_name = getenv("BIN");

	// init the env to enable logging (log_xxx printf)
	printf("argc 0x%x. %s\n", argc, getenv("LOG_LEVEL"));
	init_env();

	if (conf_filename == NULL) {
		log_error(WARN_CONF);
		log_error(USAGE);
		exit(EXIT_FAILURE);
	}
	if (bin_name == NULL) {
		log_error(WARN_BIN);
		log_error(USAGE);
		exit(EXIT_FAILURE);
	}
	log_info("LD_PRELOAD Binary: %s. CONF: %s.",
			bin_name, conf_filename);

	// load conf file
	if (init_conf(conf_filename, g_func)) {
		log_error("Failed to load conf file.");
		exit(EXIT_FAILURE);
	}

	// read proc, find .text base
	read_proc(bin_name, &pinfo);

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

