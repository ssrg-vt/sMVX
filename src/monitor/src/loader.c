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

//#include "../inc/lmvx.h"
#include <log.h>
#include <env.h>
#include <loader.h>

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

#define CONF_TAB_ADDR_FILE		"conf/tab_addr.conf"

#define WARN_CONF	 "No bin file specified."
#define WARN_BIN	 "No conf file specified."
#define USAGE 		 "Use: $ CONF=<func.conf> LD_PRELOAD=./loader.so ./<binary-vanilla> p1 p2 ..."

#define TAB_SIZE	16
/* num of func_desc_t, and the array of func_desc_t */
int g_func_num = 0;
func_desc_t g_func[TAB_SIZE];

/* describe the proc info */
static proc_info_t pinfo;

/* base address of the newly allocated code */
static void *new_text_base = NULL;

/**
 * Entry function of the LD_PRELOAD library.
 * */
int init_loader()
{
	// get env file names
	const char *conf_filename = getenv("CONF");
	const char *bin_name = getenv("BIN");

	// init the env to enable logging (log_xxx printf)
	//printf("argc 0x%x. %s\n", argc, getenv("LOG_LEVEL"));
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

/**
 * Temporarily store the func_desc_t array in a file.
 * */
void gen_conf(func_desc_t *func, void *base, const char *CONF_TBL_ADDR)
{
	FILE *conf_tbl = fopen(CONF_TBL_ADDR, "w");	// conf file of ind_tbl address

	fprintf(conf_tbl, "%p %p", func, base);
	fclose(conf_tbl);
}

/**
 * Read /proc/self/maps, find out the code/data locations
 * */
int read_proc(const char *bin_name, proc_info_t *pinfo)
{
	FILE * fproc;
	char line[512];
	char flag[8];
	uint64_t start, end;
	uint32_t file_offset, dev_major, dev_minor, inode;

	log_debug("bin: %s", bin_name);
	assert(bin_name != NULL);

	fproc = fopen("/proc/self/maps", "r");
	while (fgets(line, 511, fproc) != NULL) {
		sscanf(line, "%lx-%lx %31s %x %x:%x %u", &start, &end, flag, 
				&file_offset, &dev_major, &dev_minor, &inode);
		if (strstr(line, bin_name)) {
			if (!strcmp(flag, "r-xp")) {
				pinfo->code_start = start;
				pinfo->code_end = end;
			}
			if (!strcmp(flag, "r--p")) {
				pinfo->rodata_start = start;
				pinfo->rodata_end = end;
			}
			if (!strcmp(flag, "rw-p")) {
				pinfo->data_start = start;
				pinfo->data_end = end;
			}
		}
	}
	fclose(fproc);

	return 0;
}

/**
 * Duplicate the proc mem (code,rodata,data)
 * */
void *dup_proc(proc_info_t *pinfo)
{
	void *mem = NULL;
	// code, rodata, data segment size
	uint64_t code_sz, rodata_sz, data_sz;
	uint64_t total_sz = pinfo->data_end - pinfo->code_start;
	// .rodata offset, .data offset
	uint64_t rodata_off, data_off;

	// calculate size and offset
	code_sz = pinfo->code_end - pinfo->code_start;
	rodata_sz = pinfo->rodata_end - pinfo->rodata_start;
	data_sz = pinfo->data_end - pinfo->data_start;

	rodata_off = pinfo->rodata_start - pinfo->code_start;
	data_off = pinfo->data_start - pinfo->code_start;

	assert(total_sz > 0);
	if (code_sz+rodata_sz+data_sz != total_sz) {
		log_warn("mem space has gap");
	}
	log_debug("code sz 0x%lx, rodata sz 0x%lx, total sz 0x%lx",
			code_sz, rodata_sz, total_sz);

	// allocate memory
	mem = mmap(NULL, total_sz, PROT_WRITE|PROT_READ|PROT_EXEC,
					MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (mem == MAP_FAILED) {
		log_error("mmap failed %d: %s", errno, strerror(errno));
		return mem;
	}
	log_debug("new mem %p, total sz 0x%lx", mem, total_sz);

	// code memory content
	memcpy(mem, (void *)(pinfo->code_start), code_sz);
	memcpy(mem + rodata_off, (void *)(pinfo->rodata_start), rodata_sz);
	memcpy(mem + data_off, (void *)(pinfo->data_start), data_sz);

	// unmap any memory gaps in those 3 mem segments
	if (pinfo->rodata_start - pinfo->code_end > 0) {
		munmap(mem + code_sz, pinfo->rodata_start - pinfo->code_end);
		log_debug("gap after code end. unmap size %lx",
				pinfo->rodata_start - pinfo->code_end);
	}
	if (pinfo->data_start - pinfo->rodata_end > 0) {
		munmap(mem + pinfo->rodata_end - pinfo->code_start,
				pinfo->data_start - pinfo->rodata_end);
		log_debug("gap after rodata end. unmap size %lx",
				pinfo->data_start - pinfo->rodata_end);
	}

	return mem;
}

/**
 * Rewrite the first several instructions.
 * */
int rewrite_insn(proc_info_t *pinfo, func_desc_t *func)
{
	int i;
	//uint64_t code_sz = pinfo->code_end - pinfo->code_start;
	uint64_t *p = NULL;

	for (i = 0; i < g_func_num; i++) {
		p = (uint64_t *)(pinfo->code_start + (func+i)->offset);
		log_debug("offset 0x%x: insn code in hex %lx", (func+i)->offset, *p);
	}

	return 0;
}

