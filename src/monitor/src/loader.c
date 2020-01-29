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

#include <log.h>
#include <env.h>
#include <loader.h>

#define WARN_CONF	 "No CONF file specified."
#define WARN_BIN	 "No BIN file specified."
#define USAGE 		 "Use: $ BIN=<binary> CONF=<func.conf> LD_PRELOAD=./libmonitor.so ./<binary> p1 p2 ..."

#define TAB_SIZE	16
/** Global variables inside libmonitor.so **/
/* num of func_desc_t, and the array of func_desc_t */
int g_func_num = 0;
func_desc_t g_func[TAB_SIZE];
/* describe the proc info and binary info. */
proc_info_t pinfo;
binary_info_t binfo;
/* base address of the newly allocated code */
void *new_text_base = NULL;
void *old_text_base = NULL;

/**
 * Entry function of the LD_PRELOAD library.
 * */
int init_loader(int argc, char** argv, char** env)
{
	/* get env file names */
	const char *conf_filename = getenv("CONF");
	const char *bin_name = getenv("BIN");

	/* init the LOG_LEVEL env to enable logging (log_xxx printf) */
	init_env();
	log_debug("LD_PRELOAD argc 0x%x. LOG_LEVEL %s", argc, getenv("LOG_LEVEL"));

	/* check whether CONF and BIN have been set. */
	if (check_env(conf_filename, bin_name))
		exit(EXIT_FAILURE);

	/* load conf file */
	if (init_conf(conf_filename, g_func)) {
		log_error("Failed to load conf file.");
		exit(EXIT_FAILURE);
	}

	/* read proc, find .text base */
	read_proc(bin_name, &pinfo);

	/* read binary info from a profile file - "/tmp/dec.info" */
	read_binary_info(&binfo);

	/* duplicate the code and data (.data, .bss) VMAs */
	new_text_base = dup_proc(&pinfo, &binfo);
	old_text_base = (void *)(pinfo.code_start);
	log_info("g_func %p, old_text_base %p, new_text_base %p. delta %lx", g_func,
			old_text_base, new_text_base, new_text_base - old_text_base);

	return 0;
}

/**
 * Check whether the environment of CONF and BIN have been set.
 * */
static int check_env(const char *conf_filename, const char *bin_name)
{
	if (conf_filename == NULL) {
		log_error(WARN_CONF);
		log_error(USAGE);
		return 1;
	}
	if (bin_name == NULL) {
		log_error(WARN_BIN);
		log_error(USAGE);
		return 1;
	}
	log_info("BIN: %s. CONF: %s.", bin_name, conf_filename);

	return 0;
}

/**
 * Loading the config files (a list of sensitive functions <name,offset>)
 *   into an in-memory func_desc_t array.
 * Log the in-memory array address.
 * */
static int init_conf(const char *conf_filename, func_desc_t *func)
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
 * Read /proc/self/maps, find out the code/data locations
 * */
int read_proc(const char *bin_name, proc_info_t *pinfo)
{
	FILE * fproc;
	char line[512];
	char flag[8];
	uint64_t start, end;
	uint32_t file_offset, dev_major, dev_minor, inode;

	log_debug("VMA name: %s", bin_name);
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
 * Read binary info from a profile file "binary.info"
 * */
static int read_binary_info(binary_info_t *binfo)
{
	FILE *fbin = 0;

	fbin = fopen("/tmp/dec.info", "r");

	fscanf(fbin, "%lx %lx %lx %lx %lx %lx", 
		&(binfo->code_start), &(binfo->code_size), 
		&(binfo->data_start), &(binfo->data_size),
		&(binfo->bss_start), &(binfo->bss_size));

	fclose(fbin);

	log_info(".text [0x%lx, 0x%lx], .data [0x%lx, 0x%lx], .bss [0x%lx, 0x%lx]", 
		binfo->code_start, binfo->code_size, 
		binfo->data_start, binfo->data_size,
		binfo->bss_start, binfo->bss_size);

	return 0;
}

/**
 * Duplicate the proc mem (code,rodata,data)
 * */
static void *dup_proc(proc_info_t *pinfo, binary_info_t *binfo)
{
	void *mem = NULL;
	// code, rodata, data segment size
	uint64_t code_sz, rodata_sz, data_sz;
	// .bss is not in rw vma (data); only consider PIE code
	uint64_t total_sz = ROUNDUP(binfo->bss_start + binfo->bss_size, 4096);
	// .rodata offset, .data offset
	uint64_t rodata_off, data_off;

	// calculate size and offset
	code_sz = pinfo->code_end - pinfo->code_start;
	rodata_sz = pinfo->rodata_end - pinfo->rodata_start;
	data_sz = total_sz - (pinfo->data_start - pinfo->code_start);

	rodata_off = pinfo->rodata_start - pinfo->code_start;
	data_off = pinfo->data_start - pinfo->code_start;

	assert(total_sz > 0);
	if (code_sz+rodata_sz+data_sz != total_sz) {
		log_warn("mem space has gap");
	}
	log_debug("code sz 0x%lx, rodata sz 0x%lx, data sz 0x%lx, total sz 0x%lx",
			code_sz, rodata_sz, data_sz, total_sz);

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
 * Search code pointers from process space.
 * */
static int update_code_pointers(proc_info_t *pinfo, binary_info_t *binfo, int64_t delta)
{
	int cnt = 0;
	uint64_t code_start, code_end;
	uint64_t data_start, data_end;
	uint64_t bss_start, bss_end;
	uint64_t base, i, *p;

	/* runtime information is from base (/proc/<pid>/maps) + binary info */
	base = pinfo->code_start;
	code_start = base + binfo->code_start;
	code_end = code_start + binfo->code_size;
	data_start = base + binfo->data_start;
	data_end = data_start + binfo->data_size;
	bss_start = base + binfo->bss_start;
	bss_end = bss_start + binfo->bss_size;
	log_info("runtime code: [0x%lx,0x%lx]\n\t\t\t\tdata: [0x%lx,0x%lx]\n\t\t\t\t bss: [0x%lx,0x%lx]",
			code_start, code_end, data_start, data_end, bss_start, bss_end);

	/* search code pointers in .data and .bss */
	for (i = data_start; i <= data_end-8; i+=8) {
		p = (uint64_t *)i;
		if (*p >= code_start && *p <= code_end) {
			log_info("code pointer @ %p -> 0x%lx, offset 0x%lx (.data)", p, *p, (*p - code_start));
			*p += delta;
			cnt++;
		}
	}

	for (i = bss_start; i <= bss_end-8; i+=8) {
		p = (uint64_t *)i;
		if (*p >= code_start && *p <= code_end) {
			log_info("code pointer @ %p -> 0x%lx, offset 0x%lx (.bss)", p, *p, (*p - code_start));
			*p += delta;
			cnt++;
		}
	}

	return cnt;
}

/**
 * Search code and data pointers from process space.
 * */
void update_pointers_self()
{
	int pointer_cnt = update_code_pointers(&pinfo, &binfo, new_text_base - old_text_base);
	log_info("%s: # of code pointers %d", __func__, pointer_cnt);
}

/**
 * Rewrite the first several instructions.
 * */
#if 0
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
#endif

/**
 * Copy over the data bss
 * */
void copy_data_bss()
{
	if (!new_text_base || !old_text_base
	    || !binfo.bss_start || !binfo.bss_size) {
		log_error("Lacking information, copy_bss called in wrong order");
		assert(0);
	}

	/* Check that areas do not overlap */
	if ((old_text_base + binfo.bss_size) > new_text_base){
		log_error("Overlapping memory ranges in copy_bss before memcpy");
		assert(0);
	}

	memcpy(new_text_base + binfo.bss_start, old_text_base +
	       binfo.bss_start, binfo.bss_size);
	memcpy(new_text_base + binfo.data_start, old_text_base +
	       binfo.data_start, binfo.data_size);
}
