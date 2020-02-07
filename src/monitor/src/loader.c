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

#define USAGE 		 "Use: $ BIN=<binary name> LD_PRELOAD=./libmonitor.so ./<binary> p1 p2 ..."

/** Global variables inside libmonitor.so **/
/* describe the proc info and binary info. */
proc_info_t pinfo;
binary_info_t binfo;
/* base address of the both new and old memory */
void *new_text_base = NULL;
void *old_text_base = NULL;

/* global hash table for <function name, offset> */
hash_table_t *g_ht_fun;
rev_hash_table_t *g_ht_offset;

/**
 * Entry function of the LD_PRELOAD library.
 * */
int init_loader(int argc, char** argv, char** env)
{
	/* get env file names */
	const char *bin_name = getenv("BIN");

	/* init the LOG_LEVEL env to enable logging (log_xxx printf) */
	init_env();
	log_debug("LD_PRELOAD argc 0x%x. LOG_LEVEL %s", argc, getenv("LOG_LEVEL"));

	/* check whether BIN has been set. */
	if (bin_name == NULL) {
		log_error(USAGE);
		assert(bin_name);
	}

	/* read proc, find .text base */
	read_proc(bin_name, &pinfo);

	/* read binary info from a profile file - "/tmp/dec.info" */
	read_binary_info(&binfo);

	/* duplicate the code and data (.data, .bss) VMAs */
	new_text_base = dup_proc(&pinfo, &binfo);
	old_text_base = (void *)(pinfo.code_start);
	log_info("old_text_base %p, new_text_base %p. delta %lx",
			old_text_base, new_text_base, new_text_base - old_text_base);

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

	log_debug("%s: VMA name: %s", __func__, bin_name);
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
 * Read /proc/self/maps, find out the start and end locations of a proc entry
 * @return 0 no such entry found
 * */
int read_proc_line(const char *bin_name, uint64_t *start, uint64_t *end)
{
	FILE * fproc;
	char line[512];
	char flag[8];
	uint32_t file_offset, dev_major, dev_minor, inode;

	log_debug("%s: VMA name: %s", __func__, bin_name);
	assert(bin_name != NULL);

	fproc = fopen("/proc/self/maps", "r");
	while (fgets(line, 511, fproc) != NULL) {
		sscanf(line, "%lx-%lx %31s %x %x:%x %u", start, end, flag,
				&file_offset, &dev_major, &dev_minor, &inode);
		if (strstr(line, bin_name)) return 1;
	}

	fclose(fproc);
	return 0;
}

/**
 * Read binary info from a profile file "/tmp/dec.info"
 * */
static int read_binary_info(binary_info_t *binfo)
{
	FILE *fbin = 0;
	char t, name[128];
	uint64_t offset;
	hash_table_t *entry;
	rev_hash_table_t *rv_entry;

	fbin = fopen("/tmp/dec.info", "r");

	fscanf(fbin, "%lx %lx %lx %lx %lx %lx", 
		&(binfo->code_start), &(binfo->code_size), 
		&(binfo->data_start), &(binfo->data_size),
		&(binfo->bss_start), &(binfo->bss_size));

	log_info(".text [0x%lx, 0x%lx], .data [0x%lx, 0x%lx], .bss [0x%lx, 0x%lx]", 
		binfo->code_start, binfo->code_size, 
		binfo->data_start, binfo->data_size,
		binfo->bss_start, binfo->bss_size);

	while (fscanf(fbin, "%lx %c %127s", &offset, &t, name) != EOF) {
		/* add entry to hash table */
		entry = (hash_table_t *)malloc(sizeof(hash_table_t));
		strcpy(entry->name, name);
		entry->offset = offset;
		HASH_ADD_STR(g_ht_fun, name, entry);

		/* add entry to reverse hash table. */
		rv_entry = (rev_hash_table_t *)malloc(sizeof(rev_hash_table_t));
		strcpy(rv_entry->name, name);
		rv_entry->offset = offset;
		HASH_ADD_INT(g_ht_offset, offset, rv_entry);

		//log_info("%s:\t\t0x%lx", name, offset);
	}

	fclose(fbin);

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
 * Search and update code pointers in .data and .bss from the process space.
 * */
static int update_code_pointers(proc_info_t *pinfo, binary_info_t *binfo, int64_t delta)
{
	int cnt = 0, offset;
	uint64_t code_start, code_end;
	uint64_t data_start, data_end;
	uint64_t bss_start, bss_end;
	uint64_t base, new_base, i, *p;
	rev_hash_table_t *entry = NULL;

	/* original code area */
	base = pinfo->code_start;
	code_start = base + binfo->code_start;
	code_end = code_start + binfo->code_size;

	/* new data area */
	new_base = pinfo->code_start + delta;
	data_start = new_base + binfo->data_start;
	data_end = data_start + binfo->data_size;
	bss_start = new_base + binfo->bss_start;
	bss_end = bss_start + binfo->bss_size;

	log_info("runtime code: [0x%lx,0x%lx]\n\t\t\t\tdata: [0x%lx,0x%lx]"
			"\n\t\t\t\t bss: [0x%lx,0x%lx]",
			code_start, code_end, data_start, data_end, bss_start, bss_end);

	/* search code pointers in .data, .bss and heap */
	for (i = data_start; i <= data_end-8; i+=8) {
		p = (uint64_t *)i;
		offset = (int)(*p - base);
		HASH_FIND_INT(g_ht_offset, &offset, entry);
		if (entry != NULL) {
			*p += delta;
			log_debug("update %p @offset 0x%lx. new loc %p (.data) [%s]",
					p, offset, *p, entry->name);
			cnt++;
		}
	}

	for (i = bss_start; i <= bss_end-8; i+=8) {
		p = (uint64_t *)i;
		offset = (int)(*p - base);
		HASH_FIND_INT(g_ht_offset, &offset, entry);
		if (entry != NULL) {
			*p += delta;
			log_debug("update %p @offset 0x%lx. new loc %p (.bss) [%s]",
					p, offset, *p, entry->name);
			cnt++;
		}
	}

	return cnt;
}

/**
 * Search and update pointers in new .data and .bss pointing to old .data or
 * .bss  from the process space.
 * This is to account for the case where a .data/.bss struct in memory has a
 * pointer to old .data/.bss which has a code pointer in it (nginx has such occurrences).
 **/
static int update_data_pointers(proc_info_t *pinfo, binary_info_t *binfo, int64_t delta)
{
	int cnt = 0, offset;
	uint64_t data_start, match_end;
	uint64_t new_data_start, scan_end;
	uint64_t base, new_base, i, *p;

	if (!pinfo || !binfo) {
		log_error("pinfo or binfo cannot be null!");
		abort();
	}

	/* pinfo->code_start should be equivalent to old_text_base */
	base = pinfo->code_start;
	data_start = base + binfo->data_start;
	match_end = base + binfo->bss_start + binfo->bss_size;

	/* new data area */
	new_base = pinfo->code_start + delta;
	new_data_start = new_base + binfo->data_start;
	scan_end = new_base + binfo->bss_start + binfo->bss_size;

	/* search code pointers in .data and .bss */
	for (i = new_data_start; i <= scan_end-8; i+=8) {
		p = (uint64_t *)i;
		if (*p >= data_start && *p <= match_end - 8) {
			*p += delta;
			log_debug("update data pointer %p. original loc %p, new"
				  " loc %p (.data + .bss)",
					(void*)i, *(uint64_t *)i, *p);
			cnt++;
		}
	}

	return cnt;
}

/**
 * Search and update code pointers on heap.
 * */
static int update_heap_code_pointers(uint64_t base, int64_t delta)
{
	int cnt = 0, offset;
	uint64_t heap_start, heap_end;
	uint64_t i, *p;
	rev_hash_table_t *entry = NULL;

	read_proc_line("[heap]", &heap_start, &heap_end);
	log_debug("%s: heap [0x%lx,0x%lx]. size 0x%lx", __func__,
			heap_start, heap_end, heap_end - heap_start);

	for (i = heap_start; i <= heap_end-8; i+=8) {
		p = (uint64_t *)i;
		offset = (int)(*p - base);
		HASH_FIND_INT(g_ht_offset, &offset, entry);
		if (entry != NULL) {
			*p += delta;
			log_debug("update %p @offset 0x%lx. new loc %p (.heap) [%s]",
					p, offset, *p, entry->name);
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
	uint64_t offset = new_text_base - old_text_base;
	int code_pointer_cnt, data_pointer_cnt;
	code_pointer_cnt = update_code_pointers(&pinfo, &binfo, new_text_base - old_text_base);
	log_info("%s: # of code pointers %d", __func__, code_pointer_cnt);
	data_pointer_cnt = update_data_pointers(&pinfo, &binfo, new_text_base - old_text_base);
	log_info("%s: # of old data pointers on *data+bss* %d", __func__,
		 data_pointer_cnt);
}

/**
 * Search the code and data pointers in heap from the process space.
 * */
void update_heap_pointers_self()
{
	int pointer_cnt = update_heap_code_pointers(pinfo.code_start, new_text_base - old_text_base);
	log_info("%s: # of code pointers on *heap* %d", __func__, pointer_cnt);
}

/**
 * TODO: we want to convert the VMA permission in lmvx_start()
 * */
void update_vma_permission()
{
	uint64_t start, end, len;
	start = pinfo.code_start;
	end = pinfo.code_end;
	len = end - start;
	mprotect((void *)start, len, PROT_READ);
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
