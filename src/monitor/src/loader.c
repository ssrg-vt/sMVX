/**
 * A simple ELF loader that loads a duplicated .text into memory.
 *
 * Usage:
 *   $ BIN=<binary-variant> $PATCH_LIBS=<non libc/lmvx shared lib names, comma separated> CONF=conf/<func.conf> LD_PRELOAD=./loader.so ./<binary-vanilla> param1 param2 ...
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

#define USAGE 		 "Use: $ BIN=<binary name> $PATCH_LIBS=<non libc/lmvx \
			shared lib names, comma separated> LD_PRELOAD=./libmonitor.so ./<binary> p1 p2 ..."
#define STACK_SIZE		 (4096)
#define MAX_GOTPLT_SLOTS (1024)
#define GOTPLT_PREAMBLE_SIZE	 (24) /* Size of area before actual gotplt slots
				      starts in bytes */
#define PLT_PREAMBLE_SIZE        (16)
#define PLT_SLOT_SIZE		 (16)
/** Global variables inside libmonitor.so **/
/* describe the proc info and binary info. */
proc_info_t pinfo;
binary_info_t binfo;
/* base address of the both new and old memory */
void *new_text_base = NULL;
void *old_text_base = NULL;

extern void mpk_trampoline();

/* global hash table for <function name, offset> */
hash_table_t *g_ht_fun;
rev_hash_table_t *g_ht_offset;

/* Array to store the gotplt entry addresses */
uint64_t gotplt_address[MAX_GOTPLT_SLOTS];
uint64_t num_gotplt_slots;

__thread uint8_t tls_safestack[STACK_SIZE];
__thread void* tls_unsafestack;

/**
 * Entry function of the LD_PRELOAD library.
 * */
int init_loader(int argc, char** argv, char** env)
{
	/* get env file names */
	const char *bin_name = getenv("BIN");

	/* init the LOG_LEVEL env to enable logging (log_xxx printf) */
	init_env();
	log_debug("[LOADER]: LD_PRELOAD argc 0x%x. LOG_LEVEL %s", argc, getenv("LOG_LEVEL"));

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

	/* Get the gotplt pointers */
	read_gotplt();

	/* Patch the plt with absolute jumps since musl doesn't support lazy
	 * binding*/
	patch_binary_plt(&binfo, &pinfo);

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

	log_debug("[LOADER]: %s: VMA name: %s", __func__, bin_name);
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

	log_debug("[LOADER]: %s: VMA name: %s", __func__, bin_name);
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

	fscanf(fbin, "%lx %lx %lx %lx %lx %lx %lx %lx %lx %lx",
		&(binfo->code_start), &(binfo->code_size),
		&(binfo->data_start), &(binfo->data_size),
		&(binfo->bss_start), &(binfo->bss_size),
		&(binfo->plt_start), &(binfo->plt_size),
		&(binfo->gotplt_start), &(binfo->gotplt_size));

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
	log_debug("[LOADER]: code sz 0x%lx, rodata sz 0x%lx, data sz 0x%lx, total sz 0x%lx",
			code_sz, rodata_sz, data_sz, total_sz);

	// allocate memory
	mem = mmap(NULL, total_sz, PROT_WRITE|PROT_READ|PROT_EXEC,
					MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (mem == MAP_FAILED) {
		log_error("mmap failed %d: %s", errno, strerror(errno));
		return mem;
	}
	log_debug("[LOADER]: new mem %p, total sz 0x%lx", mem, total_sz);

	// code memory content
	memcpy(mem, (void *)(pinfo->code_start), code_sz);
	memcpy(mem + rodata_off, (void *)(pinfo->rodata_start), rodata_sz);
	memcpy(mem + data_off, (void *)(pinfo->data_start), data_sz);

	// unmap any memory gaps in those 3 mem segments
	if (pinfo->rodata_start - pinfo->code_end > 0) {
		munmap(mem + code_sz, pinfo->rodata_start - pinfo->code_end);
		log_debug("[LOADER]: gap after code end. unmap size %lx",
				pinfo->rodata_start - pinfo->code_end);
	}
	if (pinfo->data_start - pinfo->rodata_end > 0) {
		munmap(mem + pinfo->rodata_end - pinfo->code_start,
				pinfo->data_start - pinfo->rodata_end);
		log_debug("[LOADER]: gap after rodata end. unmap size %lx",
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
			log_debug("[LOADER]: update %p @offset 0x%lx. new loc %p (.data) [%s]",
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
			log_debug("[LOADER]: update %p @offset 0x%lx. new loc %p (.bss) [%s]",
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
			log_debug("[LOADER]: update data pointer %p. original loc %p, new"
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
	log_debug("[LOADER]: %s: heap [0x%lx,0x%lx]. size 0x%lx", __func__,
			heap_start, heap_end, heap_end - heap_start);

	for (i = heap_start; i <= heap_end-8; i+=8) {
		p = (uint64_t *)i;
		offset = (int)(*p - base);
		HASH_FIND_INT(g_ht_offset, &offset, entry);
		if (entry != NULL) {
			*p += delta;
			log_debug("[LOADER]: update %p @offset 0x%lx. new loc %p (.heap) [%s]",
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

void read_gotplt()
{
	uint64_t gotplt_start, gotplt_end;
	uint64_t text_base, i;
	uint64_t *p;
	text_base = pinfo.code_start;
	gotplt_start = text_base + binfo.gotplt_start;
	gotplt_end = gotplt_start + binfo.gotplt_size;

	/* Add the preamble size to get to the slots */
	gotplt_start += GOTPLT_PREAMBLE_SIZE;

	log_debug("[LOADER]: GOTPLT SLOT ADDRESS POINTERS ----------");
	for (i = gotplt_start, num_gotplt_slots = 0; i <= gotplt_end-8; i+=8,
	     ++num_gotplt_slots) {
		p = (uint64_t *)i;
		if (num_gotplt_slots >= MAX_GOTPLT_SLOTS){
			log_error("[LOADER]: Max number of gotplt slots in our"
				  " memory overshot, increase number");
			assert(0);
		}
		gotplt_address[num_gotplt_slots] = *p;
		log_debug("[LOADER]: %p, slot number: %lu", *p, num_gotplt_slots);
	}

}

//void patch_plt()
//{
//	uint64_t plt_start, plt_end;
//	uint64_t text_base, i, j;
//	jump_patch_t *p;
//	text_base = pinfo.code_start;
//	plt_start = text_base + binfo.plt_start;
//	plt_end = plt_start + binfo.plt_size;
//	/* patch_data is a packed struct, with instructions:
//	 *
//	 *  movabs 0xXXXXXXXXXXXX, $rax
//	 *  jmpq $rax
//	 *  nop
//	 *  nop
//	 *  nop
//	 *  nop
//	 *  // opcode+values for the instructions is
//	 *  0xxxxxxxxxxxxxb848
//	 *  0x90909090e0ff0000
//	 */
//	jump_patch_t patch_data = {0x48, 0xb8, 0x0, 0xff, 0xe0, 0x90, 0x90, 0x90,
//	0x90};
//
//	/* Disable protections for writing */
//	mprotect((void*)plt_start, binfo.plt_size, PROT_READ | PROT_WRITE);
//
//	/* Add the preamble size to get to the slots */
//	plt_start += PLT_PREAMBLE_SIZE;
//	for (i = plt_start, j = 0; i <= plt_end-PLT_SLOT_SIZE; i+=PLT_SLOT_SIZE,
//	     ++j) {
//		p = (jump_patch_t*)i;
//		if (j > num_gotplt_slots){
//			log_error("[LOADER]: Plt has more slots than we have"
//				  " gotplt entries!");
//			assert(0);
//		}
//		patch_data.address = gotplt_address[j];
//		*p = patch_data;
//	}
//
//	/* Set .plt to only executable state for .text segment */
//	mprotect((void*)(plt_start-PLT_PREAMBLE_SIZE), binfo.plt_size, PROT_EXEC);
//}

static void patch_binary_plt(const binary_info_t *bin_info, const proc_info_t* process_info)
{
	uint64_t plt_start, plt_end;
	uint64_t text_base, i;
	uint8_t j;
	jump_patch_t *p;
	jump_patch_general_t *pg;
	text_base = process_info->code_start;
	plt_start = text_base + bin_info->plt_start;
	plt_end = plt_start + bin_info->plt_size;
	/* general_patch_data and patch_data are packed structs:
	 *  Instructions in general_patch_data:
	 *  movabs 0xXXXXXXXXXXXX, $rax
	 *  jmpq $rax
	 *  nop
	 *  nop
	 *  nop
	 *  nop
	 *  // opcode+values for the instructions is
	 *  0xxxxxxxxxxxxxb848
	 *  0x90909090e0ff0000
	 *  Instructions in patch_data:
	 *  push $rbx
	 *  push $rax
	 *  nop
	 *  nop
	 *  nop
	 *  nop
	 *  The next two instructions are not in patch_data, as we reuse
	 *  existing instructions already in the .plt slots:
	 *  push slot_number
	 *  jmp plt_resolver_addr (first slot of plt, patched with
	 *  general_patch_data)
	 */
	jump_patch_general_t general_patch_data = {0x48, 0xb8, 0x0, 0xff, 0xe0,
	0x90, 0x90, 0x90, 0x90};
	jump_patch_t patch_data = {0x53, 0x50, 0x90, 0x90, 0x90, 0x90};

	/* Disable protections for writing */
	mprotect((void*)plt_start, bin_info->plt_size, PROT_READ | PROT_WRITE);

	/* Write the common slot first, this is usually used for lazy binding
	 * but musl doesn't support it. This means we can take advantage of this
	 * space and the existing plt instructions that redirects here.*/
	pg = (jump_patch_general_t*)plt_start;
	general_patch_data.address = (uint64_t)mpk_trampoline;
	*pg = general_patch_data;

	/* Individual PLT slot patches */
	plt_start += PLT_PREAMBLE_SIZE;
	for (i = plt_start, j = 0; i <= plt_end-PLT_SLOT_SIZE; i+=PLT_SLOT_SIZE,
	     ++j) {
		p = (jump_patch_t*)i;
		if (j > num_gotplt_slots){
			log_error("[LOADER]: Plt has more slots than we have"
				  " gotplt entries!");
			assert(0);
		}

		*p = patch_data;
	}

	/* Set .plt to only executable state for .text segment */
	mprotect((void*)(plt_start-PLT_PREAMBLE_SIZE), bin_info->plt_size, PROT_EXEC);
}


/**
 * @brief Iterate through libraries and patch all .plt entries assumes we are
 * using mpk_trampoline.
 */
void patch_library_plt()
{
	FILE *fbin = 0;
	binary_info_t lib_binfo;
	proc_info_t lib_pinfo;
	char* strtok_saveptr, *libtoken;
	char* library_names = getenv("PATCH_LIBS");
	char libinfo_path[100];

	strtok_saveptr = library_names;
	/* Go through individual library names, comma delimited in LIBS */
	for (libtoken = strtok_r(strtok_saveptr, ",", &strtok_saveptr);
	     libtoken != NULL;
	     libtoken = strtok_r(strtok_saveptr, ",",
						    &strtok_saveptr)) {
		read_proc(libtoken, &lib_pinfo);

		sprintf(libinfo_path, "/tmp/%s.info", libtoken);
		log_info("Lib tempfile path: %s", libinfo_path);
		fbin = fopen(libinfo_path, "r");

		assert(fbin && "Invalid temp lib file path. Did you run checker.sh?");

		fscanf(fbin, "%lx %lx %lx %lx %lx %lx %lx %lx %lx %lx",
			&(lib_binfo.code_start), &(lib_binfo.code_size),
			&(lib_binfo.data_start), &(lib_binfo.data_size),
			&(lib_binfo.bss_start), &(lib_binfo.bss_size),
			&(lib_binfo.plt_start), &(lib_binfo.plt_size),
			&(lib_binfo.gotplt_start), &(lib_binfo.gotplt_size));

		log_info(".text [0x%lx, 0x%lx], .data [0x%lx, 0x%lx], .bss [0x%lx, 0x%lx]",
			lib_binfo.code_start, lib_binfo.code_size,
			lib_binfo.data_start, lib_binfo.data_size,
			lib_binfo.bss_start, lib_binfo.bss_size);

		patch_binary_plt(&lib_binfo, &lib_pinfo);
		}
}
