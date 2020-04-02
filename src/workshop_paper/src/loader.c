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
#include <libmonitor.h>

#define USAGE 		 "Use: $ BIN=<binary name> LD_PRELOAD=./libmonitor.so ./<binary> p1 p2 ..."
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
void *old_text_base = NULL;

extern void mpk_trampoline();

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
	const char *bin_name = real_getenv("BIN");

	/* init the LOG_LEVEL env to enable logging (log_xxx printf) */
	init_env();
	log_debug("[LOADER]: LD_PRELOAD argc 0x%x. LOG_LEVEL %s", argc, real_getenv("LOG_LEVEL"));

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
	old_text_base = (void *)(pinfo.code_start);

	/* Get the gotplt pointers */
	read_gotplt();

	/* Patch the plt with absolute jumps since musl doesn't support lazy
	 * binding*/
	patch_plt();

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

	fproc = real_fopen("/proc/self/maps", "r");
	while (real_fgets(line, 511, fproc) != NULL) {
		real_sscanf(line, "%lx-%lx %31s %x %x:%x %u", &start, &end, flag, 
				&file_offset, &dev_major, &dev_minor, &inode);
		if (real_strstr(line, bin_name)) {
			if (!real_strcmp(flag, "r-xp")) {
				pinfo->code_start = start;
				pinfo->code_end = end;
			}
			if (!real_strcmp(flag, "r--p")) {
				pinfo->rodata_start = start;
				pinfo->rodata_end = end;
			}
			if (!real_strcmp(flag, "rw-p")) {
				pinfo->data_start = start;
				pinfo->data_end = end;
			}
		}
	}
	real_fclose(fproc);

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

	fproc = real_fopen("/proc/self/maps", "r");
	while (real_fgets(line, 511, fproc) != NULL) {
		real_sscanf(line, "%lx-%lx %31s %x %x:%x %u", start, end, flag,
				&file_offset, &dev_major, &dev_minor, &inode);
		if (real_strstr(line, bin_name)) return 1;
	}

	real_fclose(fproc);
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
	fbin = real_fopen("/tmp/dec.info", "r");
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

	real_fclose(fbin);

	return 0;
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

void patch_plt()
{
	uint64_t plt_start, plt_end;
	uint64_t text_base, i;
	uint8_t j;
	jump_patch_t *p;
	jump_patch_general_t *pg;
	text_base = pinfo.code_start;
	plt_start = text_base + binfo.plt_start;
	plt_end = plt_start + binfo.plt_size;
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
	mprotect((void*)plt_start, binfo.plt_size, PROT_READ | PROT_WRITE);

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
	mprotect((void*)(plt_start-PLT_PREAMBLE_SIZE), binfo.plt_size, PROT_EXEC);
}
