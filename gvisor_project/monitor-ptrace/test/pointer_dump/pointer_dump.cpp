/**
 * This program can dump a running process, and analyze the pointer usage.
 *
 * Usage: sudo ./pointer_dump PID
 *
 * By Xiaoguang Wang
 * */
#include "botutil.h"
#include <capstone/capstone.h>
#include <inttypes.h>
#include <vector>
#include <algorithm>	// std::find
#include <unordered_map>

#define BLOCK_SIGNALS 1

//#define DEBUG_DATA_POINTER

using namespace std;

/**
 * This describes BINARY info
 * From "readelf -a"
 * */
typedef struct {
	uint64_t _text_addr;		// .text for initialized global data
	uint64_t _text_size;
	uint64_t _data_addr;		// .data for initialized global data
	uint64_t _data_size;
	uint64_t _bss_addr;		// .bss for uninitialized global data
	uint64_t _bss_size;
	uint64_t _rel_dyn_addr;		// .rel.dyn for uninitialized global data
	uint64_t _rel_dyn_size;
	uint64_t _data_relro_addr;	// .data.rel.ro for uninitialized global data
	uint64_t _data_relro_size;
	uint64_t _rodata_addr;		// .rodata for uninitialized global data
	uint64_t _rodata_size;

	/* actually stack and heap info is a runtime info. */
	uint64_t _stack_addr;		// .stack for uninitialized global data. Get from runtime.
	uint64_t _stack_size;

	uint64_t _heap_addr;		// .heap for uninitialized global data. Get from runtime.
	uint64_t _heap_size;

	/* the runtime text addr, from /proc . */
	uint64_t _text_addr_runtime;
} binary_info;

binary_info binfo;

/**
 * Instruction and address pairs.
 * */
unordered_map<uint64_t, uint64_t> insn_addrs;

/**
 * Read binary information from config file (dumped by readelf)
 * */
void read_binary_info(char *elf_loc)
{
	FILE * fp;
	fp = fopen("binary.info", "r");

	printf("\n- reading binary.info\n");
	fscanf(fp, "%lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx",
		&(binfo._text_addr), &(binfo._text_size),
		&(binfo._data_addr), &(binfo._data_size),
		&(binfo._bss_addr), &(binfo._bss_size),
		&(binfo._rel_dyn_addr), &(binfo._rel_dyn_size),
		&(binfo._data_relro_addr), &(binfo._data_relro_size),
		&(binfo._rodata_addr), &(binfo._rodata_size));

	printf("  .text [0x%lx, 0x%lx],\n  .data [0x%lx, 0x%lx],\n"
           "  .bss [0x%lx, 0x%lx],\n  .rel.dyn [0x%lx, 0x%lx],\n"
           "  .data.rel.ro [0x%lx,0x%lx],\n  .rodata [0x%lx,0x%lx]\n",
		binfo._text_addr, binfo._text_size,
		binfo._data_addr, binfo._data_size,
		binfo._bss_addr, binfo._bss_size,
		binfo._rel_dyn_addr, binfo._rel_dyn_size,
		binfo._data_relro_addr, binfo._data_relro_size,
		binfo._rodata_addr, binfo._rodata_size);

	fclose(fp);
}

/**
 * Read runtime information from /proc
 * */
uint64_t read_proc(char *elf_loc, int pid)
{
	FILE * fproc;
	char buf[512];
	char flags[128];
	char proc_name[512];
	uint64_t start, end, file_offset, dev_major, dev_minor, inode;
	uint64_t ret_code_start = 0;

	sprintf(proc_name, "/proc/%d/maps", pid);
	fproc = fopen(proc_name, "r");

	printf("\n- reading /proc file: %s\n", proc_name);
	while (fgets(buf, 511, fproc) != NULL) {
	//	printf("[%3d] %s", strlen(buf), buf);
		/* Find the .text start address */
		if ( (strstr(buf, "/home/") != NULL) || (strstr(buf, elf_loc) != NULL)) {
			sscanf(buf, "%lx-%lx %31s %lx %lx:%lx %lu", &start, &end, flags, 
					&file_offset, &dev_major, &dev_minor, &inode);
			if (strcmp(flags, "r-xp") == 0) {
				ret_code_start = start;
				printf("==> Find: .text start 0x%lx, end 0x%lx ...\n", start, end);
				binfo._text_addr_runtime = start;
			}
		}

		/* Find the .stack start address */
		if (strstr(buf, "[stack]") != NULL) {
			sscanf(buf, "%lx-%lx %31s %lx %lx:%lx %lu", &start, &end, flags, 
					&file_offset, &dev_major, &dev_minor, &inode);
			printf("==> Find: .stack start 0x%lx, end 0x%lx. size 0x%lx\n", start, end, end-start);
			binfo._stack_addr = start;
			binfo._stack_size = end - start;
		}

		/* Find the .heap start address */
		if (strstr(buf, "[heap]") != NULL) {
			sscanf(buf, "%lx-%lx %31s %lx %lx:%lx %lu", &start, &end, flags, 
					&file_offset, &dev_major, &dev_minor, &inode);
			printf("==> Find: .heap start 0x%lx, end 0x%lx. size 0x%lx\n", start, end, end-start);
			binfo._heap_addr = start;
			binfo._heap_size = end - start;
		}
	}
	fclose(fproc);
	return ret_code_start;
}

/**
 * Dump memory of process pid to a buffer.
 *
 * @return:
 *   0: success,
 *   1: general failure,
 *   2: argument issue,
 *   3: attach failed, try again
 */
int ptrace_dump_memory(pid_t pid, uint64_t address, uint64_t size, char *outbuf)
{
	// asprintf is analogs to sprintf, but it allocate buffer. Need to free buffer
	char *mempath = NULL;
	verify(-1 != asprintf(&mempath, "/proc/%d/mem", pid));

	/* attach to target process */

	// block all signals, we can't blow up while waiting for the child to stop
	// or the child will freeze when it's SIGSTOP arrives and we don't clear it
#if defined(BLOCK_SIGNALS)
	sigset_t oldset;
	{
		sigset_t newset;
		verify(0 == sigfillset(&newset));
		// out of interest, we ensure the most likely signal is present
		assert(1 == sigismember(&newset, SIGINT));
		verify(0 == sigprocmask(SIG_BLOCK, &newset, &oldset));
	}
#endif

	// attach or exit with code 3
	if (0 != ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
		int errattch = errno;
		// if ptrace() gives EPERM, it might be because another process
		// is already attached, there's no guarantee it's still attached by
		// the time we check so this is a best attempt to determine who is
		if (errattch == EPERM) {
			pid_t tracer = get_tracer_pid(pid);
			if (tracer != 0) {
				fprintf(stderr, "Process %d is currently attached\n", tracer);
				return 3;
			}
		}
		error(errattch == EPERM ? 3 : 1, errattch, "ptrace(PTRACE_ATTACH)");
	}

	//verify(0 == raise(SIGINT));

	wait_until_tracee_stops(pid);

#if defined(BLOCK_SIGNALS)
	verify(0 == sigprocmask(SIG_SETMASK, &oldset, NULL));
#endif

	int memfd = open(mempath, O_RDONLY);
	assert(memfd != -1);

	// read bytes from the tracee's memory
	int size_rd = pread(memfd, outbuf, size, address);
	//printf("read from tracee's memory. size %ld should be equal to pread size %d. errno %x\n", size, size_rd, errno);
	verify(size == size_rd);

	verify(!close(memfd));
	verify(!ptrace(PTRACE_DETACH, pid, NULL, 0));
	free(mempath);

	if (size != size_rd)
		return 1;

	return 0;
}

/**
 * Disassemble the .text code buffer /w capstone.
 * */
int disasm_text(char *trans_buf, std::unordered_map<uint64_t, uint64_t> &m_insn_addrs,
		uint64_t address, uint64_t size)
{
	csh handle;
	cs_insn *insn;
	size_t count;   // number of instructions disassembled

	/* Call the capstone engine to disassemble the code into instructions. */
#ifdef __x86_64__
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
		printf("ERROR: Failed to initialize engine!\n");
		return -1;
	}
#endif
#ifdef __aarch64__
	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle)) {
		printf("ERROR: Failed to initialize engine!\n");
		return -1;
	}
#endif
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); // CS_OPT_SYNTAX_ATT represents AT&T syntax
	count = cs_disasm(handle, (unsigned char *)trans_buf, size, address, 0,
			  &insn);
	if (count) {
		size_t j;

		for (j = 0; j < count; j++) {
//			printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
			m_insn_addrs[insn[j].address] = 1;
		}
		cs_free(insn, count);
		printf("- disasm completed! insn count %ld\n", count);
	} else {
		printf("ERROR: Failed to disassemble given code!\n");
	}
	cs_close(&handle);

	return count;
}

/**
 * Get all the instruction addresses. Store them in unordered_map.
 * */
uint64_t get_insn_addrs(uint64_t base, uint64_t addr, uint64_t size,
			std::unordered_map<uint64_t, uint64_t> &m_insn_addrs,
			pid_t pid)
{
	uint64_t insn_cnt = 0;
	char *outbuf = (char *)malloc(size);
	assert(outbuf != NULL);

	printf("\n- Dumping code memory + disassembling code text...\n");
	printf("- .text size %lu\n", size);

	ptrace_dump_memory(pid, base + addr, size, outbuf);
	insn_cnt = disasm_text(outbuf, m_insn_addrs, base + addr, size);

	free(outbuf);
	return insn_cnt;
}

#define POINTER_SECTIONS	4
/**
 * Dump the pointers of .text, .data to files.
 * Pointers could be in .data, .bss and .stack
 * */
uint64_t dump_pointers_to_file(pid_t pid)
{
	FILE * fp;
	char *outbuf = NULL;
	int ret;
	uint32_t cnt = 0, i, j;     // pointers counter
	uint64_t *entry = NULL;     // 64 bit platform pointer has 64 bits
	uint64_t base, addr, size;
	uint64_t section[POINTER_SECTIONS][2];
	char *section_name[POINTER_SECTIONS] = {".data", ".bss", ".stack", ".heap"};

	base = binfo._text_addr_runtime;

	section[0][0] = binfo._data_addr + base;
	section[0][1] = binfo._data_size;
	section[1][0] = binfo._bss_addr + base;
	section[1][1] = binfo._bss_size;
	section[2][0] = binfo._stack_addr;
	section[2][1] = binfo._stack_size;
	section[3][0] = binfo._heap_addr;
	section[3][1] = binfo._heap_size;

	fp = fopen("result.info", "w");
	printf("\nchecking code pointers ... \n");
	printf(" unordered_map size %ld\n", insn_addrs.size());

	/*
	 * Finding code pointers:
	 * consider pointers are in the followeing 3 sections: .data, .bss,
	 * .stack;
	 * */
	for (i = 0; i < POINTER_SECTIONS; i++) {
		addr = section[i][0];
		size = section[i][1];
		printf("\nsection[%d] <%s>: start: 0x%lx, size 0x%lx\n",
			i, section_name[i], addr, size);

		outbuf = (char *)malloc(size);
		assert(outbuf != NULL);
		entry = (uint64_t *)outbuf;
again:
		printf("- entry %p\n", entry);
		/* Retrieve .data, .bss, .stack memory, respectively. */
		ret = ptrace_dump_memory(pid, addr, size, outbuf);
		if (ret != 0) goto end;

		/* Verify the code pointers. */
		for (j = 0; j < size/8; j++) {
			// Use unordered_map (hash table) for quick lookup.
			// Find all the code pointers; 8-bytes aligned.
			if (insn_addrs[entry[j]]) {
				cnt++;
			//	printf("entry[%d] 0x%lx. offset 0x%lx\n", j,
			//	       entry[j], entry[j] - base);
				fprintf(fp, "%lx\n", entry[j] - base);
			}
		}

//		if ((uint64_t)entry % 8 == 0) {
//		    entry = (uint64_t *)((uint64_t)entry + 4);
//		    goto again;
//		}

		free(outbuf);
	}

end:
	fclose(fp);
}

int main(int argc, char **argv)
{
	uint64_t base = 0;
	char elf_loc[512];
	char buffer[1024];
	uint32_t elf_name_len;

	if (argc < 2) {
		fprintf(stderr, "Missing arguments.... \nUse sudo ./dump-mem PID\n");
		return 2;
	}

	pid_t const pid = atoi(argv[1]);
	if (pid <= 0) {
		fprintf(stderr, "Invalid arguments\n");
		return 2;
	}

	/* "/proc/PID/exe" file is a symbolic link to the real file location.
	 *  readlink function resolves the link to the real file location. */
	sprintf(buffer, "/proc/%d/exe", pid);
	elf_name_len = readlink(buffer, elf_loc, 511);
	elf_loc[elf_name_len] = 0;
	printf("- binary location: %s. file name len %d\n", elf_loc, elf_name_len);

	/* Run the script to retrieve the binary info (.text .data location/size). */
	sprintf(buffer, "./checker.sh %s", elf_loc);
	printf("- executing the shell cmd: %s\n", buffer);
	system(buffer);

	/* Read runtime info from /proc file. */
	base = read_proc(elf_loc, pid);

	/* Read binary info from config file, dumped with the scripts. */
	read_binary_info(elf_loc);

	// This is a simple check in case the binary is not compiled as PIE (arm64 and x86_64)
	if (base == 0x400000) {
		base = binfo._text_addr_runtime = 0;
	}

	/* Retrieve code instructions from .text memory. */
	get_insn_addrs(base, binfo._text_addr, binfo._text_size, insn_addrs, pid);

	printf("\n========= checking pointers to code ... =======\n");
	dump_pointers_to_file(pid);
	printf("Done\n");

	return 0;
}
