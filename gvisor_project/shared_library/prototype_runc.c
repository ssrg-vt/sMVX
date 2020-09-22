/* Prototype code: 
   AEGIS Container
   Authors: Abhijit Mahurkar, Dr. Xiaoguang Wang
   GCC commnad to build shared object: 
   gcc -Wall -o ~/foo.so -Wl,--whole-archive ~/libcapstone.a -Wl,--no-whole-archive -shared -fPIC ~/foo.c -ldl
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <capstone/platform.h>
#include <capstone/capstone.h>
#include "elf_loader.h"
#include "wheelc/wheelc.h"
#include <errno.h>
#include <unistd.h>

/* capstone handle */ 
static csh handle;

/* capstone platform struct */
struct platform {
        cs_arch arch;
        cs_mode mode;
        unsigned char *code;
        size_t size;
        const char *comment;
        cs_opt_type opt_type;
        cs_opt_value opt_value;
};

typedef struct {
	uint64_t code_start;
	uint64_t code_end;
	uint64_t rodata_start;
	uint64_t rodata_end;
	uint64_t data_start;
	uint64_t data_end;
} proc_info_t;


/* Utility function to print binary data */
static void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

static const char *get_eflag_name(uint64_t flag)
{
	switch(flag) {
		default:
			return NULL;
		case X86_EFLAGS_UNDEFINED_OF:
			return "UNDEF_OF";
		case X86_EFLAGS_UNDEFINED_SF:
			return "UNDEF_SF";
		case X86_EFLAGS_UNDEFINED_ZF:
			return "UNDEF_ZF";
		case X86_EFLAGS_MODIFY_AF:
			return "MOD_AF";
		case X86_EFLAGS_UNDEFINED_PF:
			return "UNDEF_PF";
		case X86_EFLAGS_MODIFY_CF:
			return "MOD_CF";
		case X86_EFLAGS_MODIFY_SF:
			return "MOD_SF";
		case X86_EFLAGS_MODIFY_ZF:
			return "MOD_ZF";
		case X86_EFLAGS_UNDEFINED_AF:
			return "UNDEF_AF";
		case X86_EFLAGS_MODIFY_PF:
			return "MOD_PF";
		case X86_EFLAGS_UNDEFINED_CF:
			return "UNDEF_CF";
		case X86_EFLAGS_MODIFY_OF:
			return "MOD_OF";
		case X86_EFLAGS_RESET_OF:
			return "RESET_OF";
		case X86_EFLAGS_RESET_CF:
			return "RESET_CF";
		case X86_EFLAGS_RESET_DF:
			return "RESET_DF";
		case X86_EFLAGS_RESET_IF:
			return "RESET_IF";
		case X86_EFLAGS_TEST_OF:
			return "TEST_OF";
		case X86_EFLAGS_TEST_SF:
			return "TEST_SF";
		case X86_EFLAGS_TEST_ZF:
			return "TEST_ZF";
		case X86_EFLAGS_TEST_PF:
			return "TEST_PF";
		case X86_EFLAGS_TEST_CF:
			return "TEST_CF";
		case X86_EFLAGS_RESET_SF:
			return "RESET_SF";
		case X86_EFLAGS_RESET_AF:
			return "RESET_AF";
		case X86_EFLAGS_RESET_TF:
			return "RESET_TF";
		case X86_EFLAGS_RESET_NT:
			return "RESET_NT";
		case X86_EFLAGS_PRIOR_OF:
			return "PRIOR_OF";
		case X86_EFLAGS_PRIOR_SF:
			return "PRIOR_SF";
		case X86_EFLAGS_PRIOR_ZF:
			return "PRIOR_ZF";
		case X86_EFLAGS_PRIOR_AF:
			return "PRIOR_AF";
		case X86_EFLAGS_PRIOR_PF:
			return "PRIOR_PF";
		case X86_EFLAGS_PRIOR_CF:
			return "PRIOR_CF";
		case X86_EFLAGS_PRIOR_TF:
			return "PRIOR_TF";
		case X86_EFLAGS_PRIOR_IF:
			return "PRIOR_IF";
		case X86_EFLAGS_PRIOR_DF:
			return "PRIOR_DF";
		case X86_EFLAGS_TEST_NT:
			return "TEST_NT";
		case X86_EFLAGS_TEST_DF:
			return "TEST_DF";
		case X86_EFLAGS_RESET_PF:
			return "RESET_PF";
		case X86_EFLAGS_PRIOR_NT:
			return "PRIOR_NT";
		case X86_EFLAGS_MODIFY_TF:
			return "MOD_TF";
		case X86_EFLAGS_MODIFY_IF:
			return "MOD_IF";
		case X86_EFLAGS_MODIFY_DF:
			return "MOD_DF";
		case X86_EFLAGS_MODIFY_NT:
			return "MOD_NT";
		case X86_EFLAGS_MODIFY_RF:
			return "MOD_RF";
		case X86_EFLAGS_SET_CF:
			return "SET_CF";
		case X86_EFLAGS_SET_DF:
			return "SET_DF";
		case X86_EFLAGS_SET_IF:
			return "SET_IF";
	}
}

static const char *get_fpu_flag_name(uint64_t flag)
{
	switch (flag) {
		default:
			return NULL;
		case X86_FPU_FLAGS_MODIFY_C0:
			return "MOD_C0";
		case X86_FPU_FLAGS_MODIFY_C1:
			return "MOD_C1";
		case X86_FPU_FLAGS_MODIFY_C2:
			return "MOD_C2";
		case X86_FPU_FLAGS_MODIFY_C3:
			return "MOD_C3";
		case X86_FPU_FLAGS_RESET_C0:
			return "RESET_C0";
		case X86_FPU_FLAGS_RESET_C1:
			return "RESET_C1";
		case X86_FPU_FLAGS_RESET_C2:
			return "RESET_C2";
		case X86_FPU_FLAGS_RESET_C3:
			return "RESET_C3";
		case X86_FPU_FLAGS_SET_C0:
			return "SET_C0";
		case X86_FPU_FLAGS_SET_C1:
			return "SET_C1";
		case X86_FPU_FLAGS_SET_C2:
			return "SET_C2";
		case X86_FPU_FLAGS_SET_C3:
			return "SET_C3";
		case X86_FPU_FLAGS_UNDEFINED_C0:
			return "UNDEF_C0";
		case X86_FPU_FLAGS_UNDEFINED_C1:
			return "UNDEF_C1";
		case X86_FPU_FLAGS_UNDEFINED_C2:
			return "UNDEF_C2";
		case X86_FPU_FLAGS_UNDEFINED_C3:
			return "UNDEF_C3";
		case X86_FPU_FLAGS_TEST_C0:
			return "TEST_C0";
		case X86_FPU_FLAGS_TEST_C1:
			return "TEST_C1";
		case X86_FPU_FLAGS_TEST_C2:
			return "TEST_C2";
		case X86_FPU_FLAGS_TEST_C3:
			return "TEST_C3";
	}
}


/* Utility function to print instruction details */
static void print_insn_detail(csh ud, cs_mode mode, cs_insn *ins)
{
	int count, i;
	cs_x86 *x86;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	x86 = &(ins->detail->x86);

	print_string_hex("\tPrefix:", x86->prefix, 4);

	print_string_hex("\tOpcode:", x86->opcode, 4);

	printf("\trex: 0x%x\n", x86->rex);

	printf("\taddr_size: %u\n", x86->addr_size);
	printf("\tmodrm: 0x%x\n", x86->modrm);
	if (x86->encoding.modrm_offset != 0) {
		printf("\tmodrm_offset: 0x%x\n", x86->encoding.modrm_offset);
	}
	
	printf("\tdisp: 0x%" PRIx64 "\n", x86->disp);
	if (x86->encoding.disp_offset != 0) {
		printf("\tdisp_offset: 0x%x\n", x86->encoding.disp_offset);
	}
	
	if (x86->encoding.disp_size != 0) {
		printf("\tdisp_size: 0x%x\n", x86->encoding.disp_size);
	}
	
	// SIB is not available in 16-bit mode
	if ((mode & CS_MODE_16) == 0) {
		printf("\tsib: 0x%x\n", x86->sib);
		if (x86->sib_base != X86_REG_INVALID)
			printf("\t\tsib_base: %s\n", cs_reg_name(handle, x86->sib_base));
		if (x86->sib_index != X86_REG_INVALID)
			printf("\t\tsib_index: %s\n", cs_reg_name(handle, x86->sib_index));
		if (x86->sib_scale != 0)
			printf("\t\tsib_scale: %d\n", x86->sib_scale);
	}

	// XOP code condition
	if (x86->xop_cc != X86_XOP_CC_INVALID) {
		printf("\txop_cc: %u\n", x86->xop_cc);
	}

	// SSE code condition
	if (x86->sse_cc != X86_SSE_CC_INVALID) {
		printf("\tsse_cc: %u\n", x86->sse_cc);
	}

	// AVX code condition
	if (x86->avx_cc != X86_AVX_CC_INVALID) {
		printf("\tavx_cc: %u\n", x86->avx_cc);
	}

	// AVX Suppress All Exception
	if (x86->avx_sae) {
		printf("\tavx_sae: %u\n", x86->avx_sae);
	}

	// AVX Rounding Mode
	if (x86->avx_rm != X86_AVX_RM_INVALID) {
		printf("\tavx_rm: %u\n", x86->avx_rm);
	}

	// Print out all immediate operands
	count = cs_op_count(ud, ins, X86_OP_IMM);
	if (count) {
		printf("\timm_count: %u\n", count);
		for (i = 1; i < count + 1; i++) {
			int index = cs_op_index(ud, ins, X86_OP_IMM, i);
			printf("\t\timms[%u]: 0x%" PRIx64 "\n", i, x86->operands[index].imm);
			if (x86->encoding.imm_offset != 0) {
				printf("\timm_offset: 0x%x\n", x86->encoding.imm_offset);
			}
			
			if (x86->encoding.imm_size != 0) {
				printf("\timm_size: 0x%x\n", x86->encoding.imm_size);
			}
		}
	}

	if (x86->op_count)
		printf("\top_count: %u\n", x86->op_count);

	// Print out all operands
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case X86_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case X86_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.segment != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.segment: REG = %s\n", i, cs_reg_name(handle, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
				if (op->mem.scale != 1)
					printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);
				break;
			default:
				break;
		}

		// AVX broadcast type
		if (op->avx_bcast != X86_AVX_BCAST_INVALID)
			printf("\t\toperands[%u].avx_bcast: %u\n", i, op->avx_bcast);

		// AVX zero opmask {z}
		if (op->avx_zero_opmask != false)
			printf("\t\toperands[%u].avx_zero_opmask: TRUE\n", i);

		printf("\t\toperands[%u].size: %u\n", i, op->size);

		switch(op->access) {
			default:
				break;
			case CS_AC_READ:
				printf("\t\toperands[%u].access: READ\n", i);
				break;
			case CS_AC_WRITE:
				printf("\t\toperands[%u].access: WRITE\n", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				printf("\t\toperands[%u].access: READ | WRITE\n", i);
				break;
		}
	}

	// Print out all registers accessed by this instruction (either implicit or explicit)
	if (!cs_regs_access(ud, ins,
				regs_read, &regs_read_count,
				regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for(i = 0; i < regs_read_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_read[i]));
			}
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for(i = 0; i < regs_write_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_write[i]));
			}
			printf("\n");
		}
	}

	if (x86->eflags || x86->fpu_flags) {
		for(i = 0; i < ins->detail->groups_count; i++) {
			if (ins->detail->groups[i] == X86_GRP_FPU) {
				printf("\tFPU_FLAGS:");
				for(i = 0; i <= 63; i++)
					if (x86->fpu_flags & ((uint64_t)1 << i)) {
						printf(" %s", get_fpu_flag_name((uint64_t)1 << i));
					}
				printf("\n");
				break;
			}
		}

		if (i == ins->detail->groups_count) {
			printf("\tEFLAGS:");
			for(i = 0; i <= 63; i++)
				if (x86->eflags & ((uint64_t)1 << i)) {
					printf(" %s", get_eflag_name((uint64_t)1 << i));
				}
			printf("\n");
		}
	}

	printf("\n");
}


/* This function disassembles binary data passed as a buffer 
 * Input: 1. Binary data buffer
 *        2. Buffer size
 */

int disassemble_binary(char *binary_buffer, unsigned long buffer_size)
{
    /* Capstone offset address variable */
    //uint64_t address = 0x00025670;
    uint64_t address = 0x0000;

    /* Declare a type of cs_insn to store instructions */
    cs_insn *insn;
    
    /* Count of instructions */
    size_t count;

    /* Name buffer to compare instruction mnemonic */
    char name_buffer[8] = "syscall";
    /* Declare a struct for capstone , x86-64 architecture */
    struct platform platform_test = {
         CS_ARCH_X86,
         CS_MODE_64,
         (unsigned char *)binary_buffer,
         buffer_size - 1,
         "X86 64 (Intel syntax)"
     };

     cs_err err = cs_open(platform_test.arch, platform_test.mode, &handle);
                if (err) {
                        printf("Failed on cs_open() with error returned: %u\n", err);
                        abort();
                }

                if (platform_test.opt_type)
                        cs_option(handle, platform_test.opt_type, platform_test.opt_value);

                cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

                count = cs_disasm(handle, platform_test.code, platform_test.size, address, 0, &insn);
                if (count) {
                        size_t j;

                        printf("****************\n");
                        printf("Platform: %s\n", platform_test.comment);
   
                        /* Uncomment to print binary data */
                        //print_string_hex("Code:", platform_test.code, platform_test.size);
                        
                        printf("Disasm:\n");

                        for (j = 0; j < count; j++) {
                                if(!strcmp(insn[j].mnemonic,name_buffer))
                                {
                                   /* Uncomment the follwing two line to print instructions before the syscall instruction */
                                   //printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j-1].address, insn[j-1].mnemonic, insn[j-1].op_str);
                                   //print_insn_detail(handle, platform_test.mode, &insn[j-1]);
                                   printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                                   print_insn_detail(handle, platform_test.mode, &insn[j]);
                                }
                        }
                        printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

                        // free memory allocated by cs_disasm()
                        cs_free(insn, count);
                }
   return 0;
}

/**
 * Read /proc/self/maps, find out the code/data locations
 * */
int read_proc(const char *bin_name, proc_info_t *pinfo)
{

int fd;
    int i = 0;
    FILE* fp;
    char c;
    
    /* Buffer to store lines for proc file parsing */
    char buffer[1024];
    
    /* Buffer to store binary data of libc */
    char binary_buffer[1376256];
    
    /* Count of bytes read to print proc file details */ 
    int bytes_read = 0;
    
    /* Declare a char pointer to read binary data */
    char* p;

    /* Open proc file and print details */
    fd = open("/proc/self/maps",O_RDONLY);
    do 
    {
    bytes_read = read(fd, &c, 1);
    printf("%c",c);
    }while(bytes_read!=0); 

    /* Proc file processing to parse */
    fp = fopen("/proc/self/maps","r");
    while(fgets(buffer, sizeof(buffer),fp))
    {
    if(strstr(buffer,bin_name)!= NULL)
    {
      if(strstr(buffer,"r-xp")!=NULL)
      {
        sscanf(buffer,"%lX-%lX",&pinfo->code_start,&pinfo->code_end);
      }
      else if(strstr(buffer,"r--p")!=NULL)
      {
        sscanf(buffer,"%lX-%lX",&pinfo->rodata_start,&pinfo->rodata_end);
      }
      else if(strstr(buffer,"rw-p")!=NULL)
      {
        sscanf(buffer,"%lX-%lX",&pinfo->data_start,&pinfo->data_end);
      }
      else
      {;}
    } 
    }
    printf("the addresses are: %lX and %lX \n",pinfo->code_start, pinfo->code_end);
    p = (char *) pinfo->code_start + 0x670;
    
    printf("%lu",sizeof(binary_buffer));
    while(i < sizeof(binary_buffer))
    {
      binary_buffer[i] = p[i];
      i++;
    }
    
   disassemble_binary(binary_buffer,sizeof(binary_buffer));
   return 0;

}

static bool read_file(const char *fname, void **buf, size_t *len)
{
    int fd = -1;
    struct stat st;
    char *tmp_buf;
    off_t pos;
    ssize_t read_bytes;

    if (stat(fname, &st) == -1) {
        LOG_ERR("fstat: error - %s", strerror(errno));
        return false;
    }
    if (st.st_size == 0) {
        LOG_ERR("fstat: error - st.st_size = 0");
        return false;
    }

    tmp_buf = malloc(st.st_size);
    if (tmp_buf == NULL) {
        LOG_ERR("out of memory when alloc size=%lu", st.st_size);
        return false;
    }

    fd = open(fname, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        LOG_ERR("open file %s error, %s", fname, strerror(errno));
        goto out_free;
    }

    pos = 0;
    while (pos < st.st_size) {
        read_bytes = read(fd, tmp_buf + pos, st.st_size - pos);
        if (read_bytes < 0) {
            LOG_ERR("read error - %s", strerror(errno));
            goto out_free;
        }
        if (read_bytes == 0)
            break;
        pos += read_bytes;
    }

    if (pos != st.st_size) {
        LOG_ERR("read file incomplete, read %lu, size=%lu", pos, st.st_size);
        goto out_free;
    }

    *buf = tmp_buf;
    *len = st.st_size;
    return true;

out_free:
    free(tmp_buf);
    if (fd >= 0)
        close(fd);
    return false;
}

static int __myinit(void) __attribute__((constructor));
static int __myinit(void)
{
  proc_info_t pinfo;
  struct elf_module *m;
  void *bin;
  size_t len;
  const char *fname;
  const char *bname;

  fname = "/runsc";
  bname = filename_from_path(fname);

  if (!read_file(fname, &bin, &len)) {
     free(bin);
     return 0;
  }

  m = load_elf_module(bname, bin, len);
  if (m == NULL) {
     free(bin);
     LOG_ERR("load_elf_module %s failed", bname);
     return 0;
  }

  free(bin);

  /* Uncomment if a function has to be run from the shared library */
  //run_elf_module(m, "main1");

  //LOG_INFO("module %s run done", m->name);
  read_proc("libc",&pinfo);
}
