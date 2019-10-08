/**
 * A simple ELF loader that loads a duplicated .text into memory.
 *
 * Usage:
 *   $ BIN=<binary-variant> LD_PRELOAD=./loader.so ./<binary-vanilla> param1 param2 ...
 * Note: the two binaries could be different
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

#define WARNING "No variant binary specified.\n\
Use: $ BIN=<binary-variant> LD_PRELOAD=./loader.so \
./<binary-vanilla> param1 param2 ...\n"

void init(void) __attribute__ ((constructor));
int init_elf(const char *obj_name);

void init(void)
{
	const char *obj_name = getenv("BIN");
	if (obj_name == NULL) {
		fprintf(stderr, WARNING);
		exit(1);
	}

	printf("** ld_preload init function. BIN %s.\n", obj_name);
	if (init_elf(obj_name)) {
		fprintf(stderr, "Failed to init ELF binary\n");
		exit(1);
	}
}

void print_elf_header(Elf64_Ehdr *elf_header)
{
	printf("%s: version %d, OS abi %d. entry 0x%lx\n", __func__,
			elf_header->e_version, elf_header->e_ident[7], elf_header->e_entry);
}

int init_elf(const char *obj_name)
{
	int i;
	Elf64_Ehdr *elf_header = malloc(sizeof(Elf64_Ehdr));
	Elf64_Shdr *elf_section_headers = NULL;
	Elf64_Shdr *sh_strtab_header = NULL;
	char *sh_strtab = NULL;
	size_t sections;
	size_t section_header_size = sizeof(Elf64_Shdr);

	FILE *obj = fopen(obj_name, "rb");

	// retrieve ELF header
	if (obj == NULL) {
		fprintf(stderr, "Unable to open file\n");
		return 1;
	}
	fread(elf_header, sizeof(Elf64_Ehdr), 1, obj);

	if (elf_header->e_ident[0] != 0x7f || elf_header->e_ident[1] != 'E'
			|| elf_header->e_ident[2] != 'L' || elf_header->e_ident[3] != 'F') {
		fprintf(stderr, "Invalid ELF header!\n");
		return 1;
	}

	if (elf_header->e_ident[4] != ELFCLASS64 ||
		elf_header->e_ident[5] != ELFDATA2LSB)
	{
		fprintf(stderr, "This file is not 64bit little endian\n");
		return 1;
	}
	print_elf_header(elf_header);

	// allocate the ELF section header table in memory
	sections = elf_header->e_shnum;
	elf_section_headers = malloc(section_header_size * sections);
	printf("sections %lu, section header size %lu\n",
			sections, section_header_size * sections);

	// read ELF section header table from binary
	fseek(obj, elf_header->e_shoff, SEEK_SET);
	fread(elf_section_headers, section_header_size, sections, obj);

	// retrieve sh_strtab header
	sh_strtab_header = elf_section_headers + elf_header->e_shstrndx;
	sh_strtab = malloc(sh_strtab_header->sh_size);
	fseek(obj, sh_strtab_header->sh_offset, SEEK_SET);
	fread(sh_strtab, sh_strtab_header->sh_size, 1, obj);

	for (i = 0; i < sections; i++) {
		Elf64_Shdr *section = elf_section_headers + i;
		if (strcmp(".text", sh_strtab + section->sh_name)) continue;
		printf("section[%2d] addr 0x%lx, size 0x%lx. flag 0x%lx. name idx %u. name %s.\n",
				i, section->sh_addr, section->sh_size, section->sh_flags, section->sh_name,
				sh_strtab + section->sh_name);

		// alloc .text memory, using offset+size(end) as the memory block size.
		if ((section->sh_flags & (SHF_ALLOC | SHF_EXECINSTR))
				&& (section->sh_size > 0)) {
			uint64_t offset = section->sh_offset;
			uint64_t mem_size = offset + section->sh_size;
			char *mem = mmap(NULL, mem_size,
					PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

			printf("alloc mem: %p, off 0x%lx, .text size 0x%lx, mem size 0x%lx\n",
					mem, offset, section->sh_size, mem_size);
			fseek(obj, offset, SEEK_SET);
			fread(mem + offset, section->sh_size, 1, obj);
			printf("mem[0] %p, char in hex: 0x%x\n", mem + offset, mem[offset]);
		}
#if 0
		if (section->sh_type == SHT_SYMTAB || section->sh_type == SHT_STRTAB) {
			Elf64_Sym *table = malloc(section->sh_size);
			fseek(obj, section->sh_offset, SEEK_SET);
			fread(table, section->sh_size, 1, obj);
			section->sh_addr = (uint64_t)table;
			printf("type %d\n", section->sh_type);
		}
#endif
	}

	return 0;
}
