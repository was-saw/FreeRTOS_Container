#include "elf_help_print.h"
#include "elf_loader.h"
#include "xil_printf.h"
#include <stddef.h>
#include <stdint.h>

/**
 * 打印错误信息
 * @param error_code 错误代码
 */
void print_error(int error_code) {
    switch (error_code) {
        case ELF_ERROR_NULL_POINTER:
            xil_printf("Error: NULL pointer encountered.\r\n");
            break;
        case ELF_ERROR_INVALID_MAGIC:
            xil_printf("Error: Invalid ELF magic number.\r\n");
            break;
        case ELF_ERROR_INVALID_CLASS:
            xil_printf("Error: Invalid ELF class.\r\n");
            break;
        case ELF_ERROR_INVALID_ENDIAN:
            xil_printf("Error: Invalid ELF endianness.\r\n");
            break;
        case ELF_ERROR_INVALID_VERSION:
            xil_printf("Error: Invalid ELF version.\r\n");
            break;
        case ELF_ERROR_INVALID_TYPE:
            xil_printf("Error: Invalid ELF type.\r\n");
            break;
        case ELF_ERROR_INVALID_MACHINE:
            xil_printf("Error: Invalid ELF machine.\r\n");
            break;
        case ELF_ERROR_SECTION_NOT_FOUND:
            xil_printf("Error: Section not found.\r\n");
            break;
        case ELF_ERROR_SYMTAB_NOT_FOUND:
            xil_printf("Error: Symbol table not found.\r\n");
            break;
        case ELF_ERROR_STRTAB_NOT_FOUND:
            xil_printf("Error: String table not found.\r\n");
            break;
        case ELF_ERROR_RELOCATION_FAILED:
            xil_printf("Error: Relocation failed.\r\n");
            break;
        default:
            xil_printf("Error: Unknown error code.\r\n");
            break;
    }
}

/**
 * 输出 ELF 头部信息
 * @param elf_hdr ELF 头部指针
 * 按照结构体的形式输出而非类似readelf那样的输出
 * 主要是用来debug
 */
void print_elf_header(const Elf64_Ehdr *elf_hdr) {
    if (elf_hdr == NULL) {
        xil_printf("ELF Header is NULL.\r\n");
        return;
    }

    xil_printf("Elf64_Ehdr: {\r\n");
    xil_printf("  e_ident: { ");
    for (int i = 0; i < EI_NIDENT; i++) {
        xil_printf("%02x ", elf_hdr->e_ident[i]);
    }
    xil_printf("}\r\n");
    xil_printf("  e_type: %04x\r\n", elf_hdr->e_type);
    xil_printf("  e_machine: %04x\r\n", elf_hdr->e_machine);
    xil_printf("  e_version: %08x\r\n", (unsigned int)elf_hdr->e_version);
    xil_printf("  e_entry: %016llx\r\n", (unsigned long long)elf_hdr->e_entry);
    xil_printf("  e_phoff: %016llx\r\n", (unsigned long long)elf_hdr->e_phoff);
    xil_printf("  e_shoff: %016llx\r\n", (unsigned long long)elf_hdr->e_shoff);
    xil_printf("  e_flags: %08x\r\n", (unsigned int)elf_hdr->e_flags);
    xil_printf("  e_ehsize: %04x\r\n", elf_hdr->e_ehsize);
    xil_printf("  e_phentsize: %04x\r\n", elf_hdr->e_phentsize);
    xil_printf("  e_phnum: %04x\r\n", elf_hdr->e_phnum);
    xil_printf("  e_shentsize: %04x\r\n", elf_hdr->e_shentsize);
    xil_printf("  e_shnum: %04x\r\n", elf_hdr->e_shnum);
    xil_printf("  e_shstrndx: %04x\r\n", elf_hdr->e_shstrndx);
    xil_printf("}\r\n");
}

/**
 * 输出 节/符号的名字
 * @param name_no 名字在字符串表中的索引
 * @param strsh 所用字符串表的节头
 * @param elf_data ELF 文件数据指针
 */
void print_name(Elf64_Word name_no, const Elf64_Shdr *strsh, const uint8_t *elf_data) {
    if (strsh == NULL) {
        xil_printf("String section header is NULL.");
        return;
    }

    // 获取字符串表的起始地址
    const char *strtab = (const char *)(strsh->sh_offset + elf_data);
    if (name_no >= strsh->sh_size) {
        xil_printf("Name index out of bounds.");
    } else {
        xil_printf("%s", &strtab[name_no]);
    }
    return;
}

/**
 * 输出 节头表 信息
 * @param section_headers 节头表指针
 * @param shnum 节头表条目数
 * @param strsh 字符串表节头指针
 * @param elf_data ELF 文件数据指针
 * 按照结构体的形式输出而非类似readelf那样的输出
 * 主要是用来debug
 */
void print_section_headers(const Elf64_Shdr *section_headers,
                           Elf64_Half        shnum,
                           const Elf64_Shdr *strsh,
                           const uint8_t    *elf_data) {
    if (section_headers == NULL) {
        xil_printf("Section Headers are NULL.\r\n");
        return;
    }

    xil_printf("Elf64_Shdr: {\r\n");
    for (int i = 0; i < shnum; i++) {
        xil_printf(" Section Header %d {\r\n", i);
        xil_printf("  sh_name: ");
        print_name(section_headers[i].sh_name, strsh, elf_data);
        xil_printf("\r\n");
        xil_printf("  sh_type: %08x\r\n", (unsigned int)section_headers[i].sh_type);
        xil_printf("  sh_flags: %016llx\r\n", (unsigned long long)section_headers[i].sh_flags);
        xil_printf("  sh_addr: %016llx\r\n", (unsigned long long)section_headers[i].sh_addr);
        xil_printf("  sh_offset: %016llx\r\n", (unsigned long long)section_headers[i].sh_offset);
        xil_printf("  sh_size: %016llx\r\n", (unsigned long long)section_headers[i].sh_size);
        xil_printf("  sh_link: %08x\r\n", (unsigned int)section_headers[i].sh_link);
        xil_printf("  sh_info: %08x\r\n", (unsigned int)section_headers[i].sh_info);
        xil_printf("  sh_addralign: %016llx\r\n", (unsigned long long)section_headers[i].sh_addralign);
        xil_printf("  sh_entsize: %016llx\r\n", (unsigned long long)section_headers[i].sh_entsize);
        xil_printf(" }\r\n");
    }
    xil_printf("}\r\n");
}

/**
 * 输出 一项节头信息
 * @param shdr 节头指针
 * @param strsh 字符串表节头指针
 * @param elf_data ELF 文件数据指针
 * 按照结构体的形式输出而非类似readelf那样的输出
 * 主要是用来debug
 */
void print_section_header(const Elf64_Shdr *shdr,
                          const Elf64_Shdr *strsh,
                          const uint8_t    *elf_data) {
    if (shdr == NULL) {
        xil_printf("Section Header is NULL.\r\n");
        return;
    }

    xil_printf("Elf64_Shdr: {\r\n");
    xil_printf("  sh_name: ");
    print_name(shdr->sh_name, strsh, elf_data);
    xil_printf("\r\n");
    xil_printf("  sh_type: %08x\r\n", (unsigned int)shdr->sh_type);
    xil_printf("  sh_flags: %016llx\r\n", (unsigned long long)shdr->sh_flags);
    xil_printf("  sh_addr: %016llx\r\n", (unsigned long long)shdr->sh_addr);
    xil_printf("  sh_offset: %016llx\r\n", (unsigned long long)shdr->sh_offset);
    xil_printf("  sh_size: %016llx\r\n", (unsigned long long)shdr->sh_size);
    xil_printf("  sh_link: %08x\r\n", (unsigned int)shdr->sh_link);
    xil_printf("  sh_info: %08x\r\n", (unsigned int)shdr->sh_info);
    xil_printf("  sh_addralign: %016llx\r\n", (unsigned long long)shdr->sh_addralign);
    xil_printf("  sh_entsize: %016llx\r\n", (unsigned long long)shdr->sh_entsize);
    xil_printf("}\r\n");
}

/**
 * 输出符号信息
 * @param symtab_hdr 符号表节头指针
 * @param strtab_hdr 字符串表节头指针
 * @param elf_data ELF 文件数据指针
 */
void print_symbol(const Elf64_Sym sym, const Elf64_Shdr *strtab_hdr, const uint8_t *elf_data) {
    if (strtab_hdr == NULL) {
        xil_printf("String table header is NULL.\r\n");
        return;
    }

    xil_printf("Elf64_Sym: {\r\n");
    xil_printf("  st_name: ");
    print_name(sym.st_name, strtab_hdr, elf_data);
    xil_printf("\r\n");
    xil_printf("  st_info: %02x\r\n", sym.st_info);
    xil_printf("  st_other: %02x\r\n", sym.st_other);
    xil_printf("  st_shndx: %04x\r\n", sym.st_shndx);
    xil_printf("  st_value: %016llx\r\n", (unsigned long long)sym.st_value);
    xil_printf("  st_size: %016llx\r\n", (unsigned long long)sym.st_size);
    xil_printf("}\r\n");
}

/**
 * 输出所有加载到内存的代码段
 * @param context ELF文件加载上下文
 * @param section_memory
 */

void print_code(Elf64_Ctx *context, uint8_t section_memory[MAX_SECTIONS * SECTION_MEMORY_SIZE]) {
    if (context == NULL) {
        xil_printf("Context is NULL.\r\n");
        return;
    }

    xil_printf("Loaded Sections:\r\n");
    uint8_t *memory_start = context->memory_pool_index * ELF_MEMORY_SIZE + section_memory;
    for (size_t i = 0; i < context->memory_size; i++) {
        if ((i + 1) % 4 == 0) {
            xil_printf("%02x %02x %02x %02x\r\n",
                memory_start[i], memory_start[i - 1],
                memory_start[i - 2], memory_start[i - 3]);
        }
    }
}

/**
 * 输出重定位信息
 * @param rela 重定位条目指针
 */
void print_relocation_info(const Elf64_Rela *rela) {
    if (rela == NULL) {
        xil_printf("Relocation entry is NULL.\r\n");
        return;
    }

    xil_printf("Elf64_Rela: {\r\n");
    xil_printf("  r_offset: %016llx\r\n", (unsigned long long)rela->r_offset);
    xil_printf("  r_info: %016llx\r\n", (unsigned long long)rela->r_info);
    xil_printf("  r_addend: %016llx\r\n", (unsigned long long)rela->r_addend);
    xil_printf("}\r\n");
}

/**
 * 输出elf context信息
 * @param context ELF文件加载上下文
 */
void print_context(const Elf64_Ctx *context) {
    if (context == NULL) {
        xil_printf("Context is NULL.\r\n");
        return;
    }

    xil_printf("Elf64_Ctx: {\r\n");
    xil_printf("  elf_data: %016llx\r\n", (unsigned long long)context->elf_data);
    xil_printf("  elf_size: %llx\r\n", (unsigned long long)context->elf_size);
    xil_printf("  elf_hdr: %016llx\r\n", (unsigned long long)context->elf_hdr);
    xil_printf("  section_headers: %016llx\r\n", (unsigned long long)context->section_headers);
    xil_printf("  program_headers: %016llx\r\n", (unsigned long long)context->program_headers);
    xil_printf("  shstrtab: %016llx\r\n", (unsigned long long)context->shstrtab);
    xil_printf("  shstrtab_hdr: %016llx\r\n", (unsigned long long)context->shstrtab_hdr);
    xil_printf("  symtab_hdr: %016llx\r\n", (unsigned long long)context->symtab_hdr);
    xil_printf("  strtab_hdr: %016llx\r\n", (unsigned long long)context->strtab_hdr);
    xil_printf("  symtab: %016llx\r\n", (unsigned long long)context->symtab);
    xil_printf("  strtab: %016llx\r\n", (unsigned long long)context->strtab);
    xil_printf("  rela: %016llx\r\n", (unsigned long long)context->rela);
    xil_printf("  memory_pool_index: %d\r\n", context->memory_pool_index);
    xil_printf("  memory_size: %llx\r\n", (unsigned long long)context->memory_size);
    for (int i = 0; i < MAX_SECTIONS; i++) {
        xil_printf("  load_sections[%d]: %016llx\r\n", i, (unsigned long long)context->load_sections[i]);
    }
    xil_printf("  result: %d\r\n", context->result);
}