#include "syscall.h"
#include "FreeRTOS.h"

#ifdef configUSE_FILESYSTEM
#include "task.h"
#include "file_system.h"
#endif

extern void uart_puts(const char *str);

// 定义全局的 FreeRTOS 系统调用实例，供外部程序使用
FreeRTOSSyscalls_t freertos_syscalls = {
    .uart_puts = uart_puts,
#ifdef configUSE_FILESYSTEM
    .pwd = pvTaskGetPwdPath,
    .set_pwd = xTaskSetPwdPath,
#endif
    // 后续可以添加其他系统调用函数指针
};

FreeRTOS_GOT_t freertos_got __attribute__((section(".freertos_got"))) = {
    .freertos_syscalls = &freertos_syscalls,
#ifdef configUSE_FILESYSTEM
    .get_lfs_ops = pxGetLfsOps,
#endif
    // 后续可以添加其他全局偏移表项
};

GOT_t got = {.num_entries = 1, .entrys = {{"freertos_syscalls", (Elf64_Addr *)&freertos_syscalls}}};