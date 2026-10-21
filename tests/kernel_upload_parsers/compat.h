/* Host-only dependencies, not kernel allocation, sysfs or architecture emulation. */
#ifndef RVZR_UPLOAD_HOST_COMPAT_H
#define RVZR_UPLOAD_HOST_COMPAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

/* Match the kernel's unsigned types, including its %llu diagnostics. */
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

/* An explicit test configuration, never inferred from the host kernel. */
#define PAGE_SIZE 4096
#define GFP_KERNEL 0
#define KERN_ERR ""
#define KERN_WARNING ""
#define KERNEL_VERSION(a, b, c) (((a) << 16) | ((b) << 8) | (c))
#define LINUX_VERSION_CODE KERNEL_VERSION(6, 1, 0)

void *host_allocate(size_t size, bool zero);
void host_free(void *pointer);
#define kmalloc(size, flags) host_allocate((size), false)
#define kzalloc(size, flags) host_allocate((size), true)
#define vmalloc(size) host_allocate((size), false)
#define kfree(pointer) host_free(pointer)
#define vfree(pointer) host_free(pointer)
#define printk(...) fprintf(stderr, __VA_ARGS__)

/* shortcuts.h defines an unused inline vmalloc_to_phys helper. Declarations
 * suffice to parse it; intentionally no implementations or physical addresses.
 * Accidentally using that helper will fail to link.
 */
struct page;
struct page *vmalloc_to_page(void *address);
uint64_t page_to_phys(struct page *page);

#endif
