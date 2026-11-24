/* Force-included (-include) into every cpufetch source file the fuzz builds compile. It routes the
 * project's OS boundary (open() of /proc and /sys files, opendir() of PCI sysfs, getauxval(), and
 * syscall(), used only for perf_event_open by the frequency measurement in src/common/freq.c) to
 * the in-memory files carried by the fuzz input (fuzz_cpufetch.c), so a run depends only on its input.
 * read()/close() stay real: open() hands back a memfd filled with the section's bytes. */
#ifndef CPUFETCH_FUZZFS_H
#define CPUFETCH_FUZZFS_H
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
int fuzzfs_open(const char *path, int flags, ...);
DIR *fuzzfs_opendir(const char *path);
unsigned long fuzzfs_getauxval(unsigned long type);
long fuzzfs_syscall(long number, ...);
/* Heap tracking: cpufetch never frees its cpuInfo/printer structures (it is a one-shot CLI), so the
 * harness records the project's live allocations and frees the leftovers after each input; otherwise
 * the in-process fuzzer's RSS grows ~0.5 KB per input until libFuzzer's rss limit reports a fake OOM.
 * The allocations themselves are still real (ASan-checked) heap blocks. */
void *fuzzfs_malloc(size_t n);
void *fuzzfs_calloc(size_t n, size_t m);
void *fuzzfs_realloc(void *p, size_t n);
void fuzzfs_free(void *p);
#define open fuzzfs_open
#define opendir fuzzfs_opendir
#define getauxval fuzzfs_getauxval
#define syscall fuzzfs_syscall
#define malloc fuzzfs_malloc
#define calloc fuzzfs_calloc
#define realloc fuzzfs_realloc
#define free fuzzfs_free
#endif
