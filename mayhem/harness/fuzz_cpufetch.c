/*
 * libFuzzer harness for cpufetch: runs the real main() (renamed cpufetch_main by -Dmain=...) with the
 * hardware/OS boundary replaced by the fuzz input. One source, built per backend:
 *   fuzz_x86    -DARCH_X86   : CPUID comes from the input (src/x86/cpuid_asm.c is not linked)
 *   fuzz_riscv  -DARCH_RISCV : /proc/cpuinfo, /proc/device-tree/compatible, /sys/... from the input
 *   fuzz_arm    -DARCH_ARM   : same, plus nvmem / devicetree model / midr_el1 sysfs files
 *   fuzz_args   -DARCH_X86 -DFUZZ_ARGS_ONLY : the whole input is argv; CPUID is a fixed table
 *
 * Input format (text-friendly sections):
 *   === args\n<whitespace-separated argv tokens>
 *   === /proc/cpuinfo\n<file bytes>             (any absolute path the project open()s)
 *   === cpuid\n<24-byte records: leaf, subleaf, eax, ebx, ecx, edx (LE u32); subleaf ~0 = any>
 *   === auxv\n<u64 AT_HWCAP><u64 AT_HWCAP2>
 * A section's data runs up to and including the "\n" before the next "=== " line, or to the end of
 * the input (so only the last section can lack a trailing newline).
 *
 * argv is allow-listed (common.md: allow-list commands): --measure-max-freq and --accurate-pp start
 * benchmark threads with busy loops, and --version sets a flag parse_args() never resets (static
 * state that would leak into later inputs), so those are not reachable; any other option token must
 * be an exact option spelling, which also rules out getopt's abbreviations of the excluded ones.
 *
 * State kept across inputs: none that an input can change. parse_args() resets every flag it
 * can set from the allowed options; getopt is re-initialised with optind = 0; LOG_LEVEL is set by
 * main(). Heap blocks main() leaves allocated are freed after each input (see fuzzfs.h); the project
 * keeps no static pointer into the heap across calls (args.colors is reset by parse_args()).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <dirent.h>

int cpufetch_main(int argc, char *argv[]);

#define MAX_SECTIONS 64
#define MAX_ARGS 16

struct section { const char *name; size_t name_len; const uint8_t *data; size_t len; };
static struct section sections[MAX_SECTIONS];
static int nsections;

static const uint8_t *find_mem(const uint8_t *h, size_t hl, const char *n, size_t nl) {
  if (hl < nl) return NULL;
  for (size_t i = 0; i + nl <= hl; i++)
    if (memcmp(h + i, n, nl) == 0) return h + i;
  return NULL;
}

static void parse_sections(const uint8_t *data, size_t size) {
  nsections = 0;
  const uint8_t *end = data + size;
  const uint8_t *p;
  if (size >= 4 && memcmp(data, "=== ", 4) == 0) p = data;
  else {
    p = find_mem(data, size, "\n=== ", 5);
    if (!p) return;
    p++;
  }
  while (p && nsections < MAX_SECTIONS) {
    const uint8_t *name = p + 4;
    const uint8_t *nl = memchr(name, '\n', end - name);
    if (!nl) break;
    const uint8_t *body = nl + 1;
    const uint8_t *next = find_mem(body, end - body, "\n=== ", 5);
    struct section *s = &sections[nsections++];
    s->name = (const char *)name; s->name_len = nl - name;
    s->data = body; s->len = (next ? next + 1 : end) - body;  /* keeps the line's '\n' */
    p = next ? next + 1 : NULL;
  }
}

static const struct section *get_section(const char *name) {
  size_t l = strlen(name);
  for (int i = 0; i < nsections; i++)
    if (sections[i].name_len == l && memcmp(sections[i].name, name, l) == 0) return &sections[i];
  return NULL;
}

int fuzzfs_open(const char *path, int flags, ...) {
  (void)flags;
  const struct section *s = get_section(path);
  if (!s || s->name[0] != '/') { errno = ENOENT; return -1; }
  int fd = memfd_create("fuzzfs", 0);
  if (fd < 0) abort();
  size_t off = 0;
  while (off < s->len) {
    ssize_t w = write(fd, s->data + off, s->len - off);
    if (w <= 0) abort();
    off += (size_t)w;
  }
  if (lseek(fd, 0, SEEK_SET) != 0) abort();
  return fd;
}

/* Live heap blocks the project allocated during the current input (open-addressing pointer set). */
#define HEAP_SLOTS (1u << 16)
static void *heap_set[HEAP_SLOTS];
static size_t heap_live;
static int heap_overflow;  /* the set filled up: stop tracking new blocks (they just leak) */

static size_t heap_hash(void *p) { return (size_t)(((uintptr_t)p >> 4) * 0x9E3779B97F4A7C15ull) & (HEAP_SLOTS - 1); }
static void heap_add(void *p) {
  if (!p) return;
  if (heap_live >= HEAP_SLOTS / 2) { heap_overflow = 1; return; }
  size_t i = heap_hash(p);
  while (heap_set[i]) i = (i + 1) & (HEAP_SLOTS - 1);
  heap_set[i] = p; heap_live++;
}
static int heap_del(void *p) {
  size_t i = heap_hash(p);
  while (heap_set[i]) {
    if (heap_set[i] == p) {
      heap_set[i] = NULL; heap_live--;
      /* re-insert the rest of the cluster (linear-probing deletion) */
      for (size_t j = (i + 1) & (HEAP_SLOTS - 1); heap_set[j]; j = (j + 1) & (HEAP_SLOTS - 1)) {
        void *q = heap_set[j]; heap_set[j] = NULL; heap_live--; heap_add(q);
      }
      return 1;
    }
    i = (i + 1) & (HEAP_SLOTS - 1);
  }
  return 0;
}
static void heap_release_all(void) {
  for (size_t i = 0; i < HEAP_SLOTS; i++)
    if (heap_set[i]) { free(heap_set[i]); heap_set[i] = NULL; }
  heap_live = 0; heap_overflow = 0;
}
void *fuzzfs_malloc(size_t n) { void *p = malloc(n); heap_add(p); return p; }
void *fuzzfs_calloc(size_t n, size_t m) { void *p = calloc(n, m); heap_add(p); return p; }
void *fuzzfs_realloc(void *p, size_t n) {
  if (p) heap_del(p);
  void *q = realloc(p, n);
  if (q) heap_add(q); else if (p && n) heap_add(p);  /* failed realloc keeps the old block */
  return q;
}
void fuzzfs_free(void *p) { if (p) heap_del(p); free(p); }

DIR *fuzzfs_opendir(const char *path) { (void)path; errno = ENOENT; return NULL; }

unsigned long fuzzfs_getauxval(unsigned long type) {
  const struct section *s = get_section("auxv");
  uint64_t v[2] = {0, 0};
  if (s) memcpy(v, s->data, s->len < sizeof v ? s->len : sizeof v);
  if (type == AT_HWCAP) return v[0];
  if (type == AT_HWCAP2) return v[1];
  errno = ENOENT;
  return 0;
}

/* perf_event_open is the only syscall() the project makes (the cycle-counter frequency measurement
 * that runs when no max frequency is known). Report it unavailable, as on a host that forbids perf:
 * the run then depends on the input only, and no busy loop runs per input. */
long fuzzfs_syscall(long number, ...) { (void)number; errno = ENOSYS; return -1; }

#ifdef ARCH_X86
#ifdef FUZZ_ARGS_ONLY
#include "cpuid_fixed.h"   /* static const uint8_t fixed_cpuid[]: a recorded CPUID dump */
#endif
/* Replaces src/x86/cpuid_asm.c: answer CPUID from the input's records. */
void cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
  uint32_t leaf = *eax, sub = *ecx;
  const uint8_t *d; size_t n;
#ifdef FUZZ_ARGS_ONLY
  d = fixed_cpuid; n = sizeof fixed_cpuid;
#else
  const struct section *s = get_section("cpuid");
  d = s ? s->data : NULL; n = s ? s->len : 0;
#endif
  *eax = *ebx = *ecx = *edx = 0;
  for (size_t i = 0; i + 24 <= n; i += 24) {
    uint32_t r[6];
    memcpy(r, d + i, sizeof r);
    if (r[0] == leaf && (r[1] == sub || r[1] == 0xFFFFFFFFu)) {
      *eax = r[2]; *ebx = r[3]; *ecx = r[4]; *edx = r[5];
      return;
    }
  }
}
#endif

static int allowed_token(const char *t) {
  static const char *const ok[] = {
    "-s", "-c", "-h", "-d", "-v", "--style", "--color", "--help", "--debug", "--verbose",
    "--logo-long", "--logo-short", "--",
#ifdef ARCH_X86
    "-r", "-F", "--raw", "--full-cpu-name", "--logo-intel-new", "--logo-intel-old",
#endif
    NULL };
  if (t[0] != '-') return 1;  /* an option argument (or a stray operand) */
  if (strncmp(t, "--style=", 8) == 0 || strncmp(t, "--color=", 8) == 0) return 1;
  for (int i = 0; ok[i]; i++) if (strcmp(t, ok[i]) == 0) return 1;
  return 0;
}

static int build_argv(const uint8_t *d, size_t n, char *buf, char **argv) {
  int argc = 0;
  argv[argc++] = "cpufetch";
  memcpy(buf, d, n); buf[n] = '\0';
  char *save = NULL;
  for (char *t = strtok_r(buf, " \t\n\r", &save); t; t = strtok_r(NULL, " \t\n\r", &save)) {
    if (argc >= MAX_ARGS) return -1;
    if (!allowed_token(t)) return -1;
    argv[argc++] = t;
  }
  argv[argc] = NULL;
  return argc;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc; (void)argv;
  /* cpufetch prints its whole report per input; keep libFuzzer's own stderr readable. */
  if (!getenv("CPUFETCH_FUZZ_STDOUT")) {
    if (!freopen("/dev/null", "w", stdout)) return 0;
  }
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *argv[MAX_ARGS + 1];
  char *buf;
  int argc;
#ifdef FUZZ_ARGS_ONLY
  nsections = 0;
  if (memchr(data, '\0', size)) return -1;  /* argv strings cannot contain NUL */
  buf = malloc(size + 1);
  argc = build_argv(data, size, buf, argv);
#else
  parse_sections(data, size);
#if defined(ARCH_ARM) || defined(ARCH_RISCV)
  /* Precondition from the OS contract cpufetch relies on (src/common/udev.c cites it): Linux always
   * exports /sys/devices/system/cpu/present (Documentation/core-api/cpu_hotplug.rst). Its contents
   * stay fuzzed; an input describing a system without the file describes no real Linux host. */
  if (!get_section("/sys/devices/system/cpu/present")) return -1;
#endif
  const struct section *a = get_section("args");
  buf = malloc((a ? a->len : 0) + 1);
  if (a && memchr(a->data, '\0', a->len)) { free(buf); return -1; }
  argc = a ? build_argv(a->data, a->len, buf, argv) : (argv[0] = "cpufetch", argv[1] = NULL, 1);
#endif
  if (argc < 0) { free(buf); return -1; }
  optind = 0;  /* full getopt re-initialisation (glibc) */
  cpufetch_main(argc, argv);
  fflush(stdout);
  heap_release_all();
  free(buf);
  return 0;
}
