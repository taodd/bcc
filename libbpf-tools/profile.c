// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * profile    Profile CPU usage by sampling stack traces at a timed interval.
 * Copyright (c) 2022 LG Electronics
 *
 * Based on profile from BCC by Brendan Gregg and others.
 * 28-Dec-2021   Eunseon Lee   Created this.
 */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <time.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include "profile.h"
#include "profile.skel.h"
#include "trace_helpers.h"

#define OPT_PERF_MAX_STACK_DEPTH	1 /* --perf-max-stack-depth */
#define OPT_STACK_STORAGE_SIZE		2 /* --stack-storage-size */
#define OPT_LEGACY_STACKMAP		3 /* --legacy-stackmap */

#define SYM_INFO_LEN			2048

/*
 * -EFAULT in get_stackid normally means the stack-trace is not available,
 * such as getting kernel stack trace in user mode
 */
#define STACK_ID_EFAULT(stack_id)	(stack_id == -EFAULT)

#define STACK_ID_ERR(stack_id)		((stack_id < 0) && !STACK_ID_EFAULT(stack_id))

/* hash collision (-EEXIST) suggests that stack map size may be too small */
#define CHECK_STACK_COLLISION(ustack_id, kstack_id)	\
	(kstack_id == -EEXIST || ustack_id == -EEXIST)

#define MISSING_STACKS(ustack_id, kstack_id)	\
	(!env.user_stacks_only && STACK_ID_ERR(kstack_id)) + (!env.kernel_stacks_only && STACK_ID_ERR(ustack_id))

/* This structure combines key_t and count which should be sorted together */
struct key_ext_t {
	struct key_t k;
	__u64 v;
};

/* User-space aggregation key and entry for streaming ringbuf mode */
struct user_stack_key {
	__u32 pid;
	char name[TASK_COMM_LEN];
	__s32 kstack_sz;
	__s32 ustack_sz;
	unsigned long kstack[PERF_MAX_STACK_DEPTH];
	unsigned long ustack[PERF_MAX_STACK_DEPTH];
};

struct user_stack_entry {
	struct user_stack_key key;
	__u64 count;
	struct user_stack_entry *next;
};

#define USER_STACK_HASH_BITS 16
#define USER_STACK_HASH_BUCKETS (1 << USER_STACK_HASH_BITS)
static struct user_stack_entry *user_stack_hash[USER_STACK_HASH_BUCKETS];
static size_t total_unique_stacks = 0;
static size_t total_samples = 0;
static volatile bool exiting = false;

typedef const char* (*symname_fn_t)(unsigned long);

/* This structure represents output format-dependent attributes. */
struct fmt_t {
	bool folded;
	char *prefix;
	char *suffix;
	char *delim;
};

struct fmt_t stacktrace_formats[] = {
	{ false, "    ", "\n", "--" },	/* multi-line */
	{ true, ";", "", "-" }		/* folded */
};

#define pr_format(str, fmt)		printf("%s%s%s", fmt->prefix, str, fmt->suffix)

static struct env {
	pid_t pids[MAX_PID_NR];
	pid_t tids[MAX_TID_NR];
	bool user_stacks_only;
	bool kernel_stacks_only;
	int stack_storage_size;
	int perf_max_stack_depth;
	int duration;
	bool verbose;
	bool freq;
	int sample_freq;
	bool delimiter;
	bool include_idle;
	int cpu;
	bool folded;
	bool ringbuf;
} env = {
	.stack_storage_size = 1024,
	.perf_max_stack_depth = 127,
	.duration = INT_MAX,
	.freq = 1,
	.sample_freq = 49,
	.cpu = -1,
	.ringbuf = true,
};

const char *argp_program_version = "profile 0.2 (ringbuf streaming)";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Profile CPU usage by sampling stack traces at a timed interval.\n"
"\n"
"USAGE: profile [OPTIONS...] [duration]\n"
"EXAMPLES:\n"
"    profile             # profile stack traces at 49 Hertz using ringbuf until Ctrl-C\n"
"    profile -F 99       # profile stack traces at 99 Hertz\n"
"    profile 5           # profile at 49 Hertz for 5 seconds only\n"
"    profile -f          # output in folded format for flame graphs\n"
"    profile -p 185      # only profile process with PID 185\n"
"    profile -L 185      # only profile thread with TID 185\n"
"    profile -U          # only show user space stacks (no kernel)\n"
"    profile -K          # only show kernel space stacks (no user)\n"
"    profile --legacy-stackmap # use legacy in-kernel BPF_MAP_TYPE_STACK_TRACE\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "profile processes with one or more comma-separated PIDs only", 0 },
	{ "tid", 'L', "TID", 0, "profile threads with one or more comma-separated TIDs only", 0 },
	{ "user-stacks-only", 'U', NULL, 0,
	  "show stacks from user space only (no kernel space stacks)", 0 },
	{ "kernel-stacks-only", 'K', NULL, 0,
	  "show stacks from kernel space only (no user space stacks)", 0 },
	{ "frequency", 'F', "FREQUENCY", 0, "sample frequency, Hertz", 0 },
	{ "delimited", 'd', NULL, 0, "insert delimiter between kernel/user stacks", 0 },
	{ "include-idle ", 'I', NULL, 0, "include CPU idle stacks", 0 },
	{ "folded", 'f', NULL, 0, "output folded format, one line per stack (for flame graphs)", 0 },
	{ "ringbuf", 'R', NULL, 0,
	  "stream stack traces via BPF ring buffer to user space (OTel approach, default: enabled)", 0 },
	{ "legacy-stackmap", OPT_LEGACY_STACKMAP, NULL, 0,
	  "use legacy in-kernel BPF_MAP_TYPE_STACK_TRACE accumulation", 0 },
	{ "stack-storage-size", OPT_STACK_STORAGE_SIZE, "STACK-STORAGE-SIZE", 0,
	  "the number of unique stack traces in legacy mode (default 1024)", 0 },
	{ "cpu", 'C', "CPU", 0, "cpu number to run profile on", 0 },
	{ "perf-max-stack-depth", OPT_PERF_MAX_STACK_DEPTH,
	  "PERF-MAX-STACK-DEPTH", 0, "the limit for both kernel and user stack traces (default 127)", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

struct ksyms *ksyms;
struct syms_cache *syms_cache;
struct syms *syms;
static char syminfo[SYM_INFO_LEN];

static inline uint32_t hash_stack(const struct user_stack_key *k)
{
	uint32_t hash = 2166136261u;
	hash ^= k->pid;
	hash *= 16777619u;
	for (int i = 0; i < TASK_COMM_LEN && k->name[i]; i++) {
		hash ^= (uint8_t)k->name[i];
		hash *= 16777619u;
	}
	hash ^= (uint32_t)k->kstack_sz;
	hash *= 16777619u;
	for (int i = 0; i < k->kstack_sz; i++) {
		uint64_t ip = k->kstack[i];
		hash ^= (uint32_t)(ip & 0xffffffff);
		hash *= 16777619u;
		hash ^= (uint32_t)(ip >> 32);
		hash *= 16777619u;
	}
	hash ^= (uint32_t)k->ustack_sz;
	hash *= 16777619u;
	for (int i = 0; i < k->ustack_sz; i++) {
		uint64_t ip = k->ustack[i];
		hash ^= (uint32_t)(ip & 0xffffffff);
		hash *= 16777619u;
		hash ^= (uint32_t)(ip >> 32);
		hash *= 16777619u;
	}
	return hash;
}

static inline bool stack_keys_equal(const struct user_stack_key *a, const struct user_stack_key *b)
{
	if (a->pid != b->pid || a->kstack_sz != b->kstack_sz || a->ustack_sz != b->ustack_sz)
		return false;
	if (strcmp(a->name, b->name) != 0)
		return false;
	if (a->kstack_sz > 0 && memcmp(a->kstack, b->kstack, a->kstack_sz * sizeof(unsigned long)) != 0)
		return false;
	if (a->ustack_sz > 0 && memcmp(a->ustack, b->ustack, a->ustack_sz * sizeof(unsigned long)) != 0)
		return false;
	return true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct stack_event *e = data;
	struct user_stack_key key;
	memset(&key, 0, sizeof(key));
	key.pid = e->pid;
	memcpy(key.name, e->name, sizeof(key.name));
	key.name[sizeof(key.name) - 1] = '\0';
	key.kstack_sz = (e->kstack_sz > 0) ? e->kstack_sz : 0;
	key.ustack_sz = (e->ustack_sz > 0) ? e->ustack_sz : 0;

	if (key.kstack_sz > env.perf_max_stack_depth)
		key.kstack_sz = env.perf_max_stack_depth;
	if (key.ustack_sz > env.perf_max_stack_depth)
		key.ustack_sz = env.perf_max_stack_depth;

	for (int i = 0; i < key.kstack_sz; i++)
		key.kstack[i] = (unsigned long)e->kstack[i];
	for (int i = 0; i < key.ustack_sz; i++)
		key.ustack[i] = (unsigned long)e->ustack[i];

	uint32_t h = hash_stack(&key) & (USER_STACK_HASH_BUCKETS - 1);
	struct user_stack_entry *entry = user_stack_hash[h];
	while (entry) {
		if (stack_keys_equal(&entry->key, &key)) {
			entry->count++;
			total_samples++;
			return 0;
		}
		entry = entry->next;
	}

	entry = calloc(1, sizeof(*entry));
	if (!entry) {
		fprintf(stderr, "failed to alloc user_stack_entry\n");
		return 0;
	}
	entry->key = key;
	entry->count = 1;
	entry->next = user_stack_hash[h];
	user_stack_hash[h] = entry;
	total_unique_stacks++;
	total_samples++;
	return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;
	int ret;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	case 'p':
		ret = split_convert(strdup(arg), ",", env.pids, sizeof(env.pids),
				    sizeof(pid_t), str_to_int);
		if (ret) {
			if (ret == -ENOBUFS)
				fprintf(stderr, "the number of pid is too big, please "
					"increase MAX_PID_NR's value and recompile\n");
			else
				fprintf(stderr, "invalid PID: %s\n", arg);

			argp_usage(state);
		}
		break;
	case 'L':
		ret = split_convert(strdup(arg), ",", env.tids, sizeof(env.tids),
				    sizeof(pid_t), str_to_int);
		if (ret) {
			if (ret == -ENOBUFS)
				fprintf(stderr, "the number of tid is too big, please "
					"increase MAX_TID_NR's value and recompile\n");
			else
				fprintf(stderr, "invalid TID: %s\n", arg);

			argp_usage(state);
		}
		break;
	case 'U':
		env.user_stacks_only = true;
		break;
	case 'K':
		env.kernel_stacks_only = true;
		break;
	case 'F':
		errno = 0;
		env.sample_freq = strtol(arg, NULL, 10);
		if (errno || env.sample_freq <= 0) {
			fprintf(stderr, "invalid FREQUENCY: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'd':
		env.delimiter = true;
		break;
	case 'I':
		env.include_idle = true;
		break;
	case 'C':
		errno = 0;
		env.cpu = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid CPU: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'f':
		env.folded = true;
		break;
	case 'R':
		env.ringbuf = true;
		break;
	case OPT_LEGACY_STACKMAP:
		env.ringbuf = false;
		break;
	case OPT_PERF_MAX_STACK_DEPTH:
		errno = 0;
		env.perf_max_stack_depth = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid perf max stack depth: %s\n", arg);
			argp_usage(state);
		}
		break;
	case OPT_STACK_STORAGE_SIZE:
		errno = 0;
		env.stack_storage_size = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "invalid stack storage size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		if (pos_args++) {
			fprintf(stderr,
				"Unrecognized positional argument: %s\n", arg);
			argp_usage(state);
		}
		errno = 0;
		env.duration = strtol(arg, NULL, 10);
		if (errno || env.duration <= 0) {
			fprintf(stderr, "Invalid duration (in s): %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int nr_cpus;

static int open_and_attach_perf_event(struct bpf_program *prog,
				      struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = env.freq,
		.sample_freq = env.sample_freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		if (env.cpu != -1 && env.cpu != i)
			continue;

		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;

			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}

		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (!links[i]) {
			fprintf(stderr, "failed to attach perf event on cpu: "
				"%d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
	}

	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static int cmp_counts(const void *a, const void *b)
{
	const __u64 x = ((struct key_ext_t *) a)->v;
	const __u64 y = ((struct key_ext_t *) b)->v;

	/* descending order */
	return y - x;
}

static int read_counts_map(int fd, struct key_ext_t *items, __u32 *count)
{
	struct key_t empty = {};
	struct key_t *lookup_key = &empty;
	int i = 0;
	int err;

	while (bpf_map_get_next_key(fd, lookup_key, &items[i].k) == 0) {
		err = bpf_map_lookup_elem(fd, &items[i].k, &items[i].v);
		if (err < 0) {
			fprintf(stderr, "failed to lookup counts: %d\n", err);
			return -err;
		}

		if (items[i].v == 0)
			continue;

		lookup_key = &items[i].k;
		i++;
	}

	*count = i;
	return 0;
}

static const char *ksymname(unsigned long addr)
{
	const struct ksym *ksym = ksyms__map_addr(ksyms, addr);

	if (!env.verbose)
		return ksym ? ksym->name : "[unknown]";

	if (ksym)
		snprintf(syminfo, SYM_INFO_LEN, "0x%lx %s+0x%lx", addr,
			 ksym->name, addr - ksym->addr);
	else
		snprintf(syminfo, SYM_INFO_LEN, "0x%lx [unknown]", addr);

	return syminfo;
}

static const char *usyminfo(unsigned long addr)
{
	struct sym_info sinfo;
	int err;
	int c;

	c = snprintf(syminfo, SYM_INFO_LEN, "0x%016lx", addr);

	err = syms__map_addr_dso(syms, addr, &sinfo);
	if (err == 0) {
		if (sinfo.sym_name) {
			c += snprintf(syminfo + c, SYM_INFO_LEN - c, " %s+0x%lx",
				      sinfo.sym_name, sinfo.sym_offset);
		}

		snprintf(syminfo + c, SYM_INFO_LEN - c, " (%s+0x%lx)",
			 sinfo.dso_name, sinfo.dso_offset);
	}

	return syminfo;
}

static const char *usymname(unsigned long addr)
{
	const struct sym *sym;

	if (!env.verbose) {
		sym = syms__map_addr(syms, addr);
		return sym ? sym->name : "[unknown]";
	}

	return usyminfo(addr);
}

static void print_stacktrace(unsigned long *ip, symname_fn_t symname, struct fmt_t *f)
{
	int i;

	if (!f->folded) {
		for (i = 0; ip[i] && i < env.perf_max_stack_depth; i++)
			pr_format(symname(ip[i]), f);
		return;
	} else {
		for (i = env.perf_max_stack_depth - 1; i >= 0; i--) {
			if (!ip[i])
				continue;

			pr_format(symname(ip[i]), f);
		}
	}
}

static bool print_user_stacktrace(struct key_t *event, int stack_map,
				  unsigned long *ip, struct fmt_t *f, bool delim)
{
	if (env.kernel_stacks_only || STACK_ID_EFAULT(event->user_stack_id))
		return false;

	if (delim)
		pr_format(f->delim, f);

	if (bpf_map_lookup_elem(stack_map, &event->user_stack_id, ip) != 0) {
		pr_format("[Missed User Stack]", f);
	} else {
		syms = syms_cache__get_syms(syms_cache, event->pid);
		if (syms)
			print_stacktrace(ip, usymname, f);
		else if (!f->folded)
			fprintf(stderr, "failed to get syms\n");
	}

	return true;
}

static bool print_kern_stacktrace(struct key_t *event, int stack_map,
				  unsigned long *ip, struct fmt_t *f, bool delim)
{
	if (env.user_stacks_only || STACK_ID_EFAULT(event->kern_stack_id))
		return false;

	if (delim)
		pr_format(f->delim, f);

	if (bpf_map_lookup_elem(stack_map, &event->kern_stack_id, ip) != 0)
		pr_format("[Missed Kernel Stack]", f);
	else
		print_stacktrace(ip, ksymname, f);

	return true;
}

static int print_count(struct key_t *event, __u64 count, int stack_map, bool folded)
{
	unsigned long *ip;
	int ret;
	struct fmt_t *fmt = &stacktrace_formats[folded];

	ip = calloc(env.perf_max_stack_depth, sizeof(unsigned long));
	if (!ip) {
		fprintf(stderr, "failed to alloc ip\n");
		return -ENOMEM;
	}

	if (!folded) {
		/* multi-line stack output */
		ret = print_kern_stacktrace(event, stack_map, ip, fmt, false);
		print_user_stacktrace(event, stack_map, ip, fmt, ret && env.delimiter);
		printf("    %-16s %s (%d)\n", "-", event->name, event->pid);
		printf("        %lld\n\n", count);
	} else {
		/* folded stack output */
		printf("%s", event->name);
		ret = print_user_stacktrace(event, stack_map, ip, fmt, false);
		print_kern_stacktrace(event, stack_map, ip, fmt, ret && env.delimiter);
		printf(" %lld\n", count);
	}

	free(ip);

	return 0;
}

static int print_counts(int counts_map, int stack_map)
{
	struct key_ext_t *counts;
	struct key_t *event;
	__u64 count;
	__u32 nr_count = MAX_ENTRIES;
	size_t nr_missing_stacks = 0;
	bool has_collision = false;
	int i, ret = 0;

	counts = calloc(MAX_ENTRIES, sizeof(struct key_ext_t));
	if (!counts) {
		fprintf(stderr, "Out of memory\n");
		return -ENOMEM;
	}

	ret = read_counts_map(counts_map, counts, &nr_count);
	if (ret)
		goto cleanup;

	qsort(counts, nr_count, sizeof(struct key_ext_t), cmp_counts);

	for (i = 0; i < nr_count; i++) {
		event = &counts[i].k;
		count = counts[i].v;

		print_count(event, count, stack_map, env.folded);

		/* handle stack id errors */
		nr_missing_stacks += MISSING_STACKS(event->user_stack_id, event->kern_stack_id);
		has_collision = CHECK_STACK_COLLISION(event->user_stack_id, event->kern_stack_id);
	}

	if (nr_missing_stacks > 0) {
		fprintf(stderr, "WARNING: %zu stack traces could not be displayed.%s\n",
			nr_missing_stacks, has_collision ?
			" Consider increasing --stack-storage-size.":"");
	}

cleanup:
	free(counts);

	return ret;
}

static int cmp_user_stack_entries(const void *a, const void *b)
{
	const struct user_stack_entry *e1 = *(const struct user_stack_entry **)a;
	const struct user_stack_entry *e2 = *(const struct user_stack_entry **)b;
	if (e1->count > e2->count)
		return -1;
	if (e1->count < e2->count)
		return 1;
	return 0;
}

static void print_ringbuf_counts(bool folded)
{
	if (total_unique_stacks == 0)
		return;

	struct user_stack_entry **entries = calloc(total_unique_stacks, sizeof(void *));
	if (!entries) {
		fprintf(stderr, "Out of memory allocating entries for sorting\n");
		return;
	}

	size_t count = 0;
	for (size_t b = 0; b < USER_STACK_HASH_BUCKETS; b++) {
		struct user_stack_entry *curr = user_stack_hash[b];
		while (curr) {
			if (count < total_unique_stacks)
				entries[count++] = curr;
			curr = curr->next;
		}
	}

	qsort(entries, count, sizeof(void *), cmp_user_stack_entries);

	struct fmt_t *fmt = &stacktrace_formats[folded];
	for (size_t i = 0; i < count; i++) {
		struct user_stack_entry *entry = entries[i];
		struct user_stack_key *k = &entry->key;

		if (!folded) {
			/* Multi-line output */
			bool ret = false;
			if (!env.user_stacks_only && k->kstack_sz > 0) {
				for (int s = 0; s < k->kstack_sz; s++)
					pr_format(ksymname(k->kstack[s]), fmt);
				ret = true;
			}
			if (!env.kernel_stacks_only && k->ustack_sz > 0) {
				if (ret && env.delimiter)
					pr_format(fmt->delim, fmt);
				syms = syms_cache__get_syms(syms_cache, k->pid);
				for (int s = 0; s < k->ustack_sz; s++) {
					const char *name = syms ? usymname(k->ustack[s]) : "[unknown]";
					pr_format(name, fmt);
				}
			}
			printf("    %-16s %s (%d)\n", "-", k->name, k->pid);
			printf("        %llu\n\n", (unsigned long long)entry->count);
		} else {
			/* Folded output: comm;user_stacks (bottom->top);delim;kernel_stacks (bottom->top) count */
			printf("%s", k->name);
			bool ret = false;
			if (!env.kernel_stacks_only && k->ustack_sz > 0) {
				syms = syms_cache__get_syms(syms_cache, k->pid);
				for (int s = k->ustack_sz - 1; s >= 0; s--) {
					const char *name = syms ? usymname(k->ustack[s]) : "[unknown]";
					pr_format(name, fmt);
				}
				ret = true;
			}
			if (!env.user_stacks_only && k->kstack_sz > 0) {
				if (ret && env.delimiter)
					pr_format(fmt->delim, fmt);
				for (int s = k->kstack_sz - 1; s >= 0; s--) {
					pr_format(ksymname(k->kstack[s]), fmt);
				}
			}
			printf(" %llu\n", (unsigned long long)entry->count);
		}
	}

	free(entries);
}

static int set_pidns(const struct profile_bpf *obj)
{
	struct stat statbuf;

	if (!probe_bpf_ns_current_pid_tgid())
		return -EPERM;

	if (stat("/proc/self/ns/pid", &statbuf) == -1)
		return -errno;

	obj->rodata->use_pidns = true;
	obj->rodata->pidns_dev = statbuf.st_dev;
	obj->rodata->pidns_ino = statbuf.st_ino;

	return 0;
}

static void print_headers()
{
	int i;

	printf("Sampling at %d Hertz of", env.sample_freq);

	if (env.pids[0]) {
		printf(" PID [");
		for (i = 0; i < MAX_PID_NR && env.pids[i]; i++)
			printf("%d%s", env.pids[i], (i < MAX_PID_NR - 1 && env.pids[i + 1]) ? ", " : "]");
	} else if (env.tids[0]) {
		printf(" TID [");
		for (i = 0; i < MAX_TID_NR && env.tids[i]; i++)
			printf("%d%s", env.tids[i], (i < MAX_TID_NR - 1 && env.tids[i + 1]) ? ", " : "]");
	} else {
		printf(" all threads");
	}

	if (env.user_stacks_only)
		printf(" by user");
	else if (env.kernel_stacks_only)
		printf(" by kernel");
	else
		printf(" by user + kernel");

	if (env.cpu != -1)
		printf(" on CPU#%d", env.cpu);

	if (env.ringbuf)
		printf(" [mode: streaming ringbuf]");
	else
		printf(" [mode: legacy stackmap]");

	if (env.duration < INT_MAX)
		printf(" for %d secs.\n", env.duration);
	else
		printf("... Hit Ctrl-C to end.\n");
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link *links[MAX_CPU_NR] = {};
	struct profile_bpf *obj;
	struct ring_buffer *rb = NULL;
	int pids_fd, tids_fd;
	int err, i;
	__u8 val = 0;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	if (env.user_stacks_only && env.kernel_stacks_only) {
		fprintf(stderr, "user_stacks_only and kernel_stacks_only cannot be used together.\n");
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		printf("failed to get # of possible cpus: '%s'!\n",
		       strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile\n");
		return 1;
	}

	obj = profile_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->user_stacks_only = env.user_stacks_only;
	obj->rodata->kernel_stacks_only = env.kernel_stacks_only;
	obj->rodata->include_idle = env.include_idle;
	obj->rodata->use_ringbuf = env.ringbuf;
	if (env.pids[0])
		obj->rodata->filter_by_pid = true;
	else if (env.tids[0])
		obj->rodata->filter_by_tid = true;

	bpf_map__set_value_size(obj->maps.stackmap,
				env.perf_max_stack_depth * sizeof(unsigned long));
	if (env.ringbuf) {
		/* In streaming ringbuf mode, shrink legacy maps to 1 entry to save kernel RAM */
		bpf_map__set_max_entries(obj->maps.stackmap, 1);
		bpf_map__set_max_entries(obj->maps.counts, 1);
	} else {
		bpf_map__set_max_entries(obj->maps.stackmap, env.stack_storage_size);
	}

	err = set_pidns(obj);
	if (err && env.verbose)
		fprintf(stderr, "failed to translate pidns: %s\n", strerror(-err));

	err = profile_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF programs: %d\n", err);
		goto cleanup;
	}

	if (env.pids[0]) {
		pids_fd = bpf_map__fd(obj->maps.pids);
		for (i = 0; i < MAX_PID_NR && env.pids[i]; i++) {
			if (bpf_map_update_elem(pids_fd, &(env.pids[i]), &val, BPF_ANY) != 0) {
				fprintf(stderr, "failed to init pids map: %s\n", strerror(errno));
				goto cleanup;
			}
		}
	}
	else if (env.tids[0]) {
		tids_fd = bpf_map__fd(obj->maps.tids);
		for (i = 0; i < MAX_TID_NR && env.tids[i]; i++) {
			if (bpf_map_update_elem(tids_fd, &(env.tids[i]), &val, BPF_ANY) != 0) {
				fprintf(stderr, "failed to init tids map: %s\n", strerror(errno));
				goto cleanup;
			}
		}
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}

	err = open_and_attach_perf_event(obj->progs.do_perf_event, links);
	if (err)
		goto cleanup;

	signal(SIGINT, sig_handler);

	if (!env.folded)
		print_headers();

	if (env.ringbuf) {
		rb = ring_buffer__new(bpf_map__fd(obj->maps.events), handle_event, NULL, NULL);
		if (!rb) {
			fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
			goto cleanup;
		}

		time_t start = time(NULL);
		while (!exiting) {
			err = ring_buffer__poll(rb, 100 /* timeout ms */);
			if (err < 0 && err != -EINTR) {
				fprintf(stderr, "error polling ring buffer: %d\n", err);
				break;
			}
			if (env.duration != INT_MAX && (time(NULL) - start) >= env.duration)
				break;
		}

		/* Detach perf events first so no new samples arrive */
		if (env.cpu != -1) {
			bpf_link__destroy(links[env.cpu]);
			links[env.cpu] = NULL;
		} else {
			for (i = 0; i < nr_cpus; i++) {
				bpf_link__destroy(links[i]);
				links[i] = NULL;
			}
		}

		/* Drain any remaining events in ring buffer */
		ring_buffer__consume(rb);
		ring_buffer__free(rb);
		rb = NULL;

		print_ringbuf_counts(env.folded);
		if (obj->bss && obj->bss->dropped > 0) {
			fprintf(stderr, "WARNING: %llu samples dropped due to ring buffer full\n",
				(unsigned long long)obj->bss->dropped);
		}
	} else {
		/* Legacy mode */
		sleep(env.duration);
		print_counts(bpf_map__fd(obj->maps.counts),
			     bpf_map__fd(obj->maps.stackmap));
	}

cleanup:
	if (rb)
		ring_buffer__free(rb);
	if (env.cpu != -1) {
		if (links[env.cpu])
			bpf_link__destroy(links[env.cpu]);
	} else {
		for (i = 0; i < nr_cpus; i++) {
			if (links[i])
				bpf_link__destroy(links[i]);
		}
	}
	if (syms_cache)
		syms_cache__free(syms_cache);
	if (ksyms)
		ksyms__free(ksyms);
	profile_bpf__destroy(obj);

	/* Clean up user space hash table */
	for (size_t b = 0; b < USER_STACK_HASH_BUCKETS; b++) {
		struct user_stack_entry *curr = user_stack_hash[b];
		while (curr) {
			struct user_stack_entry *tmp = curr;
			curr = curr->next;
			free(tmp);
		}
		user_stack_hash[b] = NULL;
	}

	return err != 0;
}
