// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Copyright (c) 2022 LG Electronics
 *
 * Based on profile from BCC by Brendan Gregg and others.
 * 28-Dec-2021   Eunseon Lee   Created this.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "profile.h"

const volatile bool kernel_stacks_only = false;
const volatile bool user_stacks_only = false;
const volatile bool include_idle = false;
const volatile bool filter_by_pid = false;
const volatile bool filter_by_tid = false;
const volatile bool use_pidns = false;
const volatile __u64 pidns_dev = 0;
const volatile __u64 pidns_ino = 0;

__u64 dropped = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_PID_NR);
} pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u8);
	__uint(max_entries, MAX_TID_NR);
} tids SEC(".maps");

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	u64 id;
	u32 pid;
	u32 tid;
	struct bpf_pidns_info ns = {};

	if (use_pidns && !bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns,
						      sizeof(ns))) {
		pid = ns.tgid;
		tid = ns.pid;
	} else {
		id = bpf_get_current_pid_tgid();
		pid = id >> 32;
		tid = id;
	}

	if (!include_idle && tid == 0)
		return 0;

	if (filter_by_pid && !bpf_map_lookup_elem(&pids, &pid))
		return 0;

	if (filter_by_tid && !bpf_map_lookup_elem(&tids, &tid))
		return 0;

	struct stack_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__sync_fetch_and_add(&dropped, 1);
		return 0;
	}

	e->pid = pid;
	e->tid = tid;
	e->cpu = bpf_get_smp_processor_id();
	bpf_get_current_comm(&e->name, sizeof(e->name));

	if (user_stacks_only) {
		e->kstack_sz = 0;
	} else {
		long kbytes = bpf_get_stack(ctx, e->kstack, sizeof(e->kstack), 0);
		e->kstack_sz = (kbytes > 0) ? (kbytes / sizeof(__u64)) : (int)kbytes;
	}

	if (kernel_stacks_only) {
		e->ustack_sz = 0;
	} else {
		long ubytes = bpf_get_stack(ctx, e->ustack, sizeof(e->ustack), BPF_F_USER_STACK);
		e->ustack_sz = (ubytes > 0) ? (ubytes / sizeof(__u64)) : (int)ubytes;
	}

	bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
