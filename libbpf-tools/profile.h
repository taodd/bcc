// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __PROFILE_H
#define __PROFILE_H

#define TASK_COMM_LEN		16
#define MAX_CPU_NR		128
#define MAX_PID_NR		30
#define MAX_TID_NR		30
#define PERF_MAX_STACK_DEPTH	127

struct stack_event {
	__u32 pid;
	__u32 tid;
	__u32 cpu;
	char name[TASK_COMM_LEN];
	__s32 kstack_sz;
	__s32 ustack_sz;
	__u64 kstack[PERF_MAX_STACK_DEPTH];
	__u64 ustack[PERF_MAX_STACK_DEPTH];
};

#endif /* __PROFILE_H */
