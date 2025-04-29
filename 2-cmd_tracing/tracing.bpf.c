// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	u64 id;
	pid_t pid, tgid;
	struct task_struct *task;

	uid_t uid = (u32)bpf_get_current_uid_gid();
	id = bpf_get_current_pid_tgid();
	tgid = id >> 32;

	task = (struct task_struct*)bpf_get_current_task();
	pid_t ppid = BPF_CORE_READ(task, real_parent, tgid);

	char comm[256] = {};
	char *cmd_ptr = (char *)BPF_CORE_READ(ctx, args[0]);
	bpf_probe_read_str(&comm, sizeof(comm), cmd_ptr);

	// Print to trace pipe
	bpf_printk("execve: PID %d PPID %d UID %d CMD %s\n", tgid, ppid, uid, comm);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";