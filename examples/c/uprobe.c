// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/* It's a global function to make sure compiler doesn't inline it. To be extra
 * sure we also use "asm volatile" and noinline attributes to prevent
 * compiler from local inlining.
 */
__attribute__((noinline)) int uprobed_add(int a, int b)
{
	asm volatile ("");
	return a + b;
}

__attribute__((noinline)) int uprobed_sub(int a, int b)
{
	asm volatile ("");
	return a - b;
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	int err, i;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	uprobe_opts.func_name = "uprobed_add";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. libbpf will automatically find the offset for us if we provide the
	 * function name. If the function name is not specified, libbpf will try
	 * to use the function offset instead.
	 */
	 // 将 BPF 程序（skel->progs.uprobe_add）附加到指定的函数（uprobed_add）上，
	 // 返回一个指向该程序附加状态的链接对象（skel->links.uprobe_add）
	skel->links.uprobe_add_bpf = bpf_program__attach_uprobe_opts(
			skel->progs.uprobe_add_bpf, // 指向 BPF 程序的指针，表示要附加的 BPF 程序。
			0,  // 要附加探针的目标进程的 PID。0 表示当前进程。
			"/proc/self/exe", // 目标可执行文件的路径，表示当前进程的二进制文件
			// 目标函数的偏移量。0 表示使用函数名来自动查找偏移量。
			// libbpf 会根据函数名称（uprobed_add）来找到它在二进制文件中的地址。
			0,
			&uprobe_opts /* opts */);
	if (!skel->links.uprobe_add_bpf) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	uprobe_opts.func_name = "uprobed_sub";
	uprobe_opts.retprobe = true;
	skel->links.uretprobe_sub_bpf = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_sub_bpf, -1 /* self pid */, "/proc/self/exe",
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.uretprobe_sub_bpf) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = uprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (i = 0;; i++) {
		/* trigger our BPF programs */
		fprintf(stderr, ".");
		uprobed_add(i, i + 1);
		uprobed_sub(i * i, i);
		sleep(5);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}
