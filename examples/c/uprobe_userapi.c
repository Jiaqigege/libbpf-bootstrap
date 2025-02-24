// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe_userapi.skel.h"
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int file_exists(const char *path) {
    struct stat buffer;
    return (stat(path, &buffer) == 0);
}

int main(int argc, char **argv)
{
	struct uprobe_userapi_bpf *skel;
	int err, i;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <binary_path>\n", argv[0]);
        return 1;
    }

    // 获取PID参数
    pid_t pid = atoi(argv[1]);

    // 获取binary_path参数
    const char *binary_path = argv[2];


    // 打印PID和binary_path
    printf("PID: %d\n", pid);
    printf("Binary path: %s\n", binary_path);


	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = uprobe_userapi_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	uprobe_opts.func_name = "damon_custom";
	uprobe_opts.retprobe = false;
	skel->links.uprobe_damon_custom_bpf = bpf_program__attach_uprobe_opts(
		skel->progs.uprobe_damon_custom_bpf, // 指向 BPF 程序的指针，表示要附加的 BPF 程序。
		pid, // 要附加探针的目标进程的 PID。0 表示当前进程。
		binary_path, // 目标可执行文件的路径，表示当前进程的二进制文件
		// 目标函数的偏移量。0 表示使用函数名来自动查找偏移量
		// libbpf 会根据函数名称（uprobed_add）来找到它在二进制文件中的地址
		0, 
		&uprobe_opts /* opts */);
	if (!skel->links.uprobe_damon_custom_bpf) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}


	uprobe_opts.func_name = "damon_custom";
	uprobe_opts.retprobe = true;
	skel->links.uretprobe_damon_custom_bpf = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_damon_custom_bpf, pid, binary_path,
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.uretprobe_damon_custom_bpf) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	err = uprobe_userapi_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (i = 0;; i++) {
		/* trigger our BPF programs */
		fprintf(stderr, ".");

		sleep(5);
	}

cleanup:
	uprobe_userapi_bpf__destroy(skel);
	return -err;
}
