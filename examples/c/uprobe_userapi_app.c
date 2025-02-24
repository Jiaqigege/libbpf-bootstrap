#include <stdio.h>
#include <unistd.h>

int damon_custom(int a, int b)
{
	return a + b;
}

int main(int argc, char *argv[])
{
	pid_t pid = getpid();

	char exe_path[128];
	ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
	if (len != -1) {
		exe_path[len] = '\0'; // 确保路径字符串以 null 结尾
	} else {
		perror("Error reading executable path");
		return -1;
	}

	printf("Please run`sudo ./uprobe_userapi %d %s`\n", pid, exe_path);

	int param_a = 1; // 初始参数 a
	int param_b = 2; // 初始参数 b
	int counter = 0;

	while (1) {
		// 每 5 秒调用一次 damon_custom，并传递递增的参数
		sleep(5);

		// 调用 damon_custom 并传递递增的参数
		int result = damon_custom(param_a + counter, param_b + counter);
		printf("damon_custom called with a = %d, b = %d, result = %d\n", param_a + counter,
		       param_b + counter, result);

		// 递增参数
		counter++;
	}

	return 0;
}
