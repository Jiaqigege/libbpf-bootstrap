#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>

#define CREATE_TRACE_POINTS
#include "module_traceevent.h"

static int xhr_thread(void *arg)
{
	static unsigned long count;

	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ);
		trace_te_test(count);
		count++;
	}

	return 0;
}

static struct task_struct *xhr_task;

static __init int __module_init(void)
{
	printk("Hello, %s.\n", __func__);

	xhr_task = kthread_run(xhr_thread, NULL, "xhr-thread");
	if (IS_ERR(xhr_task))
		return -1;

	return 0;
}
static __exit void __module_exit(void)
{
	kthread_stop(xhr_task);
	printk("Hello, %s.\n", __func__);
	return;
}

module_init(__module_init);
module_exit(__module_exit);
MODULE_LICENSE("GPL");
