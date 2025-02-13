#undef TRACE_SYSTEM
#define TRACE_SYSTEM xhr_test

#if !defined(_TRACE_TE_TEST_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TE_TEST_H

#include <linux/tracepoint.h>

TRACE_EVENT(te_test,
    TP_PROTO(int num),
    TP_ARGS(num),
    TP_STRUCT__entry(
        __field(int, output)
        __field(int, count)
    ),
    TP_fast_assign(
        __entry->count++;
        __entry->output = num;
    ),
    TP_printk("count=%d output=%d",
        __entry->count, __entry->output)
);

#endif /* _TRACE_TE_TEST_H */
    
/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE module_traceevent

#include <trace/define_trace.h>

