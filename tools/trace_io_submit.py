#!/usr/bin/python2

# Simple example to show how to trace kernel func and func ret_value

from bcc import BPF
progs="""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
int kprobe__sys_io_submit(struct pt_regs *ctx, unsigned long kernel_ctx, long nr, void *iocbpp)
{
    bpf_trace_printk("ctx is %p, kernel_ctx is %x, nr is %lx !\\n",ctx, kernel_ctx, nr);
    return 0;
};
int kretprobe__sys_io_submit(struct pt_regs *ctx)
{
        int ret = PT_REGS_RC(ctx);
        u32 pid = bpf_get_current_pid_tgid();
        bpf_trace_printk("trace__io_submit, pid %d, ret is %d\\n", pid, ret);
        return 0;
};
"""
BPF(text=progs).trace_print()
