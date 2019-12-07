#!/usr/bin/python
#
# This is a example to instruct Linux AIO func.
#
# to capter io_submit and get parameter info.
#

# centos7.6 python2 test pass!

from bcc import BPF
from bcc.utils import printb
import ctypes as ct

prog = """
#include <linux/sched.h>
#include <linux/aio_abi.h>
// define output data structure in C

#define PRINT_XX_BYTES_CONTENT  16

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    unsigned long ctx_id;
    long nr;
    u16 aio_lio_opcode;
    u64 aio_nbytes;
    s64 aio_offset;
    char  aio_buf[PRINT_XX_BYTES_CONTENT];
};
BPF_PERF_OUTPUT(events);

int trace_io_submit(struct pt_regs *ctx, unsigned long ctx_id, long  nr, struct iocb __user* __user* iocbpp) {
    struct data_t data = {};
    struct iocb iocb_tmp = {};
    struct iocb *iocb = NULL;

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ctx_id = ctx_id;
    data.nr = nr;

    if(nr >= 1){
          iocb = iocbpp[0];
          data.aio_lio_opcode = iocb->aio_lio_opcode;
          data.aio_nbytes = iocb->aio_nbytes;
          data.aio_offset = iocb->aio_offset;
          if(data.aio_nbytes >= 16){  //only collect first 16 bytes for print
              bpf_probe_read(&iocb_tmp, sizeof(struct iocb), iocb);
              bpf_probe_read(&data.aio_buf, 16, (char *)iocb_tmp.aio_buf);
          }
          
    }


    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
submit_fnname = b.get_syscall_fnname("io_submit")
b.attach_kprobe(event=submit_fnname, fn_name="trace_io_submit")

# define output data structure in Python
TASK_COMM_LEN = 16    # linux/sched.h
class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN),
		("ctx_id", ct.c_ulong),
		("nr", ct.c_long),
                ("aio_lio_opcode", ct.c_ushort),
                ("aio_nbytes", ct.c_ulong),
                ("aio_offset", ct.c_long),
                ("aio_buf", ct.c_ubyte * 16)]
#OPCODE
#enum {
#                      IOCB_CMD_PREAD = 0,
#                      IOCB_CMD_PWRITE = 1,
#                      IOCB_CMD_FSYNC = 2,
#                      IOCB_CMD_FDSYNC = 3,
#                      IOCB_CMD_NOOP = 6,
#                      IOCB_CMD_PREADV = 7,
#                      IOCB_CMD_PWRITEV = 8,
#};

opcode_str = ["READ", "WRITE", "FSYNC", "FDSYNC", "NOOP", "READV", "WRITEV"]

# header
print("%-18s %-16s %-6s %-6s %-6s %-6s %-6s %-6s %-6s" % ("TIME(s)", "COMM", "PID", "CTX_ID", "NR", "OPCODE", "LEN", "OFFSET", "CONTENT" ))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    printb(b"%-18.9f %-16s %-6d %-6lx %-6lx %-6s %-6d %-16x [%02x %02x %02x %02x %02x %02x %02x %02x]" % (time_s, event.comm, event.pid,
        event.ctx_id, event.nr, opcode_str[event.aio_lio_opcode], event.aio_nbytes, event.aio_offset, event.aio_buf[0], event.aio_buf[1], event.aio_buf[2], event.aio_buf[3],
        event.aio_buf[4], event.aio_buf[5], event.aio_buf[6], event.aio_buf[7]))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

