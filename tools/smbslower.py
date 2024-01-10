#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# smbslower     Trace slow SMB operations
#               for Linux using BCC & eBPF
#
# Usage: smbslower.py [-h] [-j] [-p PID] [-c CID] [-d DURATION] [min_us]
#
# This script traces all SMB operations. It measures the time spent in these
# operations, and prints details for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to the smb operations,
# including reads and writes from the file system cache. Such reads and writes
# can be very frequent (depending on the workload; eg, 1M/sec), at which
# point the overhead of this tool (even if it prints no "slower" events) can
# begin to become significant.
#
# A fair bit of this code is copied from similar tools (ext4slower, nfsslower
# etc)
#
# By default a minimum millisecond threshold of 10ms is used.
#
# This tool uses kprobes to instrument the kernel for entry and exit
# information. Should work with 5.15 and above kernels.
#
# 08-Jan-2024   Meetakshi Setiya  Created this.

from __future__ import print_function
from time import strftime
from typing import Tuple
from bcc import BPF
import argparse
from datetime import datetime, timedelta

# symbols
kallsyms = "/proc/kallsyms"

# arguments
examples = """
    ./smbslower                 # trace smb operations slower than 10ms
    ./smbslower 1               # trace smb operations slower than 1ms
    ./smbslower -j 1            # ... 1 ms, parsable output (csv)
    ./smbslower 0               # trace all smb operations
    ./smbslower -p 684          # trace pid 684 only
    ./smbslower -c 5            # trace smb operation 5 (0x0005 SMB2_CREATE) only
    ./smbslower -d 10           #trace for 10 seconds only
"""
argparser = argparse.ArgumentParser(
    description="""Trace all SMB operations slower than a threshold, \
supports SMB2+.
""",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

argparser.add_argument("-p", "--pid", help="Trace this pid only")
argparser.add_argument("-c", "--cid", help="Trace this command only")
argparser.add_argument("min_ms", nargs="?", default='10',
                       help="Minimum IO duration to trace in ms (default=10ms)")
argparser.add_argument("-d", "--duration",
                       help="total duration of trace in seconds")
argparser.add_argument("-j", "--csv", action="store_true",
                       help="just print fields: comma-separated values")
argparser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = argparser.parse_args()
min_ms = int(args.min_ms)
pid = args.pid
cid = args.cid
csv = args.csv
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# for reverse lookup
smb_commands = {
    '0x0000': "SMB2_NEGOTIATE",
    '0x0001': "SMB2_SESSION_SETUP",
    '0x0002': "SMB2_LOGOFF",
    '0x0003': "SMB2_TREE_CONNECT",
    '0x0004': "SMB2_TREE_DISCONNECT",
    '0x0005': "SMB2_CREATE",
    '0x0006': "SMB2_CLOSE",
    '0x0007': "SMB2_FLUSH",
    '0x0008': "SMB2_READ",
    '0x0009': "SMB2_WRITE",
    '0x000A': "SMB2_LOCK",
    '0x000B': "SMB2_IOCTL",
    '0x000C': "SMB2_CANCEL",
    '0x000D': "SMB2_ECHO",
    '0x000E': "SMB2_QUERY_DIRECTORY",
    '0x000F': "SMB2_CHANGE_NOTIFY",
    '0x0010': "SMB2_QUERY_INFO",
    '0x0011': "SMB2_SET_INFO",
    '0x0012': "SMB2_OPLOCK_BREAK",
    '0x0013': "SMB2_SERVER_TO_CLIENT_NOTIFICATION"
}

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/types.h>
#include <linux/kref.h>

// mid_q_entry and smb2_hdr are struct definitions copied from the cifs 
// client. verified to work with kernels 5.15+
struct mid_q_entry {
	struct list_head qhead;
	struct kref refcount;
	void *server;
	__u64 mid;	
	__u16 credits;	
	__u16 credits_received;
	__u32 pid;
	__u32 sequence_number; 
	unsigned long when_alloc; 
#ifdef CONFIG_CIFS_STATS2
	unsigned long when_sent;
	unsigned long when_received;
#endif
	void *receive;
	void *callback;
	void *handle;
	void *callback_data; 
	void *creator;
	void *resp_buf;
	unsigned int resp_buf_size;
	int mid_state;
	unsigned int mid_flags;
	__le16 command;
	unsigned int optype;
	bool large_buf:1;
	bool multiRsp:1;
	bool multiEnd:1;
	bool decrypted:1;
};

struct smb2_hdr {
	__le32 ProtocolId;
	__le16 StructureSize;
	__le16 CreditCharge;
	__le32 Status;
	__le16 Command;
	__le16 CreditRequest;
	__le32 Flags;
	__le32 NextCommand;
	__le64 MessageId;
	union {
		struct {
			__le32 ProcessId;
			__le32  TreeId;
		} __packed SyncId;
		__le64  AsyncId;
	} __packed Id;
	__le64  SessionId;
	__u8   Signature[16];
} __packed;

struct headerinfo_t {
    u64 session_id;
    u64 id;
    u64 mid;
    u16 smbcommand;
    char is_compounded;
    char is_async;
};

struct val_t {
    u64 when_alloc;
    char task[TASK_COMM_LEN];
    struct headerinfo_t shdr;
};

struct data_t {
    u64 when_release;
    u64 delta_us;
    u32 pid;
    u16 smbcommand;
    u64 session_id;
    u64 id;
    char task[TASK_COMM_LEN];
    char is_compounded;
    char is_async;
};

static inline int system_endianness() {
    int n = 1;
    return (*(char *)&n == 1) ? 0 : 1; //0 for little endian, 1 for big endian
}

static inline u16 le_to_sys16(u16 x) {
	//check system's endianness
    if(system_endianness() == 0) {
		return x;
	}
	//big endian
    return ((x>>8)&0xff) | // Move byte 1 to byte 0
           ((x<<8)&0xff00); // Move byte 0 to byte 1
}

static inline u32 le_to_sys32(u32 x) {
    if(system_endianness() == 0) {
        return x;
    }
    //big endian
    return ((x>>24)&0xff) |
           ((x<<8)&0xff0000) |
           ((x>>8)&0xff00) |
           ((x<<24)&0xff000000);
}

static inline u64 le_to_sys64(u64 x) {
    if(system_endianness() == 0) {
        return x;
    }
    //big endian
    return ((x>>56)&0xff) |
           ((x<<40)&0xff000000000000) |
           ((x<<24)&0xff0000000000) |
           ((x<<8)&0xff00000000) |
           ((x>>8)&0xff000000) |
           ((x>>24)&0xff0000) |
           ((x>>40)&0xff00) |
           ((x<<56)&0xff00000000000000);
}

static inline u32 sys_to_le32(u32 x) {
    return le_to_sys32(x);
}

# define SMB2_FLAGS_ASYNC_COMMAND sys_to_le32(0x00000002)

BPF_HASH(shdrinfo, u64, struct headerinfo_t);   //pid:headerinfo
BPF_HASH(entryinfo, struct mid_q_entry *, struct val_t);    //&mid_q_entry:val_t
BPF_PERF_OUTPUT(events);

// kprobe into smb2_mid_entry_alloc and get the session details
int trace_smb_mid_alloc_entry(struct pt_regs *ctx, struct smb2_hdr *shdr) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u16 cid = le_to_sys16(shdr->Command);

    if (FILTER_PID || FILTER_CID) {
        return 0;
    }

    struct headerinfo_t headerinfo = {};
    headerinfo.session_id = le_to_sys64(shdr->SessionId);
    headerinfo.smbcommand = cid;
    headerinfo.mid = le_to_sys64(shdr->MessageId);
    if (shdr->NextCommand != 0)
        headerinfo.is_compounded = 1;
    else 
        headerinfo.is_compounded = 0;
    if (shdr->Flags & SMB2_FLAGS_ASYNC_COMMAND) {
        headerinfo.id = le_to_sys64(shdr->Id.AsyncId);
        headerinfo.is_async = 1;
    }
    else {
        headerinfo.id = le_to_sys32(shdr->Id.SyncId.TreeId);
        headerinfo.is_async = 0;
    }

    shdrinfo.update(&id, &headerinfo);
    return 0;
}

//kretprobe into smb2_mid_entry_alloc and get the time
int trace_smb_mid_alloc_exit(struct pt_regs *ctx) {
    struct mid_q_entry *mid_struct = (struct mid_q_entry *)PT_REGS_RC(ctx);
    u64 id = bpf_get_current_pid_tgid();
    u16 cid = le_to_sys16(mid_struct->command);
    u32 pid = mid_struct->pid;
    struct val_t val = {};

    struct headerinfo_t *shdr;
    shdr = shdrinfo.lookup(&id);

    if (shdr == 0) {
        //missed tracing issue or filtered
        return 0;
    }

    shdrinfo.delete(&id);

    if (shdr->mid != mid_struct->mid || shdr->smbcommand != cid) {
        // should not happen, else we likely have an algorithmic problem here
        val.when_alloc = 0;
        return 0;
    }

    val.when_alloc = bpf_ktime_get_ns();
    val.shdr = *shdr;
    bpf_get_current_comm(&val.task, sizeof(val.task));
    entryinfo.update(&mid_struct, &val); //ptr to mid struct is our key
	return 0;
}

static inline int trace_release_mid(struct pt_regs *ctx, struct mid_q_entry *mid_struct) {
    struct val_t *valp;
    valp = entryinfo.lookup(&mid_struct);

    if (valp == 0) {
        //missed tracing issue or filtered
        return 0;
    }

    //find delta
    u64 when_release = bpf_ktime_get_ns();
    u64 delta = (when_release - valp->when_alloc) / NSEC_PER_USEC;
    entryinfo.delete(&mid_struct);
    
    //filter by time
    if (FILTER_DELTA) {
        return 0;
    }

    struct data_t data = {};
    data.when_release = when_release/NSEC_PER_USEC;
    data.delta_us = delta;
    data.pid = mid_struct->pid;
    data.smbcommand = valp->shdr.smbcommand;
    data.session_id = valp->shdr.session_id;
    data.is_compounded = valp->shdr.is_compounded;
    data.is_async = valp->shdr.is_async;
    data.id = valp->shdr.id;
    memcpy(data.task, valp->task, sizeof(data.task));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

//for backwards compatibility
int trace_cifs_mid_release_entry(struct pt_regs *ctx, struct mid_q_entry *midEntry) {
    return trace_release_mid(ctx, midEntry);
}

int trace_smb_mid_release_entry(struct pt_regs *ctx, struct kref *refcount) {
    const typeof( ((struct mid_q_entry *)0)->refcount ) *__mptr = (refcount);
    struct mid_q_entry *mid_struct = (struct mid_q_entry *)( (char *)__mptr - offsetof(struct mid_q_entry, refcount) );
    return trace_release_mid(ctx, mid_struct);
}
"""


def AttachProbesSMBNetworkCalls(kfn_name: str, handler: str) -> BPF:
    global bpf_text
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="smb2_mid_entry_alloc",
                    fn_name="trace_smb_mid_alloc_entry")
    b.attach_kretprobe(event="smb2_mid_entry_alloc",
                       fn_name="trace_smb_mid_alloc_exit")
    b.attach_kprobe(event=kfn_name, fn_name=handler)
    return b


def AddFilters():
    global bpf_text
    if min_ms == 0:
        if not csv:
            print("Tracing SMB operations.")
        bpf_text = bpf_text.replace('FILTER_DELTA', '0')
    else:
        if not csv:
            print("Tracing SMB operations that are slower than %d ms." % min_ms)
        bpf_text = bpf_text.replace(
            'FILTER_DELTA', 'delta <= %s' % str(min_ms * 1000))

    if args.pid:
        if not csv:
            print("Tracing SMB operations for pid %s." % args.pid)
        bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % pid)
    else:
        bpf_text = bpf_text.replace('FILTER_PID', '0')

    if args.cid:
        if not csv:
            print("Tracing SMB operations for command %s." % args.cid)
        bpf_text = bpf_text.replace('FILTER_CID', 'cid != %s' % cid)
    else:
        bpf_text = bpf_text.replace('FILTER_CID', '0')

    if args.ebpf or debug:
        print(bpf_text)
        if args.ebpf:
            exit()


def GetSMBMidReleaseSymbolName() -> Tuple[str, str]:
    global bpf_text

    # code replacements
    with open(kallsyms) as syms:
        kfn_name = ''
        handler = ''
        for line in syms:
            a = line.rstrip().split()
            (_, kfn_name) = (a[0], a[2])
            kfn_name = kfn_name.split("\t")[0]
            if kfn_name == "__release_mid":
                handler = "trace_smb_mid_release_entry"
                break
            elif kfn_name == "cifs_mid_q_entry_release":
                handler = "trace_cifs_mid_release_entry"
                break
        if handler == '':
            print(
                "ERROR: no __release_mid or cifs_mid_q_entry_release in /proc/kallsyms. Exiting")
            print("HINT: your kernel might be older than v5.15")
            exit()
    return (kfn_name, handler)


def PrintSlowerOutput(b: BPF):
    def print_event_network(cpu, data, size):
        event = b["events"].event(data)
        command = smb_commands.get('0x{:04X}'.format(
            event.smbcommand), str(event.smbcommand))
        task = event.task.decode('utf-8', 'replace')
        if csv:
            print("%d,%s,%d,%s,%d,%s,%d,%d,%d" % (event.when_release,
                                                  task,
                                                  event.pid,
                                                  command, 
                                                  event.delta_us, 
                                                  hex(event.session_id),
                                                  ord(event.is_compounded), 
                                                  ord(event.is_async),
                                                  event.id))

        else:
            print("%-8s %-14s %-7d %-25s %-16.3f %-16s %12s %12s %12s" % (
                                                    strftime("%H:%M:%S"),
                                                    task,
                                                    event.pid,
                                                    command, 
                                                    float(event.delta_us)/1000,
                                                    hex(event.session_id),
                                                    ord(event.is_compounded), ord(event.is_async),
                                                    event.id))

    b["events"].open_perf_buffer(print_event_network, page_cnt=64)
    start_time = datetime.now()
    while not args.duration or datetime.now() - start_time < args.duration:
        try:
            b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            exit()


def TraceSMBNetworkCalls():
    global bpf_text
    (kfn_name, handler) = GetSMBMidReleaseSymbolName()
    AddFilters()
    b = AttachProbesSMBNetworkCalls(kfn_name, handler)
    if csv:
        print("ENDTIME_us,TASK,PID,TYPE,LATENCY_us,SESSIONID,COMPOUND_RQST,ASYNC_RQST,TREEID/ASYNCID,")
    else:
        print("%-8s %-14s %-7s %-25s %-17s %-16s %5s %5s %5s" % ("ENDTIME", "TASK", "PID", "TYPE", "LATENCY(ms)", "SESSIONID", "COMPOUND_RQST", "ASYNC_RQST", "TREE_ID/ASYNC_ID"))
    PrintSlowerOutput(b)


TraceSMBNetworkCalls()
