#!/usr/bin/env python3
# @lint-avoid-python-3-compatibility-imports
#
# smbvfsslower      Trace slow VFS callbacks for SMB
#                   operations for Linux using BCC & eBPF
#
# Usage: smbvfsslower.py [-h] [-j] [-p PID] [-d DURATION] [--inode] [--file]
# [--adspace] [--super] [min_us]
#
# This script traces all VFS callbacks for SMB. It measures the time spent in 
# these operations, and prints details for each that exceeded a threshold.
#
# WARNING: This adds low-overhead instrumentation to the smb operations.
# If these operations are very frequent (depending on the workload; eg, 1M/sec),
# the overhead of this tool (even if it prints no "slower" events) could be 
# significant.
#
# Some of this code is copied from similar tools (ext4slower, nfsslower
# etc)
#
# This is a generic script to trace all possible SMB VFS callbacks. By default # a minimum threshold of 10ms is used.
# 
# 08-Jan-2024   Meetakshi Setiya  Created this.

from __future__ import print_function
from time import strftime
from bcc import BPF
import argparse
from datetime import datetime, timedelta

examples = """
    ./smbvfsslower                      # trace smb operations slower than 10ms
    ./smbvfsslower 1                    # trace smb operations slower than 1ms
    ./smbvfsslower -j 1                 # ... 1 ms, parsable output (csv)
    ./smbvfsslower 0                    # trace all smb operations
    ./smbvfsslower -p 684               # trace pid 684 only
    ./smbvfsslower -d 10                # trace for 10 seconds only
    ./smbvfsslower --inode --super      # trace inode and superblock operations 
"""

argparser = argparse.ArgumentParser(
    description="""Trace latency during VFS callbacks for SMB operations. \
Supports SMB2+.
""",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)

argparser.add_argument("-p", "--pid", help="Trace this pid only")
argparser.add_argument("min_ms", nargs="?", default='10',
                       help="Minimum IO duration to trace in ms (default=10ms)")
argparser.add_argument("-d", "--duration",
                       help="total duration of trace in seconds")
argparser.add_argument("-j", "--csv", action="store_true",
                       help="just print fields: comma-separated values")
argparser.add_argument("--inode", action="store_true",
                       help="trace inode operations only")
argparser.add_argument("--file", action="store_true",
                       help="trace file operations only")
argparser.add_argument("--adspace", action="store_true",
                       help="trace address space operations only")
argparser.add_argument("--super", action="store_true",
                       help="trace superblock operations only")
argparser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = argparser.parse_args()
min_ms = int(args.min_ms)
pid = args.pid
csv = args.csv
inode = args.inode
file = args.file
adspace = args.adspace
superblock = args.super
debug = 0
if args.duration:
    args.duration = timedelta(seconds=int(args.duration))

# smb2 callbacks for file structure operations and helper functions to be executed on respective retprobes
file_operations = """
	#define cifs_loose_read_iter F0,
	#define cifs_file_write_iter F1,
	#define cifs_open F2,
	#define cifs_close F3,
	#define cifs_lock F4,
	#define cifs_flock F5,
	#define cifs_fsync F6,
	#define cifs_flush F7,
	#define cifs_file_mmap F8,
	#define filemap_splice_read F9,
	#define iter_file_splice_write F10,
	#define cifs_llseek F11,
	#define cifs_ioctl F12,
	#define cifs_copy_file_range F13,
	#define cifs_remap_file_range F14,
	#define cifs_setlease F15,
	#define cifs_fallocate F16,

    #define cifs_strict_readv F17,
    #define cifs_strict_writev F18,
    #define cifs_strict_fsync F19,
    #define cifs_file_strict_mmap F20,

    #define cifs_direct_readv F21,
    #define cifs_direct_writev F22,
    #define copy_splice_read F23,

    #define cifs_readdir F24,
    #define cifs_closedir F25,
    #define generic_read_dir F26,
    #define generic_file_llseek F27,
    #define cifs_dir_fsync F28,

int trace_file_loose_read_iter_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_loose_read_iter));
}

int trace_file_file_write_iter_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_file_write_iter));
}

int trace_file_open_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_open));
}

int trace_file_close_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_close));
}

int trace_file_lock_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_lock));
}

int trace_file_flock_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_flock));
}

int trace_file_fsync_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_fsync));
}

int trace_file_flush_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_flush));
}

int trace_file_file_mmap_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_file_mmap));
}

int trace_file_filemap_splice_read_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(filemap_splice_read));
}

int trace_file_iter_file_splice_write_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(iter_file_splice_write));
}

int trace_file_llseek_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_llseek));
}

int trace_file_ioctl_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_ioctl));
}

int trace_file_copy_file_range_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_copy_file_range));
}

int trace_file_remap_file_range_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_remap_file_range));
}

int trace_file_setlease_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_setlease));
}

int trace_file_fallocate_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_fallocate));
}

int trace_file_strict_readv_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_strict_readv));
}

int trace_file_strict_writev_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_strict_writev));
}

int trace_file_strict_fsync_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_strict_fsync));
}

int trace_file_file_strict_mmap_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_file_strict_mmap));
}

int trace_file_direct_readv_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_direct_readv));
}

int trace_file_direct_writev_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_direct_writev));
}

int trace_file_copy_splice_read_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(copy_splice_read));
}

int trace_file_readdir_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_readdir));
}

int trace_file_closedir_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_closedir));
}

int trace_file_generic_read_dir_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(generic_read_dir));
}

int trace_file_generic_file_llseek_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(generic_file_llseek));
}

int trace_file_dir_fsync_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "FILE", STR(cifs_dir_fsync));
}
"""

# smb2 callbacks for inode operations and helper functions to be executed on respective retprobes
inode_operations = """
#define cifs_create I0
#define cifs_atomic_open I1 
#define cifs_lookup I2
#define cifs_getattr I3
#define cifs_unlink I4
#define cifs_hardlink I5
#define cifs_mkdir I6
#define cifs_rmdir I7
#define cifs_rename2 I8
#define cifs_permission I9
#define cifs_setattr I10
#define cifs_symlink I11
#define cifs_mknod I12
#define cifs_listxattr I13 
#define cifs_get_acl I14
#define cifs_set_acl I15
#define cifs_fiemap I16
#define cifs_get_link I17

int trace_inode_create_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_create));
}

int trace_inode_atomic_open_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_atomic_open));
}

int trace_inode_lookup_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_lookup));
}

int trace_inode_getattr_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_getattr));
}

int trace_inode_unlink_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_unlink));
}

int trace_inode_hardlink_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_hardlink));
}

int trace_inode_mkdir_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_mkdir));
}

int trace_inode_rmdir_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_rmdir));
}

int trace_inode_rename2_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_rename2));
}

int trace_inode_permission_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_permission));
}

int trace_inode_setattr_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_setattr));
}

int trace_inode_symlink_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_symlink));
}

int trace_inode_mknod_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_mknod));
}

int trace_inode_listxattr_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_listxattr));
}

int trace_inode_get_acl_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_get_acl));
}

int trace_inode_set_acl_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_set_acl));
}

int trace_inode_fiemap_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_fiemap));
}

int trace_inode_get_link_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "INODE", STR(cifs_get_link));
}
"""

# smb2 callbacks for address space operations and helper functions to be executed on respective retprobes
address_space_operations = """
#define cifs_read_folio A0
#define cifs_readahead A1
#define cifs_writepages A2
#define cifs_write_begin A3
#define cifs_write_end A4
#define cifs_dirty_folio A5
#define cifs_release_folio A6
#define cifs_direct_io A7
#define cifs_invalidate_folio A8
#define cifs_launder_folio A9
#define filemap_migrate_folio A10
#define cifs_swap_activate A11
#define cifs_swap_deactivate A12

int trace_adspace_read_folio_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_read_folio));
}

int trace_adspace_readahead_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_readahead));
}

int trace_adspace_writepages_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_writepages));
}

int trace_adspace_write_begin_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_write_begin));
}

int trace_adspace_write_end_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_write_end));
}

int trace_adspace_dirty_folio_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_dirty_folio));
}

int trace_adspace_release_folio_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_release_folio));
}

int trace_adspace_direct_io_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_direct_io));
}

int trace_adspace_invalidate_folio_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_invalidate_folio));
}

int trace_adspace_launder_folio_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_launder_folio));
}

int trace_adspace_migrate_folio_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(filemap_migrate_folio));
}

int trace_adspace_swap_activate_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_swap_activate));
}

int trace_adspace_swap_deactivate_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "ADSPACE", STR(cifs_swap_deactivate));
}
"""

# smb2 callbacks for super block operations and helper functions to be executed on respective retprobes
super_block_operations = """
#define cifs_statfs S0
#define cifs_alloc_inode S1 
#define cifs_write_inode S2
# define cifs_free_inode S3
# define cifs_drop_inode S4
# define cifs_evict_inode S5
# define cifs_show_devname S6
# define cifs_show_options S7
# define cifs_umount_begin S8
# define cifs_freeze S9

int trace_super_statfs_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_statfs));
}

int trace_super_alloc_inode_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_alloc_inode));
}

int trace_super_write_inode_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_write_inode));
}

int trace_super_free_inode_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_free_inode));
}

int trace_super_drop_inode_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_drop_inode));
}

int trace_super_evict_inode_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_evict_inode));
}

int trace_super_show_devname_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_show_devname));
}

int trace_super_show_options_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_show_options));
}

int trace_super_umount_begin_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_umount_begin));
}

int trace_super_freeze_exit(struct pt_regs *ctx) {
    return trace_all_vfs_exit(ctx, "SUPER", STR(cifs_freeze));
}
"""

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/types.h>
#include <linux/kref.h>
#include <linux/sched.h>

#define STR(x) #x 
#define MAX_OP_TYPE_LENGTH 10
#define MAX_FUNCTION_LENGTH 30

BPF_HASH(entryinfo);    //pid:timestamp
BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u64 latency_us;
    u64 when_release;
    char type[MAX_OP_TYPE_LENGTH];
    char function[MAX_FUNCTION_LENGTH];
    char task[TASK_COMM_LEN];
};

static inline void copy_string(char destination[], const char source[]) {
    int i = 0;
    while(source[i]) {
        destination[i] = source[i];
        i++;
    }
    destination[i] = 0;
}

// common function to be executed on kprobe into all vfs callbacks
int trace_all_vfs_entry(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part

    if(FILTER_PID)
        return 0;

    // just store the timestamp
    u64 start = bpf_ktime_get_ns();
    entryinfo.update(&id, &start);

    return 0;    
}

// helper that gets called by functions to be executed on retprobe into all vfs
// callbacks
static inline int trace_all_vfs_exit(struct pt_regs *ctx, const char type[], const char fn_name[]) {
    struct val_t *valp;
    u64 id = bpf_get_current_pid_tgid();

    u64 *when_start = entryinfo.lookup(&id);
    if (when_start == 0) {
        //missed tracing issue or filtered
        return 0;
    }

    entryinfo.delete(&id);
    u64 when_end = bpf_ktime_get_ns();
    u64 delta = (when_end - *when_start) / NSEC_PER_USEC;

    //filter by time
    if (FILTER_DELTA) {
        return 0;
    }

    struct data_t data = {};
    copy_string(data.type, type);
    copy_string(data.function, fn_name);
    data.pid = id >> 32;
    data.latency_us = delta;
    data.when_release = when_end / NSEC_PER_USEC;
    bpf_get_current_comm(&data.task, sizeof(data.task));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# attach kprobes to file structure callbacks
def AttachProbesSMBVFSFileOperations(b: BPF) -> BPF:
    b.attach_kprobe(event="cifs_loose_read_iter", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_loose_read_iter", fn_name="trace_file_loose_read_iter_exit")

    b.attach_kprobe(event="cifs_file_write_iter", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_file_write_iter", fn_name="trace_file_file_write_iter_exit")

    b.attach_kprobe(event="cifs_open", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_open", fn_name="trace_file_open_exit")

    b.attach_kprobe(event="cifs_close", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_close", fn_name="trace_file_close_exit")

    b.attach_kprobe(event="cifs_lock", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_lock", fn_name="trace_file_lock_exit")

    b.attach_kprobe(event="cifs_flock", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_flock", fn_name="trace_file_flock_exit")

    b.attach_kprobe(event="cifs_fsync", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_fsync", fn_name="trace_file_fsync_exit")

    b.attach_kprobe(event="cifs_flush", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_flush", fn_name="trace_file_flush_exit")

    b.attach_kprobe(event="cifs_file_mmap", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_file_mmap", fn_name="trace_file_file_mmap_exit")

    b.attach_kprobe(event="filemap_splice_read", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="filemap_splice_read", fn_name="trace_file_filemap_splice_read_exit")

    b.attach_kprobe(event="iter_file_splice_write", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="iter_file_splice_write", fn_name="trace_file_iter_file_splice_write_exit")

    b.attach_kprobe(event="cifs_llseek", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_llseek", fn_name="trace_file_llseek_exit")

    b.attach_kprobe(event="cifs_ioctl", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_ioctl", fn_name="trace_file_ioctl_exit")

    b.attach_kprobe(event="cifs_copy_file_range", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_copy_file_range", fn_name="trace_file_copy_file_range_exit")

    b.attach_kprobe(event="cifs_remap_file_range", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_remap_file_range", fn_name="trace_file_remap_file_range_exit")

    b.attach_kprobe(event="cifs_setlease", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_setlease", fn_name="trace_file_setlease_exit")

    b.attach_kprobe(event="cifs_fallocate", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_fallocate", fn_name="trace_file_fallocate_exit")

    b.attach_kprobe(event="cifs_strict_readv", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_strict_readv", fn_name="trace_file_strict_readv_exit")

    b.attach_kprobe(event="cifs_strict_writev", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_strict_writev", fn_name="trace_file_strict_writev_exit")

    b.attach_kprobe(event="cifs_strict_fsync", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_strict_fsync", fn_name="trace_file_strict_fsync_exit")

    b.attach_kprobe(event="cifs_file_strict_mmap", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_file_strict_mmap", fn_name="trace_file_file_strict_mmap_exit")

    b.attach_kprobe(event="cifs_direct_readv", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_direct_readv", fn_name="trace_file_direct_readv_exit")

    b.attach_kprobe(event="cifs_direct_writev", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_direct_writev", fn_name="trace_file_direct_writev_exit")

    b.attach_kprobe(event="copy_splice_read", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="copy_splice_read", fn_name="trace_file_copy_splice_read_exit")

    b.attach_kprobe(event="cifs_readdir", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_readdir", fn_name="trace_file_readdir_exit")

    b.attach_kprobe(event="cifs_closedir", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_closedir", fn_name="trace_file_closedir_exit")

    b.attach_kprobe(event="generic_read_dir", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="generic_read_dir", fn_name="trace_file_generic_read_dir_exit")

    b.attach_kprobe(event="generic_file_llseek", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="generic_file_llseek", fn_name="trace_file_generic_file_llseek_exit")

    b.attach_kprobe(event="cifs_dir_fsync", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_dir_fsync", fn_name="trace_file_dir_fsync_exit")

    return b

# attach kprobes to inode callbacks
def AttachProbesSMBVFSInodeOperations(b: BPF) -> BPF:
    b.attach_kprobe(event="cifs_create", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_create", fn_name="trace_inode_create_exit")

    b.attach_kprobe(event="cifs_atomic_open", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_atomic_open", fn_name="trace_inode_atomic_open_exit")

    b.attach_kprobe(event="cifs_lookup", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_lookup", fn_name="trace_inode_lookup_exit")

    b.attach_kprobe(event="cifs_getattr", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_getattr", fn_name="trace_inode_getattr_exit")

    b.attach_kprobe(event="cifs_unlink", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_unlink", fn_name="trace_inode_unlink_exit")

    b.attach_kprobe(event="cifs_hardlink", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_hardlink", fn_name="trace_inode_hardlink_exit")

    b.attach_kprobe(event="cifs_mkdir", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_mkdir", fn_name="trace_inode_mkdir_exit")

    b.attach_kprobe(event="cifs_rmdir", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_rmdir", fn_name="trace_inode_rmdir_exit")

    b.attach_kprobe(event="cifs_rename2", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_rename2", fn_name="trace_inode_rename2_exit")

    b.attach_kprobe(event="cifs_permission", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_permission", fn_name="trace_inode_permission_exit")

    b.attach_kprobe(event="cifs_setattr", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_setattr", fn_name="trace_inode_setattr_exit")

    b.attach_kprobe(event="cifs_symlink", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_symlink", fn_name="trace_inode_symlink_exit")

    b.attach_kprobe(event="cifs_mknod", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_mknod", fn_name="trace_inode_mknod_exit")

    b.attach_kprobe(event="cifs_listxattr", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_listxattr", fn_name="trace_inode_listxattr_exit")

    b.attach_kprobe(event="cifs_get_acl", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_get_acl", fn_name="trace_inode_get_acl_exit")

    b.attach_kprobe(event="cifs_set_acl", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_set_acl", fn_name="trace_inode_set_acl_exit")

    b.attach_kprobe(event="cifs_fiemap", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_fiemap", fn_name="trace_inode_fiemap_exit")

    b.attach_kprobe(event="cifs_get_link", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_get_link", fn_name="trace_inode_get_link_exit")
    
    return b

# attach kprobes to address space callbacks
def AttachProbesSMBVFSAddressSpaceOperations(b: BPF) -> BPF:
    b.attach_kprobe(event="cifs_read_folio", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_read_folio",
                       fn_name="trace_adspace_read_folio_exit")

    b.attach_kprobe(event="cifs_readahead", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_readahead",
                       fn_name="trace_adspace_readahead_exit")

    b.attach_kprobe(event="cifs_writepages", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_writepages",
                       fn_name="trace_adspace_writepages_exit")

    b.attach_kprobe(event="cifs_write_begin", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_write_begin",
                       fn_name="trace_adspace_write_begin_exit")

    b.attach_kprobe(event="cifs_write_end", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_write_end",
                       fn_name="trace_adspace_write_end_exit")

    b.attach_kprobe(event="cifs_dirty_folio", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_dirty_folio",
                       fn_name="trace_adspace_dirty_folio_exit")

    b.attach_kprobe(event="cifs_release_folio", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_release_folio",
                       fn_name="trace_adspace_release_folio_exit")

    b.attach_kprobe(event="cifs_direct_io", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_direct_io",
                       fn_name="trace_adspace_direct_io_exit")

    b.attach_kprobe(event="cifs_invalidate_folio",
                    fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_invalidate_folio",
                       fn_name="trace_adspace_invalidate_folio_exit")

    b.attach_kprobe(event="cifs_launder_folio", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_launder_folio",
                       fn_name="trace_adspace_launder_folio_exit")

    b.attach_kprobe(event="filemap_migrate_folio",
                    fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="filemap_migrate_folio",
                       fn_name="trace_adspace_migrate_folio_exit")

    b.attach_kprobe(event="cifs_swap_activate", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_swap_activate",
                       fn_name="trace_adspace_swap_activate_exit")

    b.attach_kprobe(event="cifs_swap_deactivate", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_swap_deactivate",
                       fn_name="trace_adspace_swap_deactivate_exit")

    return b

# attach kprobes to super block callbacks
def AttachProbesSMBVFSSuperBlockOperations(b: BPF) -> BPF:
    b.attach_kprobe(event="cifs_statfs", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_statfs", fn_name="trace_super_statfs_exit")

    b.attach_kprobe(event="cifs_alloc_inode", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_alloc_inode",
                       fn_name="trace_super_alloc_inode_exit")

    b.attach_kprobe(event="cifs_write_inode", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_write_inode",
                       fn_name="trace_super_write_inode_exit")

    b.attach_kprobe(event="cifs_free_inode", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_free_inode",
                       fn_name="trace_super_free_inode_exit")

    b.attach_kprobe(event="cifs_drop_inode", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_drop_inode",
                       fn_name="trace_super_drop_inode_exit")

    b.attach_kprobe(event="cifs_evict_inode", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_evict_inode",
                       fn_name="trace_super_evict_inode_exit")

    b.attach_kprobe(event="cifs_show_devname", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_show_devname",
                       fn_name="trace_super_show_devname_exit")

    b.attach_kprobe(event="cifs_show_options", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_show_options",
                       fn_name="trace_super_show_options_exit")

    b.attach_kprobe(event="cifs_umount_begin", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_umount_begin",
                       fn_name="trace_super_umount_begin_exit")

    b.attach_kprobe(event="cifs_freeze", fn_name="trace_all_vfs_entry")
    b.attach_kretprobe(event="cifs_freeze", fn_name="trace_super_freeze_exit")

    return b

# selectively attach probes if mode selected
def AttachProbesSMBVFSCallbacks() -> BPF:
    global bpf_text
    bpf_text = bpf_text + file_operations + address_space_operations + \
        super_block_operations + inode_operations
    b = BPF(text=bpf_text)
    if inode:
        if not csv:
            print("Tracing SMB VFS inode operations.")
        b = AttachProbesSMBVFSInodeOperations(b)
    if file:
        if not csv:
            print("Tracing SMB VFS file operations.")
        b = AttachProbesSMBVFSFileOperations(b)
    if adspace:
        if not csv:
            print("Tracing SMB VFS address space operations.")
        b = AttachProbesSMBVFSAddressSpaceOperations(b)
    if superblock:
        if not csv:
            print("Tracing SMB VFS superblock operations.")
        b = AttachProbesSMBVFSSuperBlockOperations(b)
    if not inode and not file and not adspace and not superblock:
        b = AttachProbesSMBVFSFileOperations(b)
        b = AttachProbesSMBVFSInodeOperations(b)
        b = AttachProbesSMBVFSAddressSpaceOperations(b)
        b = AttachProbesSMBVFSSuperBlockOperations(b)

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

    if args.ebpf or debug:
        print(bpf_text)
        if args.ebpf:
            exit()


def PrintSlowerOutput(b: BPF):
    def print_event_vfs(cpu, data, size):
        event = b["events"].event(data)
        op_type = event.type.decode('utf-8')
        fn_name = event.function.decode('utf-8')
        if csv:
            print("%d,%s,%d,%s,%s,%d" % (event.when_release,
                                        event.task.decode('utf-8', 'replace'), event.pid,
                                        op_type,
                                        fn_name,
                                        event.latency_us))
        else:
            print("%-10s %-20s %-7d %-10s %-25s %-7.3f" % (
                                        strftime("%H:%M:%S"),
                                        event.task.decode('utf-8','replace'),
                                        event.pid,
                                        op_type,
                                        fn_name,
                                        float(event.latency_us)/1000))

    b["events"].open_perf_buffer(print_event_vfs, page_cnt=64)
    start_time = datetime.now()
    while not args.duration or datetime.now() - start_time < args.duration:
        try:
            b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            exit()


def TraceSMBVFSCallbacks():
    global bpf_text
    AddFilters()
    b = AttachProbesSMBVFSCallbacks()
    if csv:
        print("ENDTIME_us,TASK,PID,TYPE,FUNCTION,LATENCY_us")
    else:
        print("%-10s %-20s %-7s %-10s %-25s %-7s" %
              ("ENDTIME", "TASK", "PID", "TYPE", "FUNCTION", "LATENCY(ms)"))
    PrintSlowerOutput(b)


TraceSMBVFSCallbacks()
