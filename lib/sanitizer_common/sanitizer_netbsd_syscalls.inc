//===-- sanitizer_common_syscalls.inc ---------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Common syscalls handlers for tools like AddressSanitizer,
// ThreadSanitizer, MemorySanitizer, etc.
//
// This file should be included into the tool's interceptor file,
// which has to define it's own macros:
//   COMMON_SYSCALL_PRE_READ_RANGE
//          Called in prehook for regions that will be read by the kernel and
//          must be initialized.
//   COMMON_SYSCALL_PRE_WRITE_RANGE
//          Called in prehook for regions that will be written to by the kernel
//          and must be addressable. The actual write range may be smaller than
//          reported in the prehook. See POST_WRITE_RANGE.
//   COMMON_SYSCALL_POST_READ_RANGE
//          Called in posthook for regions that were read by the kernel. Does
//          not make much sense.
//   COMMON_SYSCALL_POST_WRITE_RANGE
//          Called in posthook for regions that were written to by the kernel
//          and are now initialized.
//   COMMON_SYSCALL_ACQUIRE(addr)
//          Acquire memory visibility from addr.
//   COMMON_SYSCALL_RELEASE(addr)
//          Release memory visibility to addr.
//   COMMON_SYSCALL_FD_CLOSE(fd)
//          Called before closing file descriptor fd.
//   COMMON_SYSCALL_FD_ACQUIRE(fd)
//          Acquire memory visibility from fd.
//   COMMON_SYSCALL_FD_RELEASE(fd)
//          Release memory visibility to fd.
//   COMMON_SYSCALL_PRE_FORK()
//          Called before fork syscall.
//   COMMON_SYSCALL_POST_FORK(long res)
//          Called after fork syscall.
//
// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!
//
// Generated with: generate_netbsd_syscalls.awk
// Generated date: 2017-12-16
// Generated from: syscalls.master,v 1.287 2017/12/08 01:19:29 christos Exp
//
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"
#if SANITIZER_NETBSD

#include "sanitizer_libc.h"

#define PRE_SYSCALL(name)                                                      \
  SANITIZER_INTERFACE_ATTRIBUTE void __sanitizer_syscall_pre_impl_##name
#define PRE_READ(p, s) COMMON_SYSCALL_PRE_READ_RANGE(p, s)
#define PRE_WRITE(p, s) COMMON_SYSCALL_PRE_WRITE_RANGE(p, s)

#define POST_SYSCALL(name)                                                     \
  SANITIZER_INTERFACE_ATTRIBUTE void __sanitizer_syscall_post_impl_##name
#define POST_READ(p, s) COMMON_SYSCALL_POST_READ_RANGE(p, s)
#define POST_WRITE(p, s) COMMON_SYSCALL_POST_WRITE_RANGE(p, s)

#ifndef COMMON_SYSCALL_ACQUIRE
#define COMMON_SYSCALL_ACQUIRE(addr) ((void)(addr))
#endif

#ifndef COMMON_SYSCALL_RELEASE
#define COMMON_SYSCALL_RELEASE(addr) ((void)(addr))
#endif

#ifndef COMMON_SYSCALL_FD_CLOSE
#define COMMON_SYSCALL_FD_CLOSE(fd) ((void)(fd))
#endif

#ifndef COMMON_SYSCALL_FD_ACQUIRE
#define COMMON_SYSCALL_FD_ACQUIRE(fd) ((void)(fd))
#endif

#ifndef COMMON_SYSCALL_FD_RELEASE
#define COMMON_SYSCALL_FD_RELEASE(fd) ((void)(fd))
#endif

#ifndef COMMON_SYSCALL_PRE_FORK
#define COMMON_SYSCALL_PRE_FORK()                                              \
  {}
#endif

#ifndef COMMON_SYSCALL_POST_FORK
#define COMMON_SYSCALL_POST_FORK(res)                                          \
  {}
#endif

// FIXME: do some kind of PRE_READ for all syscall arguments (int(s) and such).

extern "C" {
#define SYS_MAXSYSARGS 8
PRE_SYSCALL(syscall)(long code, long args[SYS_MAXSYSARGS]) {
  /* Nothing to do */
}
POST_SYSCALL(syscall)(long res, long code, long args[SYS_MAXSYSARGS]) {
  /* Nothing to do */
}
PRE_SYSCALL(exit)(long rval) { /* Nothing to do */ }
POST_SYSCALL(exit)(long res, long rval) { /* Nothing to do */ }
PRE_SYSCALL(fork)(void) { COMMON_SYSCALL_PRE_FORK(); }
POST_SYSCALL(fork)(long res) { COMMON_SYSCALL_POST_FORK(res); }
PRE_SYSCALL(read)(long fd, void *buf, long nbyte) {
  if (buf) {
    PRE_WRITE(buf, nbyte);
  }
}
POST_SYSCALL(read)(long res, long fd, void *buf, long nbyte) {}
PRE_SYSCALL(write)(long fd, void *buf, long nbyte) {
  if (buf) {
    PRE_READ(buf, nbyte);
  }
}
POST_SYSCALL(write)(long res, long fd, void *buf, long nbyte) {}
PRE_SYSCALL(open)(void *path, long flags, long mode) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(open)(long res, void *path, long flags, long mode) {}
PRE_SYSCALL(close)(long fd) { COMMON_SYSCALL_FD_CLOSE((int)fd); }
POST_SYSCALL(close)(long res, long fd) {}
PRE_SYSCALL(compat_50_wait4)
(long pid, void *status, long options, void *rusage) {
  /* Nothing to do */
}
POST_SYSCALL(compat_50_wait4)
(long res, long pid, void *status, long options, void *rusage) {}
PRE_SYSCALL(compat_43_ocreat)(void *path, long mode) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(compat_43_ocreat)(long res, void *path, long mode) {}
PRE_SYSCALL(link)(void *path, void *link) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
  if (link) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)link) + 1);
  }
}
POST_SYSCALL(link)(long res, void *path, void *link) {}
PRE_SYSCALL(unlink)(void *path) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(unlink)(long res, void *path) {}
/* syscall 11 has been skipped */
PRE_SYSCALL(chdir)(void *path) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(chdir)(long res, void *path) {}
PRE_SYSCALL(fchdir)(long fd) { /* Nothing to do */ }
POST_SYSCALL(fchdir)(long res, long fd) {}
PRE_SYSCALL(compat_50_mknod)(void *path, long mode, long dev) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(compat_50_mknod)(long res, void *path, long mode, long dev) {}
PRE_SYSCALL(chmod)(void *path, long mode) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(chmod)(long res, void *path, long mode) {}
PRE_SYSCALL(chown)(void *path, long uid, long gid) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(chown)(long res, void *path, long uid, long gid) {}
PRE_SYSCALL(break)(void *nsize) { /* Nothing to do */ }
POST_SYSCALL(break)(long res, void *nsize) {}
PRE_SYSCALL(compat_20_getfsstat)(void *buf, long bufsize, long flags) {
  /* Nothing to do */
}
POST_SYSCALL(compat_20_getfsstat)
(long res, void *buf, long bufsize, long flags) {}
PRE_SYSCALL(compat_43_olseek)(long fd, long offset, long whence) {
  /* Nothing to do */
}
POST_SYSCALL(compat_43_olseek)(long res, long fd, long offset, long whence) {}
PRE_SYSCALL(getpid)(void) { /* Nothing to do */ }
POST_SYSCALL(getpid)(long res) {}
PRE_SYSCALL(compat_40_mount)(void *type, void *path, long flags, void *data) {
  /* Nothing to do */
}
POST_SYSCALL(compat_40_mount)
(long res, void *type, void *path, long flags, void *data) {}
PRE_SYSCALL(unmount)(void *path, long flags) { /* Nothing to do */ }
POST_SYSCALL(unmount)(long res, void *path, long flags) {}
PRE_SYSCALL(setuid)(long uid) { /* Nothing to do */ }
POST_SYSCALL(setuid)(long res, long uid) {}
PRE_SYSCALL(getuid)(void) { /* Nothing to do */ }
POST_SYSCALL(getuid)(long res) {}
PRE_SYSCALL(geteuid)(void) { /* Nothing to do */ }
POST_SYSCALL(geteuid)(long res) {}
PRE_SYSCALL(ptrace)(long req, long pid, void *addr, long data) {
  if (req == ptrace_pt_io) {
    struct __sanitizer_ptrace_io_desc *piod =
        (struct __sanitizer_ptrace_io_desc *)addr;
    if (piod->piod_op == ptrace_piod_write_d ||
        piod->piod_op == ptrace_piod_write_i) {
      PRE_READ(piod->piod_addr, piod->piod_len);
    }
  } else if (req == ptrace_pt_set_event_mask) {
    PRE_READ(addr, struct_ptrace_ptrace_event_struct_sz);
  } else if (req == ptrace_pt_set_siginfo) {
    PRE_READ(addr, struct_ptrace_ptrace_siginfo_struct_sz);
  } else if (req == ptrace_pt_set_sigmask) {
    PRE_READ(addr, sizeof(__sanitizer_sigset_t));
  } else if (req == ptrace_pt_setregs) {
    PRE_READ(addr, struct_ptrace_reg_struct_sz);
  } else if (req == ptrace_pt_setfpregs) {
    PRE_READ(addr, struct_ptrace_fpreg_struct_sz);
  } else if (req == ptrace_pt_setdbregs) {
    PRE_READ(addr, struct_ptrace_dbreg_struct_sz);
  }
}
POST_SYSCALL(ptrace)(long res, long req, long pid, void *addr, long data) {}
PRE_SYSCALL(recvmsg)(long s, void *msg, long flags) {
  PRE_READ(msg, sizeof(__sanitizer_msghdr));
}
POST_SYSCALL(recvmsg)(long res, long s, void *msg, long flags) {}
PRE_SYSCALL(sendmsg)(long s, void *msg, long flags) { /* Nothing to do */ }
POST_SYSCALL(sendmsg)(long res, long s, void *msg, long flags) {}
PRE_SYSCALL(recvfrom)
(long s, void *buf, long len, long flags, void *from, void *fromlenaddr) {
  /* Nothing to do */
}
POST_SYSCALL(recvfrom)
(long res, long s, void *buf, long len, long flags, void *from,
  void *fromlenaddr) {}
PRE_SYSCALL(accept)(long s, void *name, void *anamelen) { /* Nothing to do */ }
POST_SYSCALL(accept)(long res, long s, void *name, void *anamelen) {}
PRE_SYSCALL(getpeername)(long fdes, void *asa, void *alen) {
  /* Nothing to do */
}
POST_SYSCALL(getpeername)(long res, long fdes, void *asa, void *alen) {}
PRE_SYSCALL(getsockname)(long fdes, void *asa, void *alen) {
  /* Nothing to do */
}
POST_SYSCALL(getsockname)(long res, long fdes, void *asa, void *alen) {}
PRE_SYSCALL(access)(void *path, long flags) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(access)(long res, void *path, long flags) {}
PRE_SYSCALL(chflags)(void *path, long flags) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(chflags)(long res, void *path, long flags) {}
PRE_SYSCALL(fchflags)(long fd, long flags) { /* Nothing to do */ }
POST_SYSCALL(fchflags)(long res, long fd, long flags) {}
PRE_SYSCALL(sync)(void) { /* Nothing to do */ }
POST_SYSCALL(sync)(long res) {}
PRE_SYSCALL(kill)(long pid, long signum) { /* Nothing to do */ }
POST_SYSCALL(kill)(long res, long pid, long signum) {}
PRE_SYSCALL(compat_43_stat43)(void *path, void *ub) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(compat_43_stat43)(long res, void *path, void *ub) {}
PRE_SYSCALL(getppid)(void) { /* Nothing to do */ }
POST_SYSCALL(getppid)(long res) {}
PRE_SYSCALL(compat_43_lstat43)(void *path, void *ub) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(compat_43_lstat43)(long res, void *path, void *ub) {}
PRE_SYSCALL(dup)(long fd) { /* Nothing to do */ }
POST_SYSCALL(dup)(long res, long fd) {}
PRE_SYSCALL(pipe)(void) { /* Nothing to do */ }
POST_SYSCALL(pipe)(long res) {}
PRE_SYSCALL(getegid)(void) { /* Nothing to do */ }
POST_SYSCALL(getegid)(long res) {}
PRE_SYSCALL(profil)(void *samples, long size, long offset, long scale) {
  /* Nothing to do */
}
POST_SYSCALL(profil)
(long res, void *samples, long size, long offset, long scale) {}
PRE_SYSCALL(ktrace)(void *fname, long ops, long facs, long pid) {
  /* Nothing to do */
}
POST_SYSCALL(ktrace)(long res, void *fname, long ops, long facs, long pid) {}
PRE_SYSCALL(compat_13_sigaction13)(long signum, void *nsa, void *osa) {
  struct __sanitizer_sigaction13 *nsa13 = (struct __sanitizer_sigaction13 *)nsa;
  if (nsa13) {
    PRE_READ(&nsa13->osa_handler, sizeof(nsa13->osa_handler));
    PRE_READ(&nsa13->osa_flags, sizeof(nsa13->osa_flags));
    PRE_READ(&nsa13->osa_mask, sizeof(nsa13->osa_mask));
  }
}
POST_SYSCALL(compat_13_sigaction13)
(long res, long signum, void *nsa, void *osa) {}
PRE_SYSCALL(getgid)(void) { /* Nothing to do */ }
POST_SYSCALL(getgid)(long res) {}
PRE_SYSCALL(compat_13_sigprocmask13)(long how, long mask) {
  /* Nothing to do */
}
POST_SYSCALL(compat_13_sigprocmask13)(long res, long how, long mask) {}
PRE_SYSCALL(__getlogin)(void *namebuf, long namelen) { /* Nothing to do */ }
POST_SYSCALL(__getlogin)(long res, void *namebuf, long namelen) {}
PRE_SYSCALL(__setlogin)(void *namebuf) {
  if (namebuf) {
    PRE_READ(namebuf, __sanitizer::internal_strlen((const char *)namebuf) + 1);
  }
}
POST_SYSCALL(__setlogin)(long res, void *namebuf) {}
PRE_SYSCALL(acct)(void *path) {
  if (path) {
    PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);
  }
}
POST_SYSCALL(acct)(long res, void *path) {}
PRE_SYSCALL(compat_13_sigpending13)(void) { /* Nothing to do */ }
POST_SYSCALL(compat_13_sigpending13)(long res) {}
PRE_SYSCALL(compat_13_sigaltstack13)(void *nss, void *oss) {}
POST_SYSCALL(compat_13_sigaltstack13)(long res, void *nss, void *oss) {}
PRE_SYSCALL(ioctl)(long fd, long com, void *data) {}
POST_SYSCALL(ioctl)(long res, long fd, long com, void *data) {}
PRE_SYSCALL(compat_12_oreboot)(long opt) {}
POST_SYSCALL(compat_12_oreboot)(long res, long opt) {}
PRE_SYSCALL(revoke)(void *path) {}
POST_SYSCALL(revoke)(long res, void *path) {}
PRE_SYSCALL(symlink)(void *path, void *link) {}
POST_SYSCALL(symlink)(long res, void *path, void *link) {}
PRE_SYSCALL(readlink)(void *path, void *buf, long count) {}
POST_SYSCALL(readlink)(long res, void *path, void *buf, long count) {}
PRE_SYSCALL(execve)(void *path, void *argp, void *envp) {}
POST_SYSCALL(execve)(long res, void *path, void *argp, void *envp) {}
PRE_SYSCALL(umask)(long newmask) {}
POST_SYSCALL(umask)(long res, long newmask) {}
PRE_SYSCALL(chroot)(void *path) {}
POST_SYSCALL(chroot)(long res, void *path) {}
PRE_SYSCALL(compat_43_fstat43)(long fd, void *sb) {}
POST_SYSCALL(compat_43_fstat43)(long res, long fd, void *sb) {}
PRE_SYSCALL(compat_43_ogetkerninfo)
(long op, void *where, void *size, long arg) {}
POST_SYSCALL(compat_43_ogetkerninfo)
(long res, long op, void *where, void *size, long arg) {}
PRE_SYSCALL(compat_43_ogetpagesize)(void) {}
POST_SYSCALL(compat_43_ogetpagesize)(long res) {}
PRE_SYSCALL(compat_12_msync)(void *addr, long len) {}
POST_SYSCALL(compat_12_msync)(long res, void *addr, long len) {}
PRE_SYSCALL(vfork)(void) {}
POST_SYSCALL(vfork)(long res) {}
/* syscall 67 has been skipped */
/* syscall 68 has been skipped */
PRE_SYSCALL(sbrk)(long incr) {}
POST_SYSCALL(sbrk)(long res, long incr) {}
PRE_SYSCALL(sstk)(long incr) {}
POST_SYSCALL(sstk)(long res, long incr) {}
PRE_SYSCALL(compat_43_ommap)
(void *addr, long len, long prot, long flags, long fd, long pos) {}
POST_SYSCALL(compat_43_ommap)
(long res, void *addr, long len, long prot, long flags, long fd, long pos) {}
PRE_SYSCALL(vadvise)(long anom) {}
POST_SYSCALL(vadvise)(long res, long anom) {}
PRE_SYSCALL(munmap)(void *addr, long len) {}
POST_SYSCALL(munmap)(long res, void *addr, long len) {}
PRE_SYSCALL(mprotect)(void *addr, long len, long prot) {}
POST_SYSCALL(mprotect)(long res, void *addr, long len, long prot) {}
PRE_SYSCALL(madvise)(void *addr, long len, long behav) {}
POST_SYSCALL(madvise)(long res, void *addr, long len, long behav) {}
/* syscall 76 has been skipped */
/* syscall 77 has been skipped */
PRE_SYSCALL(mincore)(void *addr, long len, void *vec) {}
POST_SYSCALL(mincore)(long res, void *addr, long len, void *vec) {}
PRE_SYSCALL(getgroups)(long gidsetsize, void *gidset) {}
POST_SYSCALL(getgroups)(long res, long gidsetsize, void *gidset) {}
PRE_SYSCALL(setgroups)(long gidsetsize, void *gidset) {}
POST_SYSCALL(setgroups)(long res, long gidsetsize, void *gidset) {}
PRE_SYSCALL(getpgrp)(void) {}
POST_SYSCALL(getpgrp)(long res) {}
PRE_SYSCALL(setpgid)(long pid, long pgid) {}
POST_SYSCALL(setpgid)(long res, long pid, long pgid) {}
PRE_SYSCALL(compat_50_setitimer)(long which, void *itv, void *oitv) {}
POST_SYSCALL(compat_50_setitimer)
(long res, long which, void *itv, void *oitv) {}
PRE_SYSCALL(compat_43_owait)(void) {}
POST_SYSCALL(compat_43_owait)(long res) {}
PRE_SYSCALL(compat_12_oswapon)(void *name) {}
POST_SYSCALL(compat_12_oswapon)(long res, void *name) {}
PRE_SYSCALL(compat_50_getitimer)(long which, void *itv) {}
POST_SYSCALL(compat_50_getitimer)(long res, long which, void *itv) {}
PRE_SYSCALL(compat_43_ogethostname)(void *hostname, long len) {}
POST_SYSCALL(compat_43_ogethostname)(long res, void *hostname, long len) {}
PRE_SYSCALL(compat_43_osethostname)(void *hostname, long len) {}
POST_SYSCALL(compat_43_osethostname)(long res, void *hostname, long len) {}
PRE_SYSCALL(compat_43_ogetdtablesize)(void) {}
POST_SYSCALL(compat_43_ogetdtablesize)(long res) {}
PRE_SYSCALL(dup2)(long from, long to) {}
POST_SYSCALL(dup2)(long res, long from, long to) {}
/* syscall 91 has been skipped */
PRE_SYSCALL(fcntl)(long fd, long cmd, void *arg) {}
POST_SYSCALL(fcntl)(long res, long fd, long cmd, void *arg) {}
PRE_SYSCALL(compat_50_select)
(long nd, void *in, void *ou, void *ex, void *tv) {}
POST_SYSCALL(compat_50_select)
(long res, long nd, void *in, void *ou, void *ex, void *tv) {}
/* syscall 94 has been skipped */
PRE_SYSCALL(fsync)(long fd) {}
POST_SYSCALL(fsync)(long res, long fd) {}
PRE_SYSCALL(setpriority)(long which, long who, long prio) {}
POST_SYSCALL(setpriority)(long res, long which, long who, long prio) {}
PRE_SYSCALL(compat_30_socket)(long domain, long type, long protocol) {}
POST_SYSCALL(compat_30_socket)
(long res, long domain, long type, long protocol) {}
PRE_SYSCALL(connect)(long s, void *name, long namelen) {}
POST_SYSCALL(connect)(long res, long s, void *name, long namelen) {}
PRE_SYSCALL(compat_43_oaccept)(long s, void *name, void *anamelen) {}
POST_SYSCALL(compat_43_oaccept)(long res, long s, void *name, void *anamelen) {}
PRE_SYSCALL(getpriority)(long which, long who) {}
POST_SYSCALL(getpriority)(long res, long which, long who) {}
PRE_SYSCALL(compat_43_osend)(long s, void *buf, long len, long flags) {}
POST_SYSCALL(compat_43_osend)
(long res, long s, void *buf, long len, long flags) {}
PRE_SYSCALL(compat_43_orecv)(long s, void *buf, long len, long flags) {}
POST_SYSCALL(compat_43_orecv)
(long res, long s, void *buf, long len, long flags) {}
PRE_SYSCALL(compat_13_sigreturn13)(void *sigcntxp) {}
POST_SYSCALL(compat_13_sigreturn13)(long res, void *sigcntxp) {}
PRE_SYSCALL(bind)(long s, void *name, long namelen) {}
POST_SYSCALL(bind)(long res, long s, void *name, long namelen) {}
PRE_SYSCALL(setsockopt)
(long s, long level, long name, void *val, long valsize) {}
POST_SYSCALL(setsockopt)
(long res, long s, long level, long name, void *val, long valsize) {}
PRE_SYSCALL(listen)(long s, long backlog) {}
POST_SYSCALL(listen)(long res, long s, long backlog) {}
/* syscall 107 has been skipped */
PRE_SYSCALL(compat_43_osigvec)(long signum, void *nsv, void *osv) {}
POST_SYSCALL(compat_43_osigvec)(long res, long signum, void *nsv, void *osv) {}
PRE_SYSCALL(compat_43_osigblock)(long mask) {}
POST_SYSCALL(compat_43_osigblock)(long res, long mask) {}
PRE_SYSCALL(compat_43_osigsetmask)(long mask) {}
POST_SYSCALL(compat_43_osigsetmask)(long res, long mask) {}
PRE_SYSCALL(compat_13_sigsuspend13)(long mask) {}
POST_SYSCALL(compat_13_sigsuspend13)(long res, long mask) {}
PRE_SYSCALL(compat_43_osigstack)(void *nss, void *oss) {}
POST_SYSCALL(compat_43_osigstack)(long res, void *nss, void *oss) {}
PRE_SYSCALL(compat_43_orecvmsg)(long s, void *msg, long flags) {}
POST_SYSCALL(compat_43_orecvmsg)(long res, long s, void *msg, long flags) {}
PRE_SYSCALL(compat_43_osendmsg)(long s, void *msg, long flags) {}
POST_SYSCALL(compat_43_osendmsg)(long res, long s, void *msg, long flags) {}
/* syscall 115 has been skipped */
PRE_SYSCALL(compat_50_gettimeofday)(void *tp, void *tzp) {}
POST_SYSCALL(compat_50_gettimeofday)(long res, void *tp, void *tzp) {}
PRE_SYSCALL(compat_50_getrusage)(long who, void *rusage) {}
POST_SYSCALL(compat_50_getrusage)(long res, long who, void *rusage) {}
PRE_SYSCALL(getsockopt)
(long s, long level, long name, void *val, void *avalsize) {}
POST_SYSCALL(getsockopt)
(long res, long s, long level, long name, void *val, void *avalsize) {}
/* syscall 119 has been skipped */
PRE_SYSCALL(readv)(long fd, void *iovp, long iovcnt) {}
POST_SYSCALL(readv)(long res, long fd, void *iovp, long iovcnt) {}
PRE_SYSCALL(writev)(long fd, void *iovp, long iovcnt) {}
POST_SYSCALL(writev)(long res, long fd, void *iovp, long iovcnt) {}
PRE_SYSCALL(compat_50_settimeofday)(void *tv, void *tzp) {}
POST_SYSCALL(compat_50_settimeofday)(long res, void *tv, void *tzp) {}
PRE_SYSCALL(fchown)(long fd, long uid, long gid) {}
POST_SYSCALL(fchown)(long res, long fd, long uid, long gid) {}
PRE_SYSCALL(fchmod)(long fd, long mode) {}
POST_SYSCALL(fchmod)(long res, long fd, long mode) {}
PRE_SYSCALL(compat_43_orecvfrom)
(long s, void *buf, long len, long flags, void *from, void *fromlenaddr) {}
POST_SYSCALL(compat_43_orecvfrom)
(long res, long s, void *buf, long len, long flags, void *from,
  void *fromlenaddr) {}
PRE_SYSCALL(setreuid)(long ruid, long euid) {}
POST_SYSCALL(setreuid)(long res, long ruid, long euid) {}
PRE_SYSCALL(setregid)(long rgid, long egid) {}
POST_SYSCALL(setregid)(long res, long rgid, long egid) {}
PRE_SYSCALL(rename)(void *from, void *to) {}
POST_SYSCALL(rename)(long res, void *from, void *to) {}
PRE_SYSCALL(compat_43_otruncate)(void *path, long length) {}
POST_SYSCALL(compat_43_otruncate)(long res, void *path, long length) {}
PRE_SYSCALL(compat_43_oftruncate)(long fd, long length) {}
POST_SYSCALL(compat_43_oftruncate)(long res, long fd, long length) {}
PRE_SYSCALL(flock)(long fd, long how) {}
POST_SYSCALL(flock)(long res, long fd, long how) {}
PRE_SYSCALL(mkfifo)(void *path, long mode) {}
POST_SYSCALL(mkfifo)(long res, void *path, long mode) {}
PRE_SYSCALL(sendto)
(long s, void *buf, long len, long flags, void *to, long tolen) {}
POST_SYSCALL(sendto)
(long res, long s, void *buf, long len, long flags, void *to, long tolen) {}
PRE_SYSCALL(shutdown)(long s, long how) {}
POST_SYSCALL(shutdown)(long res, long s, long how) {}
PRE_SYSCALL(socketpair)(long domain, long type, long protocol, void *rsv) {}
POST_SYSCALL(socketpair)
(long res, long domain, long type, long protocol, void *rsv) {}
PRE_SYSCALL(mkdir)(void *path, long mode) {}
POST_SYSCALL(mkdir)(long res, void *path, long mode) {}
PRE_SYSCALL(rmdir)(void *path) {}
POST_SYSCALL(rmdir)(long res, void *path) {}
PRE_SYSCALL(compat_50_utimes)(void *path, void *tptr) {}
POST_SYSCALL(compat_50_utimes)(long res, void *path, void *tptr) {}
/* syscall 139 has been skipped */
PRE_SYSCALL(compat_50_adjtime)(void *delta, void *olddelta) {}
POST_SYSCALL(compat_50_adjtime)(long res, void *delta, void *olddelta) {}
PRE_SYSCALL(compat_43_ogetpeername)(long fdes, void *asa, void *alen) {}
POST_SYSCALL(compat_43_ogetpeername)
(long res, long fdes, void *asa, void *alen) {}
PRE_SYSCALL(compat_43_ogethostid)(void) {}
POST_SYSCALL(compat_43_ogethostid)(long res) {}
PRE_SYSCALL(compat_43_osethostid)(long hostid) {}
POST_SYSCALL(compat_43_osethostid)(long res, long hostid) {}
PRE_SYSCALL(compat_43_ogetrlimit)(long which, void *rlp) {}
POST_SYSCALL(compat_43_ogetrlimit)(long res, long which, void *rlp) {}
PRE_SYSCALL(compat_43_osetrlimit)(long which, void *rlp) {}
POST_SYSCALL(compat_43_osetrlimit)(long res, long which, void *rlp) {}
PRE_SYSCALL(compat_43_okillpg)(long pgid, long signum) {}
POST_SYSCALL(compat_43_okillpg)(long res, long pgid, long signum) {}
PRE_SYSCALL(setsid)(void) {}
POST_SYSCALL(setsid)(long res) {}
PRE_SYSCALL(compat_50_quotactl)(void *path, long cmd, long uid, void *arg) {}
POST_SYSCALL(compat_50_quotactl)
(long res, void *path, long cmd, long uid, void *arg) {}
PRE_SYSCALL(compat_43_oquota)(void) {}
POST_SYSCALL(compat_43_oquota)(long res) {}
PRE_SYSCALL(compat_43_ogetsockname)(long fdec, void *asa, void *alen) {}
POST_SYSCALL(compat_43_ogetsockname)
(long res, long fdec, void *asa, void *alen) {}
/* syscall 151 has been skipped */
/* syscall 152 has been skipped */
/* syscall 153 has been skipped */
/* syscall 154 has been skipped */
PRE_SYSCALL(nfssvc)(long flag, void *argp) {}
POST_SYSCALL(nfssvc)(long res, long flag, void *argp) {}
PRE_SYSCALL(compat_43_ogetdirentries)
(long fd, void *buf, long count, void *basep) {}
POST_SYSCALL(compat_43_ogetdirentries)
(long res, long fd, void *buf, long count, void *basep) {}
PRE_SYSCALL(compat_20_statfs)(void *path, void *buf) {}
POST_SYSCALL(compat_20_statfs)(long res, void *path, void *buf) {}
PRE_SYSCALL(compat_20_fstatfs)(long fd, void *buf) {}
POST_SYSCALL(compat_20_fstatfs)(long res, long fd, void *buf) {}
/* syscall 159 has been skipped */
/* syscall 160 has been skipped */
PRE_SYSCALL(compat_30_getfh)(void *fname, void *fhp) {}
POST_SYSCALL(compat_30_getfh)(long res, void *fname, void *fhp) {}
PRE_SYSCALL(compat_09_ogetdomainname)(void *domainname, long len) {}
POST_SYSCALL(compat_09_ogetdomainname)(long res, void *domainname, long len) {}
PRE_SYSCALL(compat_09_osetdomainname)(void *domainname, long len) {}
POST_SYSCALL(compat_09_osetdomainname)(long res, void *domainname, long len) {}
PRE_SYSCALL(compat_09_ouname)(void *name) {}
POST_SYSCALL(compat_09_ouname)(long res, void *name) {}
PRE_SYSCALL(sysarch)(long op, void *parms) {}
POST_SYSCALL(sysarch)(long res, long op, void *parms) {}
/* syscall 166 has been skipped */
/* syscall 167 has been skipped */
/* syscall 168 has been skipped */
#if !defined(_LP64)
PRE_SYSCALL(compat_10_osemsys)
(long which, long a2, long a3, long a4, long a5) {}
POST_SYSCALL(compat_10_osemsys)
(long res, long which, long a2, long a3, long a4, long a5) {}
#else
/* syscall 169 has been skipped */
#endif
#if !defined(_LP64)
PRE_SYSCALL(compat_10_omsgsys)
(long which, long a2, long a3, long a4, long a5, long a6) {}
POST_SYSCALL(compat_10_omsgsys)
(long res, long which, long a2, long a3, long a4, long a5, long a6) {}
#else
/* syscall 170 has been skipped */
#endif
#if !defined(_LP64)
PRE_SYSCALL(compat_10_oshmsys)(long which, long a2, long a3, long a4) {}
POST_SYSCALL(compat_10_oshmsys)
(long res, long which, long a2, long a3, long a4) {}
#else
/* syscall 171 has been skipped */
#endif
/* syscall 172 has been skipped */
PRE_SYSCALL(pread)(long fd, void *buf, long nbyte, long PAD, long offset) {}
POST_SYSCALL(pread)
(long res, long fd, void *buf, long nbyte, long PAD, long offset) {}
PRE_SYSCALL(pwrite)(long fd, void *buf, long nbyte, long PAD, long offset) {}
POST_SYSCALL(pwrite)
(long res, long fd, void *buf, long nbyte, long PAD, long offset) {}
PRE_SYSCALL(compat_30_ntp_gettime)(void *ntvp) {}
POST_SYSCALL(compat_30_ntp_gettime)(long res, void *ntvp) {}
#if defined(NTP) || !defined(_KERNEL_OPT)
PRE_SYSCALL(ntp_adjtime)(void *tp) {}
POST_SYSCALL(ntp_adjtime)(long res, void *tp) {}
#else
/* syscall 176 has been skipped */
#endif
/* syscall 177 has been skipped */
/* syscall 178 has been skipped */
/* syscall 179 has been skipped */
/* syscall 180 has been skipped */
PRE_SYSCALL(setgid)(long gid) {}
POST_SYSCALL(setgid)(long res, long gid) {}
PRE_SYSCALL(setegid)(long egid) {}
POST_SYSCALL(setegid)(long res, long egid) {}
PRE_SYSCALL(seteuid)(long euid) {}
POST_SYSCALL(seteuid)(long res, long euid) {}
PRE_SYSCALL(lfs_bmapv)(void *fsidp, void *blkiov, long blkcnt) {}
POST_SYSCALL(lfs_bmapv)(long res, void *fsidp, void *blkiov, long blkcnt) {}
PRE_SYSCALL(lfs_markv)(void *fsidp, void *blkiov, long blkcnt) {}
POST_SYSCALL(lfs_markv)(long res, void *fsidp, void *blkiov, long blkcnt) {}
PRE_SYSCALL(lfs_segclean)(void *fsidp, long segment) {}
POST_SYSCALL(lfs_segclean)(long res, void *fsidp, long segment) {}
PRE_SYSCALL(compat_50_lfs_segwait)(void *fsidp, void *tv) {}
POST_SYSCALL(compat_50_lfs_segwait)(long res, void *fsidp, void *tv) {}
PRE_SYSCALL(compat_12_stat12)(void *path, void *ub) {}
POST_SYSCALL(compat_12_stat12)(long res, void *path, void *ub) {}
PRE_SYSCALL(compat_12_fstat12)(long fd, void *sb) {}
POST_SYSCALL(compat_12_fstat12)(long res, long fd, void *sb) {}
PRE_SYSCALL(compat_12_lstat12)(void *path, void *ub) {}
POST_SYSCALL(compat_12_lstat12)(long res, void *path, void *ub) {}
PRE_SYSCALL(pathconf)(void *path, long name) {}
POST_SYSCALL(pathconf)(long res, void *path, long name) {}
PRE_SYSCALL(fpathconf)(long fd, long name) {}
POST_SYSCALL(fpathconf)(long res, long fd, long name) {}
/* syscall 193 has been skipped */
PRE_SYSCALL(getrlimit)(long which, void *rlp) {}
POST_SYSCALL(getrlimit)(long res, long which, void *rlp) {}
PRE_SYSCALL(setrlimit)(long which, void *rlp) {}
POST_SYSCALL(setrlimit)(long res, long which, void *rlp) {}
PRE_SYSCALL(compat_12_getdirentries)
(long fd, void *buf, long count, void *basep) {}
POST_SYSCALL(compat_12_getdirentries)
(long res, long fd, void *buf, long count, void *basep) {}
PRE_SYSCALL(mmap)
(void *addr, long len, long prot, long flags, long fd, long PAD, long pos) {}
POST_SYSCALL(mmap)
(long res, void *addr, long len, long prot, long flags, long fd, long PAD,
  long pos) {}
PRE_SYSCALL(__syscall)(long code, long args[SYS_MAXSYSARGS]) {}
POST_SYSCALL(__syscall)(long res, long code, long args[SYS_MAXSYSARGS]) {}
PRE_SYSCALL(lseek)(long fd, long PAD, long offset, long whence) {}
POST_SYSCALL(lseek)(long res, long fd, long PAD, long offset, long whence) {}
PRE_SYSCALL(truncate)(void *path, long PAD, long length) {}
POST_SYSCALL(truncate)(long res, void *path, long PAD, long length) {}
PRE_SYSCALL(ftruncate)(long fd, long PAD, long length) {}
POST_SYSCALL(ftruncate)(long res, long fd, long PAD, long length) {}
PRE_SYSCALL(__sysctl)
(void *name, long namelen, void *oldv, void *oldlenp, void *newv, long newlen) {
}
POST_SYSCALL(__sysctl)
(long res, void *name, long namelen, void *oldv, void *oldlenp, void *newv,
  long newlen) {}
PRE_SYSCALL(mlock)(void *addr, long len) {}
POST_SYSCALL(mlock)(long res, void *addr, long len) {}
PRE_SYSCALL(munlock)(void *addr, long len) {}
POST_SYSCALL(munlock)(long res, void *addr, long len) {}
PRE_SYSCALL(undelete)(void *path) {}
POST_SYSCALL(undelete)(long res, void *path) {}
PRE_SYSCALL(compat_50_futimes)(long fd, void *tptr) {}
POST_SYSCALL(compat_50_futimes)(long res, long fd, void *tptr) {}
PRE_SYSCALL(getpgid)(long pid) {}
POST_SYSCALL(getpgid)(long res, long pid) {}
PRE_SYSCALL(reboot)(long opt, void *bootstr) {}
POST_SYSCALL(reboot)(long res, long opt, void *bootstr) {}
PRE_SYSCALL(poll)(void *fds, long nfds, long timeout) {}
POST_SYSCALL(poll)(long res, void *fds, long nfds, long timeout) {}
PRE_SYSCALL(afssys)
(long id, long a1, long a2, long a3, long a4, long a5, long a6) {}
POST_SYSCALL(afssys)
(long res, long id, long a1, long a2, long a3, long a4, long a5, long a6) {}
/* syscall 211 has been skipped */
/* syscall 212 has been skipped */
/* syscall 213 has been skipped */
/* syscall 214 has been skipped */
/* syscall 215 has been skipped */
/* syscall 216 has been skipped */
/* syscall 217 has been skipped */
/* syscall 218 has been skipped */
/* syscall 219 has been skipped */
PRE_SYSCALL(compat_14___semctl)(long semid, long semnum, long cmd, void *arg) {}
POST_SYSCALL(compat_14___semctl)
(long res, long semid, long semnum, long cmd, void *arg) {}
PRE_SYSCALL(semget)(long key, long nsems, long semflg) {}
POST_SYSCALL(semget)(long res, long key, long nsems, long semflg) {}
PRE_SYSCALL(semop)(long semid, void *sops, long nsops) {}
POST_SYSCALL(semop)(long res, long semid, void *sops, long nsops) {}
PRE_SYSCALL(semconfig)(long flag) {}
POST_SYSCALL(semconfig)(long res, long flag) {}
PRE_SYSCALL(compat_14_msgctl)(long msqid, long cmd, void *buf) {}
POST_SYSCALL(compat_14_msgctl)(long res, long msqid, long cmd, void *buf) {}
PRE_SYSCALL(msgget)(long key, long msgflg) {}
POST_SYSCALL(msgget)(long res, long key, long msgflg) {}
PRE_SYSCALL(msgsnd)(long msqid, void *msgp, long msgsz, long msgflg) {}
POST_SYSCALL(msgsnd)
(long res, long msqid, void *msgp, long msgsz, long msgflg) {}
PRE_SYSCALL(msgrcv)
(long msqid, void *msgp, long msgsz, long msgtyp, long msgflg) {}
POST_SYSCALL(msgrcv)
(long res, long msqid, void *msgp, long msgsz, long msgtyp, long msgflg) {}
PRE_SYSCALL(shmat)(long shmid, void *shmaddr, long shmflg) {}
POST_SYSCALL(shmat)(long res, long shmid, void *shmaddr, long shmflg) {}
PRE_SYSCALL(compat_14_shmctl)(long shmid, long cmd, void *buf) {}
POST_SYSCALL(compat_14_shmctl)(long res, long shmid, long cmd, void *buf) {}
PRE_SYSCALL(shmdt)(void *shmaddr) {}
POST_SYSCALL(shmdt)(long res, void *shmaddr) {}
PRE_SYSCALL(shmget)(long key, long size, long shmflg) {}
POST_SYSCALL(shmget)(long res, long key, long size, long shmflg) {}
PRE_SYSCALL(compat_50_clock_gettime)(long clock_id, void *tp) {}
POST_SYSCALL(compat_50_clock_gettime)(long res, long clock_id, void *tp) {}
PRE_SYSCALL(compat_50_clock_settime)(long clock_id, void *tp) {}
POST_SYSCALL(compat_50_clock_settime)(long res, long clock_id, void *tp) {}
PRE_SYSCALL(compat_50_clock_getres)(long clock_id, void *tp) {}
POST_SYSCALL(compat_50_clock_getres)(long res, long clock_id, void *tp) {}
PRE_SYSCALL(timer_create)(long clock_id, void *evp, void *timerid) {}
POST_SYSCALL(timer_create)(long res, long clock_id, void *evp, void *timerid) {}
PRE_SYSCALL(timer_delete)(long timerid) {}
POST_SYSCALL(timer_delete)(long res, long timerid) {}
PRE_SYSCALL(compat_50_timer_settime)
(long timerid, long flags, void *value, void *ovalue) {}
POST_SYSCALL(compat_50_timer_settime)
(long res, long timerid, long flags, void *value, void *ovalue) {}
PRE_SYSCALL(compat_50_timer_gettime)(long timerid, void *value) {}
POST_SYSCALL(compat_50_timer_gettime)(long res, long timerid, void *value) {}
PRE_SYSCALL(timer_getoverrun)(long timerid) {}
POST_SYSCALL(timer_getoverrun)(long res, long timerid) {}
PRE_SYSCALL(compat_50_nanosleep)(void *rqtp, void *rmtp) {}
POST_SYSCALL(compat_50_nanosleep)(long res, void *rqtp, void *rmtp) {}
PRE_SYSCALL(fdatasync)(long fd) {}
POST_SYSCALL(fdatasync)(long res, long fd) {}
PRE_SYSCALL(mlockall)(long flags) {}
POST_SYSCALL(mlockall)(long res, long flags) {}
PRE_SYSCALL(munlockall)(void) {}
POST_SYSCALL(munlockall)(long res) {}
PRE_SYSCALL(compat_50___sigtimedwait)(void *set, void *info, void *timeout) {}
POST_SYSCALL(compat_50___sigtimedwait)
(long res, void *set, void *info, void *timeout) {}
PRE_SYSCALL(sigqueueinfo)(long pid, void *info) {}
POST_SYSCALL(sigqueueinfo)(long res, long pid, void *info) {}
PRE_SYSCALL(modctl)(long cmd, void *arg) {}
POST_SYSCALL(modctl)(long res, long cmd, void *arg) {}
PRE_SYSCALL(_ksem_init)(long value, void *idp) {}
POST_SYSCALL(_ksem_init)(long res, long value, void *idp) {}
PRE_SYSCALL(_ksem_open)
(void *name, long oflag, long mode, long value, void *idp) {}
POST_SYSCALL(_ksem_open)
(long res, void *name, long oflag, long mode, long value, void *idp) {}
PRE_SYSCALL(_ksem_unlink)(void *name) {}
POST_SYSCALL(_ksem_unlink)(long res, void *name) {}
PRE_SYSCALL(_ksem_close)(long id) {}
POST_SYSCALL(_ksem_close)(long res, long id) {}
PRE_SYSCALL(_ksem_post)(long id) {}
POST_SYSCALL(_ksem_post)(long res, long id) {}
PRE_SYSCALL(_ksem_wait)(long id) {}
POST_SYSCALL(_ksem_wait)(long res, long id) {}
PRE_SYSCALL(_ksem_trywait)(long id) {}
POST_SYSCALL(_ksem_trywait)(long res, long id) {}
PRE_SYSCALL(_ksem_getvalue)(long id, void *value) {}
POST_SYSCALL(_ksem_getvalue)(long res, long id, void *value) {}
PRE_SYSCALL(_ksem_destroy)(long id) {}
POST_SYSCALL(_ksem_destroy)(long res, long id) {}
PRE_SYSCALL(_ksem_timedwait)(long id, void *abstime) {}
POST_SYSCALL(_ksem_timedwait)(long res, long id, void *abstime) {}
PRE_SYSCALL(mq_open)(long name, long oflag, long mode, void *attr) {}
POST_SYSCALL(mq_open)(long res, long name, long oflag, long mode, void *attr) {}
PRE_SYSCALL(mq_close)(long mqdes) {}
POST_SYSCALL(mq_close)(long res, long mqdes) {}
PRE_SYSCALL(mq_unlink)(void *name) {}
POST_SYSCALL(mq_unlink)(long res, void *name) {}
PRE_SYSCALL(mq_getattr)(long mqdes, void *mqstat) {}
POST_SYSCALL(mq_getattr)(long res, long mqdes, void *mqstat) {}
PRE_SYSCALL(mq_setattr)(long mqdes, void *mqstat, void *omqstat) {}
POST_SYSCALL(mq_setattr)(long res, long mqdes, void *mqstat, void *omqstat) {}
PRE_SYSCALL(mq_notify)(long mqdes, void *notification) {}
POST_SYSCALL(mq_notify)(long res, long mqdes, void *notification) {}
PRE_SYSCALL(mq_send)(long mqdes, void *msg_ptr, long msg_len, long msg_prio) {}
POST_SYSCALL(mq_send)
(long res, long mqdes, void *msg_ptr, long msg_len, long msg_prio) {}
PRE_SYSCALL(mq_receive)
(long mqdes, void *msg_ptr, long msg_len, void *msg_prio) {}
POST_SYSCALL(mq_receive)
(long res, long mqdes, void *msg_ptr, long msg_len, void *msg_prio) {}
PRE_SYSCALL(compat_50_mq_timedsend)
(long mqdes, void *msg_ptr, long msg_len, long msg_prio, void *abs_timeout) {}
POST_SYSCALL(compat_50_mq_timedsend)
(long res, long mqdes, void *msg_ptr, long msg_len, long msg_prio,
  void *abs_timeout) {}
PRE_SYSCALL(compat_50_mq_timedreceive)
(long mqdes, void *msg_ptr, long msg_len, void *msg_prio, void *abs_timeout) {}
POST_SYSCALL(compat_50_mq_timedreceive)
(long res, long mqdes, void *msg_ptr, long msg_len, void *msg_prio,
  void *abs_timeout) {}
/* syscall 267 has been skipped */
/* syscall 268 has been skipped */
/* syscall 269 has been skipped */
PRE_SYSCALL(__posix_rename)(void *from, void *to) {}
POST_SYSCALL(__posix_rename)(long res, void *from, void *to) {}
PRE_SYSCALL(swapctl)(long cmd, void *arg, long misc) {}
POST_SYSCALL(swapctl)(long res, long cmd, void *arg, long misc) {}
PRE_SYSCALL(compat_30_getdents)(long fd, void *buf, long count) {}
POST_SYSCALL(compat_30_getdents)(long res, long fd, void *buf, long count) {}
PRE_SYSCALL(minherit)(void *addr, long len, long inherit) {}
POST_SYSCALL(minherit)(long res, void *addr, long len, long inherit) {}
PRE_SYSCALL(lchmod)(void *path, long mode) {}
POST_SYSCALL(lchmod)(long res, void *path, long mode) {}
PRE_SYSCALL(lchown)(void *path, long uid, long gid) {}
POST_SYSCALL(lchown)(long res, void *path, long uid, long gid) {}
PRE_SYSCALL(compat_50_lutimes)(void *path, void *tptr) {}
POST_SYSCALL(compat_50_lutimes)(long res, void *path, void *tptr) {}
PRE_SYSCALL(__msync13)(void *addr, long len, long flags) {}
POST_SYSCALL(__msync13)(long res, void *addr, long len, long flags) {}
PRE_SYSCALL(compat_30___stat13)(void *path, void *ub) {}
POST_SYSCALL(compat_30___stat13)(long res, void *path, void *ub) {}
PRE_SYSCALL(compat_30___fstat13)(long fd, void *sb) {}
POST_SYSCALL(compat_30___fstat13)(long res, long fd, void *sb) {}
PRE_SYSCALL(compat_30___lstat13)(void *path, void *ub) {}
POST_SYSCALL(compat_30___lstat13)(long res, void *path, void *ub) {}
PRE_SYSCALL(__sigaltstack14)(void *nss, void *oss) {}
POST_SYSCALL(__sigaltstack14)(long res, void *nss, void *oss) {}
PRE_SYSCALL(__vfork14)(void) {}
POST_SYSCALL(__vfork14)(long res) {}
PRE_SYSCALL(__posix_chown)(void *path, long uid, long gid) {}
POST_SYSCALL(__posix_chown)(long res, void *path, long uid, long gid) {}
PRE_SYSCALL(__posix_fchown)(long fd, long uid, long gid) {}
POST_SYSCALL(__posix_fchown)(long res, long fd, long uid, long gid) {}
PRE_SYSCALL(__posix_lchown)(void *path, long uid, long gid) {}
POST_SYSCALL(__posix_lchown)(long res, void *path, long uid, long gid) {}
PRE_SYSCALL(getsid)(long pid) {}
POST_SYSCALL(getsid)(long res, long pid) {}
PRE_SYSCALL(__clone)(long flags, void *stack) {}
POST_SYSCALL(__clone)(long res, long flags, void *stack) {}
PRE_SYSCALL(fktrace)(long fd, long ops, long facs, long pid) {}
POST_SYSCALL(fktrace)(long res, long fd, long ops, long facs, long pid) {}
PRE_SYSCALL(preadv)(long fd, void *iovp, long iovcnt, long PAD, long offset) {}
POST_SYSCALL(preadv)
(long res, long fd, void *iovp, long iovcnt, long PAD, long offset) {}
PRE_SYSCALL(pwritev)(long fd, void *iovp, long iovcnt, long PAD, long offset) {}
POST_SYSCALL(pwritev)
(long res, long fd, void *iovp, long iovcnt, long PAD, long offset) {}
PRE_SYSCALL(compat_16___sigaction14)(long signum, void *nsa, void *osa) {}
POST_SYSCALL(compat_16___sigaction14)
(long res, long signum, void *nsa, void *osa) {}
PRE_SYSCALL(__sigpending14)(void *set) {}
POST_SYSCALL(__sigpending14)(long res, void *set) {}
PRE_SYSCALL(__sigprocmask14)(long how, void *set, void *oset) {}
POST_SYSCALL(__sigprocmask14)(long res, long how, void *set, void *oset) {}
PRE_SYSCALL(__sigsuspend14)(void *set) {}
POST_SYSCALL(__sigsuspend14)(long res, void *set) {}
PRE_SYSCALL(compat_16___sigreturn14)(void *sigcntxp) {}
POST_SYSCALL(compat_16___sigreturn14)(long res, void *sigcntxp) {}
PRE_SYSCALL(__getcwd)(void *bufp, long length) {}
POST_SYSCALL(__getcwd)(long res, void *bufp, long length) {}
PRE_SYSCALL(fchroot)(long fd) {}
POST_SYSCALL(fchroot)(long res, long fd) {}
PRE_SYSCALL(compat_30_fhopen)(void *fhp, long flags) {}
POST_SYSCALL(compat_30_fhopen)(long res, void *fhp, long flags) {}
PRE_SYSCALL(compat_30_fhstat)(void *fhp, void *sb) {}
POST_SYSCALL(compat_30_fhstat)(long res, void *fhp, void *sb) {}
PRE_SYSCALL(compat_20_fhstatfs)(void *fhp, void *buf) {}
POST_SYSCALL(compat_20_fhstatfs)(long res, void *fhp, void *buf) {}
PRE_SYSCALL(compat_50_____semctl13)
(long semid, long semnum, long cmd, void *arg) {}
POST_SYSCALL(compat_50_____semctl13)
(long res, long semid, long semnum, long cmd, void *arg) {}
PRE_SYSCALL(compat_50___msgctl13)(long msqid, long cmd, void *buf) {}
POST_SYSCALL(compat_50___msgctl13)(long res, long msqid, long cmd, void *buf) {}
PRE_SYSCALL(compat_50___shmctl13)(long shmid, long cmd, void *buf) {}
POST_SYSCALL(compat_50___shmctl13)(long res, long shmid, long cmd, void *buf) {}
PRE_SYSCALL(lchflags)(void *path, long flags) {}
POST_SYSCALL(lchflags)(long res, void *path, long flags) {}
PRE_SYSCALL(issetugid)(void) {}
POST_SYSCALL(issetugid)(long res) {}
PRE_SYSCALL(utrace)(void *label, void *addr, long len) {}
POST_SYSCALL(utrace)(long res, void *label, void *addr, long len) {}
PRE_SYSCALL(getcontext)(void *ucp) {}
POST_SYSCALL(getcontext)(long res, void *ucp) {}
PRE_SYSCALL(setcontext)(void *ucp) {}
POST_SYSCALL(setcontext)(long res, void *ucp) {}
PRE_SYSCALL(_lwp_create)(void *ucp, long flags, void *new_lwp) {}
POST_SYSCALL(_lwp_create)(long res, void *ucp, long flags, void *new_lwp) {}
PRE_SYSCALL(_lwp_exit)(void) {}
POST_SYSCALL(_lwp_exit)(long res) {}
PRE_SYSCALL(_lwp_self)(void) {}
POST_SYSCALL(_lwp_self)(long res) {}
PRE_SYSCALL(_lwp_wait)(long wait_for, void *departed) {}
POST_SYSCALL(_lwp_wait)(long res, long wait_for, void *departed) {}
PRE_SYSCALL(_lwp_suspend)(long target) {}
POST_SYSCALL(_lwp_suspend)(long res, long target) {}
PRE_SYSCALL(_lwp_continue)(long target) {}
POST_SYSCALL(_lwp_continue)(long res, long target) {}
PRE_SYSCALL(_lwp_wakeup)(long target) {}
POST_SYSCALL(_lwp_wakeup)(long res, long target) {}
PRE_SYSCALL(_lwp_getprivate)(void) {}
POST_SYSCALL(_lwp_getprivate)(long res) {}
PRE_SYSCALL(_lwp_setprivate)(void *ptr) {}
POST_SYSCALL(_lwp_setprivate)(long res, void *ptr) {}
PRE_SYSCALL(_lwp_kill)(long target, long signo) {}
POST_SYSCALL(_lwp_kill)(long res, long target, long signo) {}
PRE_SYSCALL(_lwp_detach)(long target) {}
POST_SYSCALL(_lwp_detach)(long res, long target) {}
PRE_SYSCALL(compat_50__lwp_park)
(void *ts, long unpark, void *hint, void *unparkhint) {}
POST_SYSCALL(compat_50__lwp_park)
(long res, void *ts, long unpark, void *hint, void *unparkhint) {}
PRE_SYSCALL(_lwp_unpark)(long target, void *hint) {}
POST_SYSCALL(_lwp_unpark)(long res, long target, void *hint) {}
PRE_SYSCALL(_lwp_unpark_all)(void *targets, long ntargets, void *hint) {}
POST_SYSCALL(_lwp_unpark_all)
(long res, void *targets, long ntargets, void *hint) {}
PRE_SYSCALL(_lwp_setname)(long target, void *name) {}
POST_SYSCALL(_lwp_setname)(long res, long target, void *name) {}
PRE_SYSCALL(_lwp_getname)(long target, void *name, long len) {}
POST_SYSCALL(_lwp_getname)(long res, long target, void *name, long len) {}
PRE_SYSCALL(_lwp_ctl)(long features, void **address) {}
POST_SYSCALL(_lwp_ctl)(long res, long features, void **address) {}
/* syscall 326 has been skipped */
/* syscall 327 has been skipped */
/* syscall 328 has been skipped */
/* syscall 329 has been skipped */
PRE_SYSCALL(compat_60_sa_register)
(void *newv, void **oldv, long flags, long stackinfo_offset) {}
POST_SYSCALL(compat_60_sa_register)
(long res, void *newv, void **oldv, long flags, long stackinfo_offset) {}
PRE_SYSCALL(compat_60_sa_stacks)(long num, void *stacks) {}
POST_SYSCALL(compat_60_sa_stacks)(long res, long num, void *stacks) {}
PRE_SYSCALL(compat_60_sa_enable)(void) {}
POST_SYSCALL(compat_60_sa_enable)(long res) {}
PRE_SYSCALL(compat_60_sa_setconcurrency)(long concurrency) {}
POST_SYSCALL(compat_60_sa_setconcurrency)(long res, long concurrency) {}
PRE_SYSCALL(compat_60_sa_yield)(void) {}
POST_SYSCALL(compat_60_sa_yield)(long res) {}
PRE_SYSCALL(compat_60_sa_preempt)(long sa_id) {}
POST_SYSCALL(compat_60_sa_preempt)(long res, long sa_id) {}
/* syscall 336 has been skipped */
/* syscall 337 has been skipped */
/* syscall 338 has been skipped */
/* syscall 339 has been skipped */
PRE_SYSCALL(__sigaction_sigtramp)
(long signum, void *nsa, void *osa, void *tramp, long vers) {}
POST_SYSCALL(__sigaction_sigtramp)
(long res, long signum, void *nsa, void *osa, void *tramp, long vers) {}
PRE_SYSCALL(pmc_get_info)(long ctr, long op, void *args) {}
POST_SYSCALL(pmc_get_info)(long res, long ctr, long op, void *args) {}
PRE_SYSCALL(pmc_control)(long ctr, long op, void *args) {}
POST_SYSCALL(pmc_control)(long res, long ctr, long op, void *args) {}
PRE_SYSCALL(rasctl)(void *addr, long len, long op) {}
POST_SYSCALL(rasctl)(long res, void *addr, long len, long op) {}
PRE_SYSCALL(kqueue)(void) {}
POST_SYSCALL(kqueue)(long res) {}
PRE_SYSCALL(compat_50_kevent)
(long fd, void *changelist, long nchanges, void *eventlist, long nevents,
  void *timeout) {}
POST_SYSCALL(compat_50_kevent)
(long res, long fd, void *changelist, long nchanges, void *eventlist,
  long nevents, void *timeout) {}
PRE_SYSCALL(_sched_setparam)(long pid, long lid, long policy, void *params) {}
POST_SYSCALL(_sched_setparam)
(long res, long pid, long lid, long policy, void *params) {}
PRE_SYSCALL(_sched_getparam)(long pid, long lid, void *policy, void *params) {}
POST_SYSCALL(_sched_getparam)
(long res, long pid, long lid, void *policy, void *params) {}
PRE_SYSCALL(_sched_setaffinity)(long pid, long lid, long size, void *cpuset) {}
POST_SYSCALL(_sched_setaffinity)
(long res, long pid, long lid, long size, void *cpuset) {}
PRE_SYSCALL(_sched_getaffinity)(long pid, long lid, long size, void *cpuset) {}
POST_SYSCALL(_sched_getaffinity)
(long res, long pid, long lid, long size, void *cpuset) {}
PRE_SYSCALL(sched_yield)(void) {}
POST_SYSCALL(sched_yield)(long res) {}
PRE_SYSCALL(_sched_protect)(long priority) {}
POST_SYSCALL(_sched_protect)(long res, long priority) {}
/* syscall 352 has been skipped */
/* syscall 353 has been skipped */
PRE_SYSCALL(fsync_range)(long fd, long flags, long start, long length) {}
POST_SYSCALL(fsync_range)
(long res, long fd, long flags, long start, long length) {}
PRE_SYSCALL(uuidgen)(void *store, long count) {}
POST_SYSCALL(uuidgen)(long res, void *store, long count) {}
PRE_SYSCALL(getvfsstat)(void *buf, long bufsize, long flags) {}
POST_SYSCALL(getvfsstat)(long res, void *buf, long bufsize, long flags) {}
PRE_SYSCALL(statvfs1)(void *path, void *buf, long flags) {}
POST_SYSCALL(statvfs1)(long res, void *path, void *buf, long flags) {}
PRE_SYSCALL(fstatvfs1)(long fd, void *buf, long flags) {}
POST_SYSCALL(fstatvfs1)(long res, long fd, void *buf, long flags) {}
PRE_SYSCALL(compat_30_fhstatvfs1)(void *fhp, void *buf, long flags) {}
POST_SYSCALL(compat_30_fhstatvfs1)
(long res, void *fhp, void *buf, long flags) {}
PRE_SYSCALL(extattrctl)
(void *path, long cmd, void *filename, long attrnamespace, void *attrname) {}
POST_SYSCALL(extattrctl)
(long res, void *path, long cmd, void *filename, long attrnamespace,
  void *attrname) {}
PRE_SYSCALL(extattr_set_file)
(void *path, long attrnamespace, void *attrname, void *data, long nbytes) {}
POST_SYSCALL(extattr_set_file)
(long res, void *path, long attrnamespace, void *attrname, void *data,
  long nbytes) {}
PRE_SYSCALL(extattr_get_file)
(void *path, long attrnamespace, void *attrname, void *data, long nbytes) {}
POST_SYSCALL(extattr_get_file)
(long res, void *path, long attrnamespace, void *attrname, void *data,
  long nbytes) {}
PRE_SYSCALL(extattr_delete_file)
(void *path, long attrnamespace, void *attrname) {}
POST_SYSCALL(extattr_delete_file)
(long res, void *path, long attrnamespace, void *attrname) {}
PRE_SYSCALL(extattr_set_fd)
(long fd, long attrnamespace, void *attrname, void *data, long nbytes) {}
POST_SYSCALL(extattr_set_fd)
(long res, long fd, long attrnamespace, void *attrname, void *data,
  long nbytes) {}
PRE_SYSCALL(extattr_get_fd)
(long fd, long attrnamespace, void *attrname, void *data, long nbytes) {}
POST_SYSCALL(extattr_get_fd)
(long res, long fd, long attrnamespace, void *attrname, void *data,
  long nbytes) {}
PRE_SYSCALL(extattr_delete_fd)(long fd, long attrnamespace, void *attrname) {}
POST_SYSCALL(extattr_delete_fd)
(long res, long fd, long attrnamespace, void *attrname) {}
PRE_SYSCALL(extattr_set_link)
(void *path, long attrnamespace, void *attrname, void *data, long nbytes) {}
POST_SYSCALL(extattr_set_link)
(long res, void *path, long attrnamespace, void *attrname, void *data,
  long nbytes) {}
PRE_SYSCALL(extattr_get_link)
(void *path, long attrnamespace, void *attrname, void *data, long nbytes) {}
POST_SYSCALL(extattr_get_link)
(long res, void *path, long attrnamespace, void *attrname, void *data,
  long nbytes) {}
PRE_SYSCALL(extattr_delete_link)
(void *path, long attrnamespace, void *attrname) {}
POST_SYSCALL(extattr_delete_link)
(long res, void *path, long attrnamespace, void *attrname) {}
PRE_SYSCALL(extattr_list_fd)
(long fd, long attrnamespace, void *data, long nbytes) {}
POST_SYSCALL(extattr_list_fd)
(long res, long fd, long attrnamespace, void *data, long nbytes) {}
PRE_SYSCALL(extattr_list_file)
(void *path, long attrnamespace, void *data, long nbytes) {}
POST_SYSCALL(extattr_list_file)
(long res, void *path, long attrnamespace, void *data, long nbytes) {}
PRE_SYSCALL(extattr_list_link)
(void *path, long attrnamespace, void *data, long nbytes) {}
POST_SYSCALL(extattr_list_link)
(long res, void *path, long attrnamespace, void *data, long nbytes) {}
PRE_SYSCALL(compat_50_pselect)
(long nd, void *in, void *ou, void *ex, void *ts, void *mask) {}
POST_SYSCALL(compat_50_pselect)
(long res, long nd, void *in, void *ou, void *ex, void *ts, void *mask) {}
PRE_SYSCALL(compat_50_pollts)(void *fds, long nfds, void *ts, void *mask) {}
POST_SYSCALL(compat_50_pollts)
(long res, void *fds, long nfds, void *ts, void *mask) {}
PRE_SYSCALL(setxattr)
(void *path, void *name, void *value, long size, long flags) {}
POST_SYSCALL(setxattr)
(long res, void *path, void *name, void *value, long size, long flags) {}
PRE_SYSCALL(lsetxattr)
(void *path, void *name, void *value, long size, long flags) {}
POST_SYSCALL(lsetxattr)
(long res, void *path, void *name, void *value, long size, long flags) {}
PRE_SYSCALL(fsetxattr)
(long fd, void *name, void *value, long size, long flags) {}
POST_SYSCALL(fsetxattr)
(long res, long fd, void *name, void *value, long size, long flags) {}
PRE_SYSCALL(getxattr)(void *path, void *name, void *value, long size) {}
POST_SYSCALL(getxattr)
(long res, void *path, void *name, void *value, long size) {}
PRE_SYSCALL(lgetxattr)(void *path, void *name, void *value, long size) {}
POST_SYSCALL(lgetxattr)
(long res, void *path, void *name, void *value, long size) {}
PRE_SYSCALL(fgetxattr)(long fd, void *name, void *value, long size) {}
POST_SYSCALL(fgetxattr)
(long res, long fd, void *name, void *value, long size) {}
PRE_SYSCALL(listxattr)(void *path, void *list, long size) {}
POST_SYSCALL(listxattr)(long res, void *path, void *list, long size) {}
PRE_SYSCALL(llistxattr)(void *path, void *list, long size) {}
POST_SYSCALL(llistxattr)(long res, void *path, void *list, long size) {}
PRE_SYSCALL(flistxattr)(long fd, void *list, long size) {}
POST_SYSCALL(flistxattr)(long res, long fd, void *list, long size) {}
PRE_SYSCALL(removexattr)(void *path, void *name) {}
POST_SYSCALL(removexattr)(long res, void *path, void *name) {}
PRE_SYSCALL(lremovexattr)(void *path, void *name) {}
POST_SYSCALL(lremovexattr)(long res, void *path, void *name) {}
PRE_SYSCALL(fremovexattr)(long fd, void *name) {}
POST_SYSCALL(fremovexattr)(long res, long fd, void *name) {}
PRE_SYSCALL(compat_50___stat30)(void *path, void *ub) {}
POST_SYSCALL(compat_50___stat30)(long res, void *path, void *ub) {}
PRE_SYSCALL(compat_50___fstat30)(long fd, void *sb) {}
POST_SYSCALL(compat_50___fstat30)(long res, long fd, void *sb) {}
PRE_SYSCALL(compat_50___lstat30)(void *path, void *ub) {}
POST_SYSCALL(compat_50___lstat30)(long res, void *path, void *ub) {}
PRE_SYSCALL(__getdents30)(long fd, void *buf, long count) {}
POST_SYSCALL(__getdents30)(long res, long fd, void *buf, long count) {}
PRE_SYSCALL(posix_fadvise)(long) {}
POST_SYSCALL(posix_fadvise)(long res, long) {}
PRE_SYSCALL(compat_30___fhstat30)(void *fhp, void *sb) {}
POST_SYSCALL(compat_30___fhstat30)(long res, void *fhp, void *sb) {}
PRE_SYSCALL(compat_50___ntp_gettime30)(void *ntvp) {}
POST_SYSCALL(compat_50___ntp_gettime30)(long res, void *ntvp) {}
PRE_SYSCALL(__socket30)(long domain, long type, long protocol) {}
POST_SYSCALL(__socket30)(long res, long domain, long type, long protocol) {}
PRE_SYSCALL(__getfh30)(void *fname, void *fhp, void *fh_size) {}
POST_SYSCALL(__getfh30)(long res, void *fname, void *fhp, void *fh_size) {}
PRE_SYSCALL(__fhopen40)(void *fhp, long fh_size, long flags) {}
POST_SYSCALL(__fhopen40)(long res, void *fhp, long fh_size, long flags) {}
PRE_SYSCALL(__fhstatvfs140)(void *fhp, long fh_size, void *buf, long flags) {}
POST_SYSCALL(__fhstatvfs140)
(long res, void *fhp, long fh_size, void *buf, long flags) {}
PRE_SYSCALL(compat_50___fhstat40)(void *fhp, long fh_size, void *sb) {}
POST_SYSCALL(compat_50___fhstat40)
(long res, void *fhp, long fh_size, void *sb) {}
PRE_SYSCALL(aio_cancel)(long fildes, void *aiocbp) {}
POST_SYSCALL(aio_cancel)(long res, long fildes, void *aiocbp) {}
PRE_SYSCALL(aio_error)(void *aiocbp) {}
POST_SYSCALL(aio_error)(long res, void *aiocbp) {}
PRE_SYSCALL(aio_fsync)(long op, void *aiocbp) {}
POST_SYSCALL(aio_fsync)(long res, long op, void *aiocbp) {}
PRE_SYSCALL(aio_read)(void *aiocbp) {}
POST_SYSCALL(aio_read)(long res, void *aiocbp) {}
PRE_SYSCALL(aio_return)(void *aiocbp) {}
POST_SYSCALL(aio_return)(long res, void *aiocbp) {}
PRE_SYSCALL(compat_50_aio_suspend)(void *list, long nent, void *timeout) {}
POST_SYSCALL(compat_50_aio_suspend)
(long res, void *list, long nent, void *timeout) {}
PRE_SYSCALL(aio_write)(void *aiocbp) {}
POST_SYSCALL(aio_write)(long res, void *aiocbp) {}
PRE_SYSCALL(lio_listio)(long mode, void *list, long nent, void *sig) {}
POST_SYSCALL(lio_listio)
(long res, long mode, void *list, long nent, void *sig) {}
/* syscall 407 has been skipped */
/* syscall 408 has been skipped */
/* syscall 409 has been skipped */
PRE_SYSCALL(__mount50)
(void *type, void *path, long flags, void *data, long data_len) {}
POST_SYSCALL(__mount50)
(long res, void *type, void *path, long flags, void *data, long data_len) {}
PRE_SYSCALL(mremap)
(void *old_address, long old_size, void *new_address, long new_size,
  long flags) {}
POST_SYSCALL(mremap)
(long res, void *old_address, long old_size, void *new_address, long new_size,
  long flags) {}
PRE_SYSCALL(pset_create)(void *psid) {}
POST_SYSCALL(pset_create)(long res, void *psid) {}
PRE_SYSCALL(pset_destroy)(long psid) {}
POST_SYSCALL(pset_destroy)(long res, long psid) {}
PRE_SYSCALL(pset_assign)(long psid, long cpuid, void *opsid) {}
POST_SYSCALL(pset_assign)(long res, long psid, long cpuid, void *opsid) {}
PRE_SYSCALL(_pset_bind)
(long idtype, long first_id, long second_id, long psid, void *opsid) {}
POST_SYSCALL(_pset_bind)
(long res, long idtype, long first_id, long second_id, long psid, void *opsid) {
}
PRE_SYSCALL(__posix_fadvise50)
(long fd, long PAD, long offset, long len, long advice) {}
POST_SYSCALL(__posix_fadvise50)
(long res, long fd, long PAD, long offset, long len, long advice) {}
PRE_SYSCALL(__select50)(long nd, void *in, void *ou, void *ex, void *tv) {}
POST_SYSCALL(__select50)
(long res, long nd, void *in, void *ou, void *ex, void *tv) {}
PRE_SYSCALL(__gettimeofday50)(void *tp, void *tzp) {}
POST_SYSCALL(__gettimeofday50)(long res, void *tp, void *tzp) {}
PRE_SYSCALL(__settimeofday50)(void *tv, void *tzp) {}
POST_SYSCALL(__settimeofday50)(long res, void *tv, void *tzp) {}
PRE_SYSCALL(__utimes50)(void *path, void *tptr) {}
POST_SYSCALL(__utimes50)(long res, void *path, void *tptr) {}
PRE_SYSCALL(__adjtime50)(void *delta, void *olddelta) {}
POST_SYSCALL(__adjtime50)(long res, void *delta, void *olddelta) {}
PRE_SYSCALL(__lfs_segwait50)(void *fsidp, void *tv) {}
POST_SYSCALL(__lfs_segwait50)(long res, void *fsidp, void *tv) {}
PRE_SYSCALL(__futimes50)(long fd, void *tptr) {}
POST_SYSCALL(__futimes50)(long res, long fd, void *tptr) {}
PRE_SYSCALL(__lutimes50)(void *path, void *tptr) {}
POST_SYSCALL(__lutimes50)(long res, void *path, void *tptr) {}
PRE_SYSCALL(__setitimer50)(long which, void *itv, void *oitv) {}
POST_SYSCALL(__setitimer50)(long res, long which, void *itv, void *oitv) {}
PRE_SYSCALL(__getitimer50)(long which, void *itv) {}
POST_SYSCALL(__getitimer50)(long res, long which, void *itv) {}
PRE_SYSCALL(__clock_gettime50)(long clock_id, void *tp) {}
POST_SYSCALL(__clock_gettime50)(long res, long clock_id, void *tp) {}
PRE_SYSCALL(__clock_settime50)(long clock_id, void *tp) {}
POST_SYSCALL(__clock_settime50)(long res, long clock_id, void *tp) {}
PRE_SYSCALL(__clock_getres50)(long clock_id, void *tp) {}
POST_SYSCALL(__clock_getres50)(long res, long clock_id, void *tp) {}
PRE_SYSCALL(__nanosleep50)(void *rqtp, void *rmtp) {}
POST_SYSCALL(__nanosleep50)(long res, void *rqtp, void *rmtp) {}
PRE_SYSCALL(____sigtimedwait50)(void *set, void *info, void *timeout) {}
POST_SYSCALL(____sigtimedwait50)
(long res, void *set, void *info, void *timeout) {}
PRE_SYSCALL(__mq_timedsend50)
(long mqdes, void *msg_ptr, long msg_len, long msg_prio, void *abs_timeout) {}
POST_SYSCALL(__mq_timedsend50)
(long res, long mqdes, void *msg_ptr, long msg_len, long msg_prio,
  void *abs_timeout) {}
PRE_SYSCALL(__mq_timedreceive50)
(long mqdes, void *msg_ptr, long msg_len, void *msg_prio, void *abs_timeout) {}
POST_SYSCALL(__mq_timedreceive50)
(long res, long mqdes, void *msg_ptr, long msg_len, void *msg_prio,
  void *abs_timeout) {}
PRE_SYSCALL(compat_60__lwp_park)
(void *ts, long unpark, void *hint, void *unparkhint) {}
POST_SYSCALL(compat_60__lwp_park)
(long res, void *ts, long unpark, void *hint, void *unparkhint) {}
PRE_SYSCALL(__kevent50)
(long fd, void *changelist, long nchanges, void *eventlist, long nevents,
  void *timeout) {}
POST_SYSCALL(__kevent50)
(long res, long fd, void *changelist, long nchanges, void *eventlist,
  long nevents, void *timeout) {}
PRE_SYSCALL(__pselect50)
(long nd, void *in, void *ou, void *ex, void *ts, void *mask) {}
POST_SYSCALL(__pselect50)
(long res, long nd, void *in, void *ou, void *ex, void *ts, void *mask) {}
PRE_SYSCALL(__pollts50)(void *fds, long nfds, void *ts, void *mask) {}
POST_SYSCALL(__pollts50)
(long res, void *fds, long nfds, void *ts, void *mask) {}
PRE_SYSCALL(__aio_suspend50)(void *list, long nent, void *timeout) {}
POST_SYSCALL(__aio_suspend50)(long res, void *list, long nent, void *timeout) {}
PRE_SYSCALL(__stat50)(void *path, void *ub) {}
POST_SYSCALL(__stat50)(long res, void *path, void *ub) {}
PRE_SYSCALL(__fstat50)(long fd, void *sb) {}
POST_SYSCALL(__fstat50)(long res, long fd, void *sb) {}
PRE_SYSCALL(__lstat50)(void *path, void *ub) {}
POST_SYSCALL(__lstat50)(long res, void *path, void *ub) {}
PRE_SYSCALL(____semctl50)(long semid, long semnum, long cmd, void *arg) {}
POST_SYSCALL(____semctl50)
(long res, long semid, long semnum, long cmd, void *arg) {}
PRE_SYSCALL(__shmctl50)(long shmid, long cmd, void *buf) {}
POST_SYSCALL(__shmctl50)(long res, long shmid, long cmd, void *buf) {}
PRE_SYSCALL(__msgctl50)(long msqid, long cmd, void *buf) {}
POST_SYSCALL(__msgctl50)(long res, long msqid, long cmd, void *buf) {}
PRE_SYSCALL(__getrusage50)(long who, void *rusage) {}
POST_SYSCALL(__getrusage50)(long res, long who, void *rusage) {}
PRE_SYSCALL(__timer_settime50)
(long timerid, long flags, void *value, void *ovalue) {}
POST_SYSCALL(__timer_settime50)
(long res, long timerid, long flags, void *value, void *ovalue) {}
PRE_SYSCALL(__timer_gettime50)(long timerid, void *value) {}
POST_SYSCALL(__timer_gettime50)(long res, long timerid, void *value) {}
#if defined(NTP) || !defined(_KERNEL_OPT)
PRE_SYSCALL(__ntp_gettime50)(void *ntvp) {}
POST_SYSCALL(__ntp_gettime50)(long res, void *ntvp) {}
#else
/* syscall 448 has been skipped */
#endif
PRE_SYSCALL(__wait450)(long pid, void *status, long options, void *rusage) {}
POST_SYSCALL(__wait450)
(long res, long pid, void *status, long options, void *rusage) {}
PRE_SYSCALL(__mknod50)(void *path, long mode, long dev) {}
POST_SYSCALL(__mknod50)(long res, void *path, long mode, long dev) {}
PRE_SYSCALL(__fhstat50)(void *fhp, long fh_size, void *sb) {}
POST_SYSCALL(__fhstat50)(long res, void *fhp, long fh_size, void *sb) {}
/* syscall 452 has been skipped */
PRE_SYSCALL(pipe2)(void *fildes, long flags) {}
POST_SYSCALL(pipe2)(long res, void *fildes, long flags) {}
PRE_SYSCALL(dup3)(long from, long to, long flags) {}
POST_SYSCALL(dup3)(long res, long from, long to, long flags) {}
PRE_SYSCALL(kqueue1)(long flags) {}
POST_SYSCALL(kqueue1)(long res, long flags) {}
PRE_SYSCALL(paccept)
(long s, void *name, void *anamelen, void *mask, long flags) {}
POST_SYSCALL(paccept)
(long res, long s, void *name, void *anamelen, void *mask, long flags) {}
PRE_SYSCALL(linkat)(long fd1, void *name1, long fd2, void *name2, long flags) {}
POST_SYSCALL(linkat)
(long res, long fd1, void *name1, long fd2, void *name2, long flags) {}
PRE_SYSCALL(renameat)(long fromfd, void *from, long tofd, void *to) {}
POST_SYSCALL(renameat)
(long res, long fromfd, void *from, long tofd, void *to) {}
PRE_SYSCALL(mkfifoat)(long fd, void *path, long mode) {}
POST_SYSCALL(mkfifoat)(long res, long fd, void *path, long mode) {}
PRE_SYSCALL(mknodat)(long fd, void *path, long mode, long PAD, long dev) {}
POST_SYSCALL(mknodat)
(long res, long fd, void *path, long mode, long PAD, long dev) {}
PRE_SYSCALL(mkdirat)(long fd, void *path, long mode) {}
POST_SYSCALL(mkdirat)(long res, long fd, void *path, long mode) {}
PRE_SYSCALL(faccessat)(long fd, void *path, long amode, long flag) {}
POST_SYSCALL(faccessat)(long res, long fd, void *path, long amode, long flag) {}
PRE_SYSCALL(fchmodat)(long fd, void *path, long mode, long flag) {}
POST_SYSCALL(fchmodat)(long res, long fd, void *path, long mode, long flag) {}
PRE_SYSCALL(fchownat)(long fd, void *path, long owner, long group, long flag) {}
POST_SYSCALL(fchownat)
(long res, long fd, void *path, long owner, long group, long flag) {}
PRE_SYSCALL(fexecve)(long fd, void *argp, void *envp) {}
POST_SYSCALL(fexecve)(long res, long fd, void *argp, void *envp) {}
PRE_SYSCALL(fstatat)(long fd, void *path, void *buf, long flag) {}
POST_SYSCALL(fstatat)(long res, long fd, void *path, void *buf, long flag) {}
PRE_SYSCALL(utimensat)(long fd, void *path, void *tptr, long flag) {}
POST_SYSCALL(utimensat)(long res, long fd, void *path, void *tptr, long flag) {}
PRE_SYSCALL(openat)(long fd, void *path, long oflags, long mode) {}
POST_SYSCALL(openat)(long res, long fd, void *path, long oflags, long mode) {}
PRE_SYSCALL(readlinkat)(long fd, void *path, void *buf, long bufsize) {}
POST_SYSCALL(readlinkat)
(long res, long fd, void *path, void *buf, long bufsize) {}
PRE_SYSCALL(symlinkat)(void *path1, long fd, void *path2) {}
POST_SYSCALL(symlinkat)(long res, void *path1, long fd, void *path2) {}
PRE_SYSCALL(unlinkat)(long fd, void *path, long flag) {}
POST_SYSCALL(unlinkat)(long res, long fd, void *path, long flag) {}
PRE_SYSCALL(futimens)(long fd, void *tptr) {}
POST_SYSCALL(futimens)(long res, long fd, void *tptr) {}
PRE_SYSCALL(__quotactl)(void *path, void *args) {}
POST_SYSCALL(__quotactl)(long res, void *path, void *args) {}
PRE_SYSCALL(posix_spawn)
(void *pid, void *path, void *file_actions, void *attrp, void *argv,
  void *envp) {}
POST_SYSCALL(posix_spawn)
(long res, void *pid, void *path, void *file_actions, void *attrp, void *argv,
  void *envp) {}
PRE_SYSCALL(recvmmsg)
(long s, void *mmsg, long vlen, long flags, void *timeout) {}
POST_SYSCALL(recvmmsg)
(long res, long s, void *mmsg, long vlen, long flags, void *timeout) {}
PRE_SYSCALL(sendmmsg)(long s, void *mmsg, long vlen, long flags) {}
POST_SYSCALL(sendmmsg)(long res, long s, void *mmsg, long vlen, long flags) {}
PRE_SYSCALL(clock_nanosleep)
(long clock_id, long flags, void *rqtp, void *rmtp) {}
POST_SYSCALL(clock_nanosleep)
(long res, long clock_id, long flags, void *rqtp, void *rmtp) {}
PRE_SYSCALL(___lwp_park60)
(long clock_id, long flags, void *ts, long unpark, void *hint,
  void *unparkhint) {}
POST_SYSCALL(___lwp_park60)
(long res, long clock_id, long flags, void *ts, long unpark, void *hint,
  void *unparkhint) {}
PRE_SYSCALL(posix_fallocate)(long fd, long PAD, long pos, long len) {}
POST_SYSCALL(posix_fallocate)
(long res, long fd, long PAD, long pos, long len) {}
PRE_SYSCALL(fdiscard)(long fd, long PAD, long pos, long len) {}
POST_SYSCALL(fdiscard)(long res, long fd, long PAD, long pos, long len) {}
PRE_SYSCALL(wait6)
(long idtype, long id, void *status, long options, void *wru, void *info) {}
POST_SYSCALL(wait6)
(long res, long idtype, long id, void *status, long options, void *wru,
  void *info) {}
PRE_SYSCALL(clock_getcpuclockid2)(long idtype, long id, void *clock_id) {}
POST_SYSCALL(clock_getcpuclockid2)
(long res, long idtype, long id, void *clock_id) {}
#undef SYS_MAXSYSARGS
} // extern "C"

#undef PRE_SYSCALL
#undef PRE_READ
#undef PRE_WRITE
#undef POST_SYSCALL
#undef POST_READ
#undef POST_WRITE

#endif // SANITIZER_NETBSD
