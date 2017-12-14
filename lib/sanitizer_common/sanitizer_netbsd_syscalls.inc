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
// Generated with: make_netbsd_syscalls_header.awk
// Generated date: 2017-12-15
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
PRE_SYSCALL(syscall)() {}
POST_SYSCALL(syscall)(register_t res, ) {}
PRE_SYSCALL(exit)() {}
POST_SYSCALL(exit)(register_t res, ) {}
PRE_SYSCALL(fork)() {}
POST_SYSCALL(fork)(register_t res, ) {}
PRE_SYSCALL(read)() {}
POST_SYSCALL(read)(register_t res, ) {}
PRE_SYSCALL(write)() {}
POST_SYSCALL(write)(register_t res, ) {}
PRE_SYSCALL(open)() {}
POST_SYSCALL(open)(register_t res, ) {}
PRE_SYSCALL(close)() {}
POST_SYSCALL(close)(register_t res, ) {}
PRE_SYSCALL(compat_50_wait4)() {}
POST_SYSCALL(compat_50_wait4)(register_t res, ) {}
PRE_SYSCALL(compat_43_ocreat)() {}
POST_SYSCALL(compat_43_ocreat)(register_t res, ) {}
PRE_SYSCALL(link)() {}
POST_SYSCALL(link)(register_t res, ) {}
PRE_SYSCALL(unlink)() {}
POST_SYSCALL(unlink)(register_t res, ) {}
/* syscall 11 has been skipped */
PRE_SYSCALL(chdir)() {}
POST_SYSCALL(chdir)(register_t res, ) {}
PRE_SYSCALL(fchdir)() {}
POST_SYSCALL(fchdir)(register_t res, ) {}
PRE_SYSCALL(compat_50_mknod)() {}
POST_SYSCALL(compat_50_mknod)(register_t res, ) {}
PRE_SYSCALL(chmod)() {}
POST_SYSCALL(chmod)(register_t res, ) {}
PRE_SYSCALL(chown)() {}
POST_SYSCALL(chown)(register_t res, ) {}
PRE_SYSCALL(break)() {}
POST_SYSCALL(break)(register_t res, ) {}
PRE_SYSCALL(compat_20_getfsstat)() {}
POST_SYSCALL(compat_20_getfsstat)(register_t res, ) {}
PRE_SYSCALL(compat_43_olseek)() {}
POST_SYSCALL(compat_43_olseek)(register_t res, ) {}
PRE_SYSCALL(getpid)() {}
POST_SYSCALL(getpid)(register_t res, ) {}
PRE_SYSCALL(compat_40_mount)() {}
POST_SYSCALL(compat_40_mount)(register_t res, ) {}
PRE_SYSCALL(unmount)() {}
POST_SYSCALL(unmount)(register_t res, ) {}
PRE_SYSCALL(setuid)() {}
POST_SYSCALL(setuid)(register_t res, ) {}
PRE_SYSCALL(getuid)() {}
POST_SYSCALL(getuid)(register_t res, ) {}
PRE_SYSCALL(geteuid)() {}
POST_SYSCALL(geteuid)(register_t res, ) {}
PRE_SYSCALL(ptrace)() {}
POST_SYSCALL(ptrace)(register_t res, ) {}
PRE_SYSCALL(recvmsg)() {}
POST_SYSCALL(recvmsg)(register_t res, ) {}
PRE_SYSCALL(sendmsg)() {}
POST_SYSCALL(sendmsg)(register_t res, ) {}
PRE_SYSCALL(recvfrom)() {}
POST_SYSCALL(recvfrom)(register_t res, ) {}
PRE_SYSCALL(accept)() {}
POST_SYSCALL(accept)(register_t res, ) {}
PRE_SYSCALL(getpeername)() {}
POST_SYSCALL(getpeername)(register_t res, ) {}
PRE_SYSCALL(getsockname)() {}
POST_SYSCALL(getsockname)(register_t res, ) {}
PRE_SYSCALL(access)() {}
POST_SYSCALL(access)(register_t res, ) {}
PRE_SYSCALL(chflags)() {}
POST_SYSCALL(chflags)(register_t res, ) {}
PRE_SYSCALL(fchflags)() {}
POST_SYSCALL(fchflags)(register_t res, ) {}
PRE_SYSCALL(sync)() {}
POST_SYSCALL(sync)(register_t res, ) {}
PRE_SYSCALL(kill)() {}
POST_SYSCALL(kill)(register_t res, ) {}
PRE_SYSCALL(compat_43_stat43)() {}
POST_SYSCALL(compat_43_stat43)(register_t res, ) {}
PRE_SYSCALL(getppid)() {}
POST_SYSCALL(getppid)(register_t res, ) {}
PRE_SYSCALL(compat_43_lstat43)() {}
POST_SYSCALL(compat_43_lstat43)(register_t res, ) {}
PRE_SYSCALL(dup)() {}
POST_SYSCALL(dup)(register_t res, ) {}
PRE_SYSCALL(pipe)() {}
POST_SYSCALL(pipe)(register_t res, ) {}
PRE_SYSCALL(getegid)() {}
POST_SYSCALL(getegid)(register_t res, ) {}
PRE_SYSCALL(profil)() {}
POST_SYSCALL(profil)(register_t res, ) {}
PRE_SYSCALL(ktrace)() {}
POST_SYSCALL(ktrace)(register_t res, ) {}
PRE_SYSCALL(compat_13_sigaction13)() {}
POST_SYSCALL(compat_13_sigaction13)(register_t res, ) {}
PRE_SYSCALL(getgid)() {}
POST_SYSCALL(getgid)(register_t res, ) {}
PRE_SYSCALL(compat_13_sigprocmask13)() {}
POST_SYSCALL(compat_13_sigprocmask13)(register_t res, ) {}
PRE_SYSCALL(__getlogin)() {}
POST_SYSCALL(__getlogin)(register_t res, ) {}
PRE_SYSCALL(__setlogin)() {}
POST_SYSCALL(__setlogin)(register_t res, ) {}
PRE_SYSCALL(acct)() {}
POST_SYSCALL(acct)(register_t res, ) {}
PRE_SYSCALL(compat_13_sigpending13)() {}
POST_SYSCALL(compat_13_sigpending13)(register_t res, ) {}
PRE_SYSCALL(compat_13_sigaltstack13)() {}
POST_SYSCALL(compat_13_sigaltstack13)(register_t res, ) {}
PRE_SYSCALL(ioctl)() {}
POST_SYSCALL(ioctl)(register_t res, ) {}
PRE_SYSCALL(compat_12_oreboot)() {}
POST_SYSCALL(compat_12_oreboot)(register_t res, ) {}
PRE_SYSCALL(revoke)() {}
POST_SYSCALL(revoke)(register_t res, ) {}
PRE_SYSCALL(symlink)() {}
POST_SYSCALL(symlink)(register_t res, ) {}
PRE_SYSCALL(readlink)() {}
POST_SYSCALL(readlink)(register_t res, ) {}
PRE_SYSCALL(execve)() {}
POST_SYSCALL(execve)(register_t res, ) {}
PRE_SYSCALL(umask)() {}
POST_SYSCALL(umask)(register_t res, ) {}
PRE_SYSCALL(chroot)() {}
POST_SYSCALL(chroot)(register_t res, ) {}
PRE_SYSCALL(compat_43_fstat43)() {}
POST_SYSCALL(compat_43_fstat43)(register_t res, ) {}
PRE_SYSCALL(compat_43_ogetkerninfo)() {}
POST_SYSCALL(compat_43_ogetkerninfo)(register_t res, ) {}
PRE_SYSCALL(compat_43_ogetpagesize)() {}
POST_SYSCALL(compat_43_ogetpagesize)(register_t res, ) {}
PRE_SYSCALL(compat_12_msync)() {}
POST_SYSCALL(compat_12_msync)(register_t res, ) {}
PRE_SYSCALL(vfork)() {}
POST_SYSCALL(vfork)(register_t res, ) {}
/* syscall 67 has been skipped */
/* syscall 68 has been skipped */
PRE_SYSCALL(sbrk)() {}
POST_SYSCALL(sbrk)(register_t res, ) {}
PRE_SYSCALL(sstk)() {}
POST_SYSCALL(sstk)(register_t res, ) {}
PRE_SYSCALL(compat_43_ommap)() {}
POST_SYSCALL(compat_43_ommap)(register_t res, ) {}
PRE_SYSCALL(vadvise)() {}
POST_SYSCALL(vadvise)(register_t res, ) {}
PRE_SYSCALL(munmap)() {}
POST_SYSCALL(munmap)(register_t res, ) {}
PRE_SYSCALL(mprotect)() {}
POST_SYSCALL(mprotect)(register_t res, ) {}
PRE_SYSCALL(madvise)() {}
POST_SYSCALL(madvise)(register_t res, ) {}
/* syscall 76 has been skipped */
/* syscall 77 has been skipped */
PRE_SYSCALL(mincore)() {}
POST_SYSCALL(mincore)(register_t res, ) {}
PRE_SYSCALL(getgroups)() {}
POST_SYSCALL(getgroups)(register_t res, ) {}
PRE_SYSCALL(setgroups)() {}
POST_SYSCALL(setgroups)(register_t res, ) {}
PRE_SYSCALL(getpgrp)() {}
POST_SYSCALL(getpgrp)(register_t res, ) {}
PRE_SYSCALL(setpgid)() {}
POST_SYSCALL(setpgid)(register_t res, ) {}
PRE_SYSCALL(compat_50_setitimer)() {}
POST_SYSCALL(compat_50_setitimer)(register_t res, ) {}
PRE_SYSCALL(compat_43_owait)() {}
POST_SYSCALL(compat_43_owait)(register_t res, ) {}
PRE_SYSCALL(compat_12_oswapon)() {}
POST_SYSCALL(compat_12_oswapon)(register_t res, ) {}
PRE_SYSCALL(compat_50_getitimer)() {}
POST_SYSCALL(compat_50_getitimer)(register_t res, ) {}
PRE_SYSCALL(compat_43_ogethostname)() {}
POST_SYSCALL(compat_43_ogethostname)(register_t res, ) {}
PRE_SYSCALL(compat_43_osethostname)() {}
POST_SYSCALL(compat_43_osethostname)(register_t res, ) {}
PRE_SYSCALL(compat_43_ogetdtablesize)() {}
POST_SYSCALL(compat_43_ogetdtablesize)(register_t res, ) {}
PRE_SYSCALL(dup2)() {}
POST_SYSCALL(dup2)(register_t res, ) {}
/* syscall 91 has been skipped */
PRE_SYSCALL(fcntl)() {}
POST_SYSCALL(fcntl)(register_t res, ) {}
PRE_SYSCALL(compat_50_select)() {}
POST_SYSCALL(compat_50_select)(register_t res, ) {}
/* syscall 94 has been skipped */
PRE_SYSCALL(fsync)() {}
POST_SYSCALL(fsync)(register_t res, ) {}
PRE_SYSCALL(setpriority)() {}
POST_SYSCALL(setpriority)(register_t res, ) {}
PRE_SYSCALL(compat_30_socket)() {}
POST_SYSCALL(compat_30_socket)(register_t res, ) {}
PRE_SYSCALL(connect)() {}
POST_SYSCALL(connect)(register_t res, ) {}
PRE_SYSCALL(compat_43_oaccept)() {}
POST_SYSCALL(compat_43_oaccept)(register_t res, ) {}
PRE_SYSCALL(getpriority)() {}
POST_SYSCALL(getpriority)(register_t res, ) {}
PRE_SYSCALL(compat_43_osend)() {}
POST_SYSCALL(compat_43_osend)(register_t res, ) {}
PRE_SYSCALL(compat_43_orecv)() {}
POST_SYSCALL(compat_43_orecv)(register_t res, ) {}
PRE_SYSCALL(compat_13_sigreturn13)() {}
POST_SYSCALL(compat_13_sigreturn13)(register_t res, ) {}
PRE_SYSCALL(bind)() {}
POST_SYSCALL(bind)(register_t res, ) {}
PRE_SYSCALL(setsockopt)() {}
POST_SYSCALL(setsockopt)(register_t res, ) {}
PRE_SYSCALL(listen)() {}
POST_SYSCALL(listen)(register_t res, ) {}
/* syscall 107 has been skipped */
PRE_SYSCALL(compat_43_osigvec)() {}
POST_SYSCALL(compat_43_osigvec)(register_t res, ) {}
PRE_SYSCALL(compat_43_osigblock)() {}
POST_SYSCALL(compat_43_osigblock)(register_t res, ) {}
PRE_SYSCALL(compat_43_osigsetmask)() {}
POST_SYSCALL(compat_43_osigsetmask)(register_t res, ) {}
PRE_SYSCALL(compat_13_sigsuspend13)() {}
POST_SYSCALL(compat_13_sigsuspend13)(register_t res, ) {}
PRE_SYSCALL(compat_43_osigstack)() {}
POST_SYSCALL(compat_43_osigstack)(register_t res, ) {}
PRE_SYSCALL(compat_43_orecvmsg)() {}
POST_SYSCALL(compat_43_orecvmsg)(register_t res, ) {}
PRE_SYSCALL(compat_43_osendmsg)() {}
POST_SYSCALL(compat_43_osendmsg)(register_t res, ) {}
/* syscall 115 has been skipped */
PRE_SYSCALL(compat_50_gettimeofday)() {}
POST_SYSCALL(compat_50_gettimeofday)(register_t res, ) {}
PRE_SYSCALL(compat_50_getrusage)() {}
POST_SYSCALL(compat_50_getrusage)(register_t res, ) {}
PRE_SYSCALL(getsockopt)() {}
POST_SYSCALL(getsockopt)(register_t res, ) {}
/* syscall 119 has been skipped */
PRE_SYSCALL(readv)() {}
POST_SYSCALL(readv)(register_t res, ) {}
PRE_SYSCALL(writev)() {}
POST_SYSCALL(writev)(register_t res, ) {}
PRE_SYSCALL(compat_50_settimeofday)() {}
POST_SYSCALL(compat_50_settimeofday)(register_t res, ) {}
PRE_SYSCALL(fchown)() {}
POST_SYSCALL(fchown)(register_t res, ) {}
PRE_SYSCALL(fchmod)() {}
POST_SYSCALL(fchmod)(register_t res, ) {}
PRE_SYSCALL(compat_43_orecvfrom)() {}
POST_SYSCALL(compat_43_orecvfrom)(register_t res, ) {}
PRE_SYSCALL(setreuid)() {}
POST_SYSCALL(setreuid)(register_t res, ) {}
PRE_SYSCALL(setregid)() {}
POST_SYSCALL(setregid)(register_t res, ) {}
PRE_SYSCALL(rename)() {}
POST_SYSCALL(rename)(register_t res, ) {}
PRE_SYSCALL(compat_43_otruncate)() {}
POST_SYSCALL(compat_43_otruncate)(register_t res, ) {}
PRE_SYSCALL(compat_43_oftruncate)() {}
POST_SYSCALL(compat_43_oftruncate)(register_t res, ) {}
PRE_SYSCALL(flock)() {}
POST_SYSCALL(flock)(register_t res, ) {}
PRE_SYSCALL(mkfifo)() {}
POST_SYSCALL(mkfifo)(register_t res, ) {}
PRE_SYSCALL(sendto)() {}
POST_SYSCALL(sendto)(register_t res, ) {}
PRE_SYSCALL(shutdown)() {}
POST_SYSCALL(shutdown)(register_t res, ) {}
PRE_SYSCALL(socketpair)() {}
POST_SYSCALL(socketpair)(register_t res, ) {}
PRE_SYSCALL(mkdir)() {}
POST_SYSCALL(mkdir)(register_t res, ) {}
PRE_SYSCALL(rmdir)() {}
POST_SYSCALL(rmdir)(register_t res, ) {}
PRE_SYSCALL(compat_50_utimes)() {}
POST_SYSCALL(compat_50_utimes)(register_t res, ) {}
/* syscall 139 has been skipped */
PRE_SYSCALL(compat_50_adjtime)() {}
POST_SYSCALL(compat_50_adjtime)(register_t res, ) {}
PRE_SYSCALL(compat_43_ogetpeername)() {}
POST_SYSCALL(compat_43_ogetpeername)(register_t res, ) {}
PRE_SYSCALL(compat_43_ogethostid)() {}
POST_SYSCALL(compat_43_ogethostid)(register_t res, ) {}
PRE_SYSCALL(compat_43_osethostid)() {}
POST_SYSCALL(compat_43_osethostid)(register_t res, ) {}
PRE_SYSCALL(compat_43_ogetrlimit)() {}
POST_SYSCALL(compat_43_ogetrlimit)(register_t res, ) {}
PRE_SYSCALL(compat_43_osetrlimit)() {}
POST_SYSCALL(compat_43_osetrlimit)(register_t res, ) {}
PRE_SYSCALL(compat_43_okillpg)() {}
POST_SYSCALL(compat_43_okillpg)(register_t res, ) {}
PRE_SYSCALL(setsid)() {}
POST_SYSCALL(setsid)(register_t res, ) {}
PRE_SYSCALL(compat_50_quotactl)() {}
POST_SYSCALL(compat_50_quotactl)(register_t res, ) {}
PRE_SYSCALL(compat_43_oquota)() {}
POST_SYSCALL(compat_43_oquota)(register_t res, ) {}
PRE_SYSCALL(compat_43_ogetsockname)() {}
POST_SYSCALL(compat_43_ogetsockname)(register_t res, ) {}
/* syscall 151 has been skipped */
/* syscall 152 has been skipped */
/* syscall 153 has been skipped */
/* syscall 154 has been skipped */
PRE_SYSCALL(nfssvc)() {}
POST_SYSCALL(nfssvc)(register_t res, ) {}
PRE_SYSCALL(compat_43_ogetdirentries)() {}
POST_SYSCALL(compat_43_ogetdirentries)(register_t res, ) {}
PRE_SYSCALL(compat_20_statfs)() {}
POST_SYSCALL(compat_20_statfs)(register_t res, ) {}
PRE_SYSCALL(compat_20_fstatfs)() {}
POST_SYSCALL(compat_20_fstatfs)(register_t res, ) {}
/* syscall 159 has been skipped */
/* syscall 160 has been skipped */
PRE_SYSCALL(compat_30_getfh)() {}
POST_SYSCALL(compat_30_getfh)(register_t res, ) {}
PRE_SYSCALL(compat_09_ogetdomainname)() {}
POST_SYSCALL(compat_09_ogetdomainname)(register_t res, ) {}
PRE_SYSCALL(compat_09_osetdomainname)() {}
POST_SYSCALL(compat_09_osetdomainname)(register_t res, ) {}
PRE_SYSCALL(compat_09_ouname)() {}
POST_SYSCALL(compat_09_ouname)(register_t res, ) {}
PRE_SYSCALL(sysarch)() {}
POST_SYSCALL(sysarch)(register_t res, ) {}
/* syscall 166 has been skipped */
/* syscall 167 has been skipped */
/* syscall 168 has been skipped */
#if !defined(_LP64)
PRE_SYSCALL(compat_10_osemsys)() {}
POST_SYSCALL(compat_10_osemsys)(register_t res, ) {}
#else
/* syscall 169 has been skipped */
#if !defined(_LP64)
PRE_SYSCALL(compat_10_omsgsys)() {}
POST_SYSCALL(compat_10_omsgsys)(register_t res, ) {}
#else
/* syscall 170 has been skipped */
#if !defined(_LP64)
PRE_SYSCALL(compat_10_oshmsys)() {}
POST_SYSCALL(compat_10_oshmsys)(register_t res, ) {}
#else
/* syscall 171 has been skipped */
#endif
/* syscall 172 has been skipped */
PRE_SYSCALL(pread)() {}
POST_SYSCALL(pread)(register_t res, ) {}
PRE_SYSCALL(pwrite)() {}
POST_SYSCALL(pwrite)(register_t res, ) {}
PRE_SYSCALL(compat_30_ntp_gettime)() {}
POST_SYSCALL(compat_30_ntp_gettime)(register_t res, ) {}
#if defined(NTP) || !defined(_KERNEL_OPT)
PRE_SYSCALL(ntp_adjtime)() {}
POST_SYSCALL(ntp_adjtime)(register_t res, ) {}
#else
/* syscall 176 has been skipped */
#endif
/* syscall 177 has been skipped */
/* syscall 178 has been skipped */
/* syscall 179 has been skipped */
/* syscall 180 has been skipped */
PRE_SYSCALL(setgid)() {}
POST_SYSCALL(setgid)(register_t res, ) {}
PRE_SYSCALL(setegid)() {}
POST_SYSCALL(setegid)(register_t res, ) {}
PRE_SYSCALL(seteuid)() {}
POST_SYSCALL(seteuid)(register_t res, ) {}
PRE_SYSCALL(lfs_bmapv)() {}
POST_SYSCALL(lfs_bmapv)(register_t res, ) {}
PRE_SYSCALL(lfs_markv)() {}
POST_SYSCALL(lfs_markv)(register_t res, ) {}
PRE_SYSCALL(lfs_segclean)() {}
POST_SYSCALL(lfs_segclean)(register_t res, ) {}
PRE_SYSCALL(compat_50_lfs_segwait)() {}
POST_SYSCALL(compat_50_lfs_segwait)(register_t res, ) {}
PRE_SYSCALL(compat_12_stat12)() {}
POST_SYSCALL(compat_12_stat12)(register_t res, ) {}
PRE_SYSCALL(compat_12_fstat12)() {}
POST_SYSCALL(compat_12_fstat12)(register_t res, ) {}
PRE_SYSCALL(compat_12_lstat12)() {}
POST_SYSCALL(compat_12_lstat12)(register_t res, ) {}
PRE_SYSCALL(pathconf)() {}
POST_SYSCALL(pathconf)(register_t res, ) {}
PRE_SYSCALL(fpathconf)() {}
POST_SYSCALL(fpathconf)(register_t res, ) {}
/* syscall 193 has been skipped */
PRE_SYSCALL(getrlimit)() {}
POST_SYSCALL(getrlimit)(register_t res, ) {}
PRE_SYSCALL(setrlimit)() {}
POST_SYSCALL(setrlimit)(register_t res, ) {}
PRE_SYSCALL(compat_12_getdirentries)() {}
POST_SYSCALL(compat_12_getdirentries)(register_t res, ) {}
PRE_SYSCALL(mmap)() {}
POST_SYSCALL(mmap)(register_t res, ) {}
PRE_SYSCALL(__syscall)() {}
POST_SYSCALL(__syscall)(register_t res, ) {}
PRE_SYSCALL(lseek)() {}
POST_SYSCALL(lseek)(register_t res, ) {}
PRE_SYSCALL(truncate)() {}
POST_SYSCALL(truncate)(register_t res, ) {}
PRE_SYSCALL(ftruncate)() {}
POST_SYSCALL(ftruncate)(register_t res, ) {}
PRE_SYSCALL(__sysctl)() {}
POST_SYSCALL(__sysctl)(register_t res, ) {}
PRE_SYSCALL(mlock)() {}
POST_SYSCALL(mlock)(register_t res, ) {}
PRE_SYSCALL(munlock)() {}
POST_SYSCALL(munlock)(register_t res, ) {}
PRE_SYSCALL(undelete)() {}
POST_SYSCALL(undelete)(register_t res, ) {}
PRE_SYSCALL(compat_50_futimes)() {}
POST_SYSCALL(compat_50_futimes)(register_t res, ) {}
PRE_SYSCALL(getpgid)() {}
POST_SYSCALL(getpgid)(register_t res, ) {}
PRE_SYSCALL(reboot)() {}
POST_SYSCALL(reboot)(register_t res, ) {}
PRE_SYSCALL(poll)() {}
POST_SYSCALL(poll)(register_t res, ) {}
PRE_SYSCALL(afssys)() {}
POST_SYSCALL(afssys)(register_t res, ) {}
/* syscall 211 has been skipped */
/* syscall 212 has been skipped */
/* syscall 213 has been skipped */
/* syscall 214 has been skipped */
/* syscall 215 has been skipped */
/* syscall 216 has been skipped */
/* syscall 217 has been skipped */
/* syscall 218 has been skipped */
/* syscall 219 has been skipped */
PRE_SYSCALL(compat_14___semctl)() {}
POST_SYSCALL(compat_14___semctl)(register_t res, ) {}
PRE_SYSCALL(semget)() {}
POST_SYSCALL(semget)(register_t res, ) {}
PRE_SYSCALL(semop)() {}
POST_SYSCALL(semop)(register_t res, ) {}
PRE_SYSCALL(semconfig)() {}
POST_SYSCALL(semconfig)(register_t res, ) {}
PRE_SYSCALL(compat_14_msgctl)() {}
POST_SYSCALL(compat_14_msgctl)(register_t res, ) {}
PRE_SYSCALL(msgget)() {}
POST_SYSCALL(msgget)(register_t res, ) {}
PRE_SYSCALL(msgsnd)() {}
POST_SYSCALL(msgsnd)(register_t res, ) {}
PRE_SYSCALL(msgrcv)() {}
POST_SYSCALL(msgrcv)(register_t res, ) {}
PRE_SYSCALL(shmat)() {}
POST_SYSCALL(shmat)(register_t res, ) {}
PRE_SYSCALL(compat_14_shmctl)() {}
POST_SYSCALL(compat_14_shmctl)(register_t res, ) {}
PRE_SYSCALL(shmdt)() {}
POST_SYSCALL(shmdt)(register_t res, ) {}
PRE_SYSCALL(shmget)() {}
POST_SYSCALL(shmget)(register_t res, ) {}
PRE_SYSCALL(compat_50_clock_gettime)() {}
POST_SYSCALL(compat_50_clock_gettime)(register_t res, ) {}
PRE_SYSCALL(compat_50_clock_settime)() {}
POST_SYSCALL(compat_50_clock_settime)(register_t res, ) {}
PRE_SYSCALL(compat_50_clock_getres)() {}
POST_SYSCALL(compat_50_clock_getres)(register_t res, ) {}
PRE_SYSCALL(timer_create)() {}
POST_SYSCALL(timer_create)(register_t res, ) {}
PRE_SYSCALL(timer_delete)() {}
POST_SYSCALL(timer_delete)(register_t res, ) {}
PRE_SYSCALL(compat_50_timer_settime)() {}
POST_SYSCALL(compat_50_timer_settime)(register_t res, ) {}
PRE_SYSCALL(compat_50_timer_gettime)() {}
POST_SYSCALL(compat_50_timer_gettime)(register_t res, ) {}
PRE_SYSCALL(timer_getoverrun)() {}
POST_SYSCALL(timer_getoverrun)(register_t res, ) {}
PRE_SYSCALL(compat_50_nanosleep)() {}
POST_SYSCALL(compat_50_nanosleep)(register_t res, ) {}
PRE_SYSCALL(fdatasync)() {}
POST_SYSCALL(fdatasync)(register_t res, ) {}
PRE_SYSCALL(mlockall)() {}
POST_SYSCALL(mlockall)(register_t res, ) {}
PRE_SYSCALL(munlockall)() {}
POST_SYSCALL(munlockall)(register_t res, ) {}
PRE_SYSCALL(compat_50___sigtimedwait)() {}
POST_SYSCALL(compat_50___sigtimedwait)(register_t res, ) {}
PRE_SYSCALL(sigqueueinfo)() {}
POST_SYSCALL(sigqueueinfo)(register_t res, ) {}
PRE_SYSCALL(modctl)() {}
POST_SYSCALL(modctl)(register_t res, ) {}
PRE_SYSCALL(_ksem_init)() {}
POST_SYSCALL(_ksem_init)(register_t res, ) {}
PRE_SYSCALL(_ksem_open)() {}
POST_SYSCALL(_ksem_open)(register_t res, ) {}
PRE_SYSCALL(_ksem_unlink)() {}
POST_SYSCALL(_ksem_unlink)(register_t res, ) {}
PRE_SYSCALL(_ksem_close)() {}
POST_SYSCALL(_ksem_close)(register_t res, ) {}
PRE_SYSCALL(_ksem_post)() {}
POST_SYSCALL(_ksem_post)(register_t res, ) {}
PRE_SYSCALL(_ksem_wait)() {}
POST_SYSCALL(_ksem_wait)(register_t res, ) {}
PRE_SYSCALL(_ksem_trywait)() {}
POST_SYSCALL(_ksem_trywait)(register_t res, ) {}
PRE_SYSCALL(_ksem_getvalue)() {}
POST_SYSCALL(_ksem_getvalue)(register_t res, ) {}
PRE_SYSCALL(_ksem_destroy)() {}
POST_SYSCALL(_ksem_destroy)(register_t res, ) {}
PRE_SYSCALL(_ksem_timedwait)() {}
POST_SYSCALL(_ksem_timedwait)(register_t res, ) {}
PRE_SYSCALL(mq_open)() {}
POST_SYSCALL(mq_open)(register_t res, ) {}
PRE_SYSCALL(mq_close)() {}
POST_SYSCALL(mq_close)(register_t res, ) {}
PRE_SYSCALL(mq_unlink)() {}
POST_SYSCALL(mq_unlink)(register_t res, ) {}
PRE_SYSCALL(mq_getattr)() {}
POST_SYSCALL(mq_getattr)(register_t res, ) {}
PRE_SYSCALL(mq_setattr)() {}
POST_SYSCALL(mq_setattr)(register_t res, ) {}
PRE_SYSCALL(mq_notify)() {}
POST_SYSCALL(mq_notify)(register_t res, ) {}
PRE_SYSCALL(mq_send)() {}
POST_SYSCALL(mq_send)(register_t res, ) {}
PRE_SYSCALL(mq_receive)() {}
POST_SYSCALL(mq_receive)(register_t res, ) {}
PRE_SYSCALL(compat_50_mq_timedsend)() {}
POST_SYSCALL(compat_50_mq_timedsend)(register_t res, ) {}
PRE_SYSCALL(compat_50_mq_timedreceive)() {}
POST_SYSCALL(compat_50_mq_timedreceive)(register_t res, ) {}
/* syscall 267 has been skipped */
/* syscall 268 has been skipped */
/* syscall 269 has been skipped */
PRE_SYSCALL(__posix_rename)() {}
POST_SYSCALL(__posix_rename)(register_t res, ) {}
PRE_SYSCALL(swapctl)() {}
POST_SYSCALL(swapctl)(register_t res, ) {}
PRE_SYSCALL(compat_30_getdents)() {}
POST_SYSCALL(compat_30_getdents)(register_t res, ) {}
PRE_SYSCALL(minherit)() {}
POST_SYSCALL(minherit)(register_t res, ) {}
PRE_SYSCALL(lchmod)() {}
POST_SYSCALL(lchmod)(register_t res, ) {}
PRE_SYSCALL(lchown)() {}
POST_SYSCALL(lchown)(register_t res, ) {}
PRE_SYSCALL(compat_50_lutimes)() {}
POST_SYSCALL(compat_50_lutimes)(register_t res, ) {}
PRE_SYSCALL(__msync13)() {}
POST_SYSCALL(__msync13)(register_t res, ) {}
PRE_SYSCALL(compat_30___stat13)() {}
POST_SYSCALL(compat_30___stat13)(register_t res, ) {}
PRE_SYSCALL(compat_30___fstat13)() {}
POST_SYSCALL(compat_30___fstat13)(register_t res, ) {}
PRE_SYSCALL(compat_30___lstat13)() {}
POST_SYSCALL(compat_30___lstat13)(register_t res, ) {}
PRE_SYSCALL(__sigaltstack14)() {}
POST_SYSCALL(__sigaltstack14)(register_t res, ) {}
PRE_SYSCALL(__vfork14)() {}
POST_SYSCALL(__vfork14)(register_t res, ) {}
PRE_SYSCALL(__posix_chown)() {}
POST_SYSCALL(__posix_chown)(register_t res, ) {}
PRE_SYSCALL(__posix_fchown)() {}
POST_SYSCALL(__posix_fchown)(register_t res, ) {}
PRE_SYSCALL(__posix_lchown)() {}
POST_SYSCALL(__posix_lchown)(register_t res, ) {}
PRE_SYSCALL(getsid)() {}
POST_SYSCALL(getsid)(register_t res, ) {}
PRE_SYSCALL(__clone)() {}
POST_SYSCALL(__clone)(register_t res, ) {}
PRE_SYSCALL(fktrace)() {}
POST_SYSCALL(fktrace)(register_t res, ) {}
PRE_SYSCALL(preadv)() {}
POST_SYSCALL(preadv)(register_t res, ) {}
PRE_SYSCALL(pwritev)() {}
POST_SYSCALL(pwritev)(register_t res, ) {}
PRE_SYSCALL(compat_16___sigaction14)() {}
POST_SYSCALL(compat_16___sigaction14)(register_t res, ) {}
PRE_SYSCALL(__sigpending14)() {}
POST_SYSCALL(__sigpending14)(register_t res, ) {}
PRE_SYSCALL(__sigprocmask14)() {}
POST_SYSCALL(__sigprocmask14)(register_t res, ) {}
PRE_SYSCALL(__sigsuspend14)() {}
POST_SYSCALL(__sigsuspend14)(register_t res, ) {}
PRE_SYSCALL(compat_16___sigreturn14)() {}
POST_SYSCALL(compat_16___sigreturn14)(register_t res, ) {}
PRE_SYSCALL(__getcwd)() {}
POST_SYSCALL(__getcwd)(register_t res, ) {}
PRE_SYSCALL(fchroot)() {}
POST_SYSCALL(fchroot)(register_t res, ) {}
PRE_SYSCALL(compat_30_fhopen)() {}
POST_SYSCALL(compat_30_fhopen)(register_t res, ) {}
PRE_SYSCALL(compat_30_fhstat)() {}
POST_SYSCALL(compat_30_fhstat)(register_t res, ) {}
PRE_SYSCALL(compat_20_fhstatfs)() {}
POST_SYSCALL(compat_20_fhstatfs)(register_t res, ) {}
PRE_SYSCALL(compat_50_____semctl13)() {}
POST_SYSCALL(compat_50_____semctl13)(register_t res, ) {}
PRE_SYSCALL(compat_50___msgctl13)() {}
POST_SYSCALL(compat_50___msgctl13)(register_t res, ) {}
PRE_SYSCALL(compat_50___shmctl13)() {}
POST_SYSCALL(compat_50___shmctl13)(register_t res, ) {}
PRE_SYSCALL(lchflags)() {}
POST_SYSCALL(lchflags)(register_t res, ) {}
PRE_SYSCALL(issetugid)() {}
POST_SYSCALL(issetugid)(register_t res, ) {}
PRE_SYSCALL(utrace)() {}
POST_SYSCALL(utrace)(register_t res, ) {}
PRE_SYSCALL(getcontext)() {}
POST_SYSCALL(getcontext)(register_t res, ) {}
PRE_SYSCALL(setcontext)() {}
POST_SYSCALL(setcontext)(register_t res, ) {}
PRE_SYSCALL(_lwp_create)() {}
POST_SYSCALL(_lwp_create)(register_t res, ) {}
PRE_SYSCALL(_lwp_exit)() {}
POST_SYSCALL(_lwp_exit)(register_t res, ) {}
PRE_SYSCALL(_lwp_self)() {}
POST_SYSCALL(_lwp_self)(register_t res, ) {}
PRE_SYSCALL(_lwp_wait)() {}
POST_SYSCALL(_lwp_wait)(register_t res, ) {}
PRE_SYSCALL(_lwp_suspend)() {}
POST_SYSCALL(_lwp_suspend)(register_t res, ) {}
PRE_SYSCALL(_lwp_continue)() {}
POST_SYSCALL(_lwp_continue)(register_t res, ) {}
PRE_SYSCALL(_lwp_wakeup)() {}
POST_SYSCALL(_lwp_wakeup)(register_t res, ) {}
PRE_SYSCALL(_lwp_getprivate)() {}
POST_SYSCALL(_lwp_getprivate)(register_t res, ) {}
PRE_SYSCALL(_lwp_setprivate)() {}
POST_SYSCALL(_lwp_setprivate)(register_t res, ) {}
PRE_SYSCALL(_lwp_kill)() {}
POST_SYSCALL(_lwp_kill)(register_t res, ) {}
PRE_SYSCALL(_lwp_detach)() {}
POST_SYSCALL(_lwp_detach)(register_t res, ) {}
PRE_SYSCALL(compat_50__lwp_park)() {}
POST_SYSCALL(compat_50__lwp_park)(register_t res, ) {}
PRE_SYSCALL(_lwp_unpark)() {}
POST_SYSCALL(_lwp_unpark)(register_t res, ) {}
PRE_SYSCALL(_lwp_unpark_all)() {}
POST_SYSCALL(_lwp_unpark_all)(register_t res, ) {}
PRE_SYSCALL(_lwp_setname)() {}
POST_SYSCALL(_lwp_setname)(register_t res, ) {}
PRE_SYSCALL(_lwp_getname)() {}
POST_SYSCALL(_lwp_getname)(register_t res, ) {}
PRE_SYSCALL(_lwp_ctl)() {}
POST_SYSCALL(_lwp_ctl)(register_t res, ) {}
/* syscall 326 has been skipped */
/* syscall 327 has been skipped */
/* syscall 328 has been skipped */
/* syscall 329 has been skipped */
PRE_SYSCALL(compat_60_sa_register)() {}
POST_SYSCALL(compat_60_sa_register)(register_t res, ) {}
PRE_SYSCALL(compat_60_sa_stacks)() {}
POST_SYSCALL(compat_60_sa_stacks)(register_t res, ) {}
PRE_SYSCALL(compat_60_sa_enable)() {}
POST_SYSCALL(compat_60_sa_enable)(register_t res, ) {}
PRE_SYSCALL(compat_60_sa_setconcurrency)() {}
POST_SYSCALL(compat_60_sa_setconcurrency)(register_t res, ) {}
PRE_SYSCALL(compat_60_sa_yield)() {}
POST_SYSCALL(compat_60_sa_yield)(register_t res, ) {}
PRE_SYSCALL(compat_60_sa_preempt)() {}
POST_SYSCALL(compat_60_sa_preempt)(register_t res, ) {}
/* syscall 336 has been skipped */
/* syscall 337 has been skipped */
/* syscall 338 has been skipped */
/* syscall 339 has been skipped */
PRE_SYSCALL(__sigaction_sigtramp)() {}
POST_SYSCALL(__sigaction_sigtramp)(register_t res, ) {}
PRE_SYSCALL(pmc_get_info)() {}
POST_SYSCALL(pmc_get_info)(register_t res, ) {}
PRE_SYSCALL(pmc_control)() {}
POST_SYSCALL(pmc_control)(register_t res, ) {}
PRE_SYSCALL(rasctl)() {}
POST_SYSCALL(rasctl)(register_t res, ) {}
PRE_SYSCALL(kqueue)() {}
POST_SYSCALL(kqueue)(register_t res, ) {}
PRE_SYSCALL(compat_50_kevent)() {}
POST_SYSCALL(compat_50_kevent)(register_t res, ) {}
PRE_SYSCALL(_sched_setparam)() {}
POST_SYSCALL(_sched_setparam)(register_t res, ) {}
PRE_SYSCALL(_sched_getparam)() {}
POST_SYSCALL(_sched_getparam)(register_t res, ) {}
PRE_SYSCALL(_sched_setaffinity)() {}
POST_SYSCALL(_sched_setaffinity)(register_t res, ) {}
PRE_SYSCALL(_sched_getaffinity)() {}
POST_SYSCALL(_sched_getaffinity)(register_t res, ) {}
PRE_SYSCALL(sched_yield)() {}
POST_SYSCALL(sched_yield)(register_t res, ) {}
PRE_SYSCALL(_sched_protect)() {}
POST_SYSCALL(_sched_protect)(register_t res, ) {}
/* syscall 352 has been skipped */
/* syscall 353 has been skipped */
PRE_SYSCALL(fsync_range)() {}
POST_SYSCALL(fsync_range)(register_t res, ) {}
PRE_SYSCALL(uuidgen)() {}
POST_SYSCALL(uuidgen)(register_t res, ) {}
PRE_SYSCALL(getvfsstat)() {}
POST_SYSCALL(getvfsstat)(register_t res, ) {}
PRE_SYSCALL(statvfs1)() {}
POST_SYSCALL(statvfs1)(register_t res, ) {}
PRE_SYSCALL(fstatvfs1)() {}
POST_SYSCALL(fstatvfs1)(register_t res, ) {}
PRE_SYSCALL(compat_30_fhstatvfs1)() {}
POST_SYSCALL(compat_30_fhstatvfs1)(register_t res, ) {}
PRE_SYSCALL(extattrctl)() {}
POST_SYSCALL(extattrctl)(register_t res, ) {}
PRE_SYSCALL(extattr_set_file)() {}
POST_SYSCALL(extattr_set_file)(register_t res, ) {}
PRE_SYSCALL(extattr_get_file)() {}
POST_SYSCALL(extattr_get_file)(register_t res, ) {}
PRE_SYSCALL(extattr_delete_file)() {}
POST_SYSCALL(extattr_delete_file)(register_t res, ) {}
PRE_SYSCALL(extattr_set_fd)() {}
POST_SYSCALL(extattr_set_fd)(register_t res, ) {}
PRE_SYSCALL(extattr_get_fd)() {}
POST_SYSCALL(extattr_get_fd)(register_t res, ) {}
PRE_SYSCALL(extattr_delete_fd)() {}
POST_SYSCALL(extattr_delete_fd)(register_t res, ) {}
PRE_SYSCALL(extattr_set_link)() {}
POST_SYSCALL(extattr_set_link)(register_t res, ) {}
PRE_SYSCALL(extattr_get_link)() {}
POST_SYSCALL(extattr_get_link)(register_t res, ) {}
PRE_SYSCALL(extattr_delete_link)() {}
POST_SYSCALL(extattr_delete_link)(register_t res, ) {}
PRE_SYSCALL(extattr_list_fd)() {}
POST_SYSCALL(extattr_list_fd)(register_t res, ) {}
PRE_SYSCALL(extattr_list_file)() {}
POST_SYSCALL(extattr_list_file)(register_t res, ) {}
PRE_SYSCALL(extattr_list_link)() {}
POST_SYSCALL(extattr_list_link)(register_t res, ) {}
PRE_SYSCALL(compat_50_pselect)() {}
POST_SYSCALL(compat_50_pselect)(register_t res, ) {}
PRE_SYSCALL(compat_50_pollts)() {}
POST_SYSCALL(compat_50_pollts)(register_t res, ) {}
PRE_SYSCALL(setxattr)() {}
POST_SYSCALL(setxattr)(register_t res, ) {}
PRE_SYSCALL(lsetxattr)() {}
POST_SYSCALL(lsetxattr)(register_t res, ) {}
PRE_SYSCALL(fsetxattr)() {}
POST_SYSCALL(fsetxattr)(register_t res, ) {}
PRE_SYSCALL(getxattr)() {}
POST_SYSCALL(getxattr)(register_t res, ) {}
PRE_SYSCALL(lgetxattr)() {}
POST_SYSCALL(lgetxattr)(register_t res, ) {}
PRE_SYSCALL(fgetxattr)() {}
POST_SYSCALL(fgetxattr)(register_t res, ) {}
PRE_SYSCALL(listxattr)() {}
POST_SYSCALL(listxattr)(register_t res, ) {}
PRE_SYSCALL(llistxattr)() {}
POST_SYSCALL(llistxattr)(register_t res, ) {}
PRE_SYSCALL(flistxattr)() {}
POST_SYSCALL(flistxattr)(register_t res, ) {}
PRE_SYSCALL(removexattr)() {}
POST_SYSCALL(removexattr)(register_t res, ) {}
PRE_SYSCALL(lremovexattr)() {}
POST_SYSCALL(lremovexattr)(register_t res, ) {}
PRE_SYSCALL(fremovexattr)() {}
POST_SYSCALL(fremovexattr)(register_t res, ) {}
PRE_SYSCALL(compat_50___stat30)() {}
POST_SYSCALL(compat_50___stat30)(register_t res, ) {}
PRE_SYSCALL(compat_50___fstat30)() {}
POST_SYSCALL(compat_50___fstat30)(register_t res, ) {}
PRE_SYSCALL(compat_50___lstat30)() {}
POST_SYSCALL(compat_50___lstat30)(register_t res, ) {}
PRE_SYSCALL(__getdents30)() {}
POST_SYSCALL(__getdents30)(register_t res, ) {}
PRE_SYSCALL(posix_fadvise)() {}
POST_SYSCALL(posix_fadvise)(register_t res, ) {}
PRE_SYSCALL(compat_30___fhstat30)() {}
POST_SYSCALL(compat_30___fhstat30)(register_t res, ) {}
PRE_SYSCALL(compat_50___ntp_gettime30)() {}
POST_SYSCALL(compat_50___ntp_gettime30)(register_t res, ) {}
PRE_SYSCALL(__socket30)() {}
POST_SYSCALL(__socket30)(register_t res, ) {}
PRE_SYSCALL(__getfh30)() {}
POST_SYSCALL(__getfh30)(register_t res, ) {}
PRE_SYSCALL(__fhopen40)() {}
POST_SYSCALL(__fhopen40)(register_t res, ) {}
PRE_SYSCALL(__fhstatvfs140)() {}
POST_SYSCALL(__fhstatvfs140)(register_t res, ) {}
PRE_SYSCALL(compat_50___fhstat40)() {}
POST_SYSCALL(compat_50___fhstat40)(register_t res, ) {}
PRE_SYSCALL(aio_cancel)() {}
POST_SYSCALL(aio_cancel)(register_t res, ) {}
PRE_SYSCALL(aio_error)() {}
POST_SYSCALL(aio_error)(register_t res, ) {}
PRE_SYSCALL(aio_fsync)() {}
POST_SYSCALL(aio_fsync)(register_t res, ) {}
PRE_SYSCALL(aio_read)() {}
POST_SYSCALL(aio_read)(register_t res, ) {}
PRE_SYSCALL(aio_return)() {}
POST_SYSCALL(aio_return)(register_t res, ) {}
PRE_SYSCALL(compat_50_aio_suspend)() {}
POST_SYSCALL(compat_50_aio_suspend)(register_t res, ) {}
PRE_SYSCALL(aio_write)() {}
POST_SYSCALL(aio_write)(register_t res, ) {}
PRE_SYSCALL(lio_listio)() {}
POST_SYSCALL(lio_listio)(register_t res, ) {}
/* syscall 407 has been skipped */
/* syscall 408 has been skipped */
/* syscall 409 has been skipped */
PRE_SYSCALL(__mount50)() {}
POST_SYSCALL(__mount50)(register_t res, ) {}
PRE_SYSCALL(mremap)() {}
POST_SYSCALL(mremap)(register_t res, ) {}
PRE_SYSCALL(pset_create)() {}
POST_SYSCALL(pset_create)(register_t res, ) {}
PRE_SYSCALL(pset_destroy)() {}
POST_SYSCALL(pset_destroy)(register_t res, ) {}
PRE_SYSCALL(pset_assign)() {}
POST_SYSCALL(pset_assign)(register_t res, ) {}
PRE_SYSCALL(_pset_bind)() {}
POST_SYSCALL(_pset_bind)(register_t res, ) {}
PRE_SYSCALL(__posix_fadvise50)() {}
POST_SYSCALL(__posix_fadvise50)(register_t res, ) {}
PRE_SYSCALL(__select50)() {}
POST_SYSCALL(__select50)(register_t res, ) {}
PRE_SYSCALL(__gettimeofday50)() {}
POST_SYSCALL(__gettimeofday50)(register_t res, ) {}
PRE_SYSCALL(__settimeofday50)() {}
POST_SYSCALL(__settimeofday50)(register_t res, ) {}
PRE_SYSCALL(__utimes50)() {}
POST_SYSCALL(__utimes50)(register_t res, ) {}
PRE_SYSCALL(__adjtime50)() {}
POST_SYSCALL(__adjtime50)(register_t res, ) {}
PRE_SYSCALL(__lfs_segwait50)() {}
POST_SYSCALL(__lfs_segwait50)(register_t res, ) {}
PRE_SYSCALL(__futimes50)() {}
POST_SYSCALL(__futimes50)(register_t res, ) {}
PRE_SYSCALL(__lutimes50)() {}
POST_SYSCALL(__lutimes50)(register_t res, ) {}
PRE_SYSCALL(__setitimer50)() {}
POST_SYSCALL(__setitimer50)(register_t res, ) {}
PRE_SYSCALL(__getitimer50)() {}
POST_SYSCALL(__getitimer50)(register_t res, ) {}
PRE_SYSCALL(__clock_gettime50)() {}
POST_SYSCALL(__clock_gettime50)(register_t res, ) {}
PRE_SYSCALL(__clock_settime50)() {}
POST_SYSCALL(__clock_settime50)(register_t res, ) {}
PRE_SYSCALL(__clock_getres50)() {}
POST_SYSCALL(__clock_getres50)(register_t res, ) {}
PRE_SYSCALL(__nanosleep50)() {}
POST_SYSCALL(__nanosleep50)(register_t res, ) {}
PRE_SYSCALL(____sigtimedwait50)() {}
POST_SYSCALL(____sigtimedwait50)(register_t res, ) {}
PRE_SYSCALL(__mq_timedsend50)() {}
POST_SYSCALL(__mq_timedsend50)(register_t res, ) {}
PRE_SYSCALL(__mq_timedreceive50)() {}
POST_SYSCALL(__mq_timedreceive50)(register_t res, ) {}
PRE_SYSCALL(compat_60__lwp_park)() {}
POST_SYSCALL(compat_60__lwp_park)(register_t res, ) {}
PRE_SYSCALL(__kevent50)() {}
POST_SYSCALL(__kevent50)(register_t res, ) {}
PRE_SYSCALL(__pselect50)() {}
POST_SYSCALL(__pselect50)(register_t res, ) {}
PRE_SYSCALL(__pollts50)() {}
POST_SYSCALL(__pollts50)(register_t res, ) {}
PRE_SYSCALL(__aio_suspend50)() {}
POST_SYSCALL(__aio_suspend50)(register_t res, ) {}
PRE_SYSCALL(__stat50)() {}
POST_SYSCALL(__stat50)(register_t res, ) {}
PRE_SYSCALL(__fstat50)() {}
POST_SYSCALL(__fstat50)(register_t res, ) {}
PRE_SYSCALL(__lstat50)() {}
POST_SYSCALL(__lstat50)(register_t res, ) {}
PRE_SYSCALL(____semctl50)() {}
POST_SYSCALL(____semctl50)(register_t res, ) {}
PRE_SYSCALL(__shmctl50)() {}
POST_SYSCALL(__shmctl50)(register_t res, ) {}
PRE_SYSCALL(__msgctl50)() {}
POST_SYSCALL(__msgctl50)(register_t res, ) {}
PRE_SYSCALL(__getrusage50)() {}
POST_SYSCALL(__getrusage50)(register_t res, ) {}
PRE_SYSCALL(__timer_settime50)() {}
POST_SYSCALL(__timer_settime50)(register_t res, ) {}
PRE_SYSCALL(__timer_gettime50)() {}
POST_SYSCALL(__timer_gettime50)(register_t res, ) {}
#if defined(NTP) || !defined(_KERNEL_OPT)
PRE_SYSCALL(__ntp_gettime50)() {}
POST_SYSCALL(__ntp_gettime50)(register_t res, ) {}
#else
/* syscall 448 has been skipped */
#endif
PRE_SYSCALL(__wait450)() {}
POST_SYSCALL(__wait450)(register_t res, ) {}
PRE_SYSCALL(__mknod50)() {}
POST_SYSCALL(__mknod50)(register_t res, ) {}
PRE_SYSCALL(__fhstat50)() {}
POST_SYSCALL(__fhstat50)(register_t res, ) {}
/* syscall 452 has been skipped */
PRE_SYSCALL(pipe2)() {}
POST_SYSCALL(pipe2)(register_t res, ) {}
PRE_SYSCALL(dup3)() {}
POST_SYSCALL(dup3)(register_t res, ) {}
PRE_SYSCALL(kqueue1)() {}
POST_SYSCALL(kqueue1)(register_t res, ) {}
PRE_SYSCALL(paccept)() {}
POST_SYSCALL(paccept)(register_t res, ) {}
PRE_SYSCALL(linkat)() {}
POST_SYSCALL(linkat)(register_t res, ) {}
PRE_SYSCALL(renameat)() {}
POST_SYSCALL(renameat)(register_t res, ) {}
PRE_SYSCALL(mkfifoat)() {}
POST_SYSCALL(mkfifoat)(register_t res, ) {}
PRE_SYSCALL(mknodat)() {}
POST_SYSCALL(mknodat)(register_t res, ) {}
PRE_SYSCALL(mkdirat)() {}
POST_SYSCALL(mkdirat)(register_t res, ) {}
PRE_SYSCALL(faccessat)() {}
POST_SYSCALL(faccessat)(register_t res, ) {}
PRE_SYSCALL(fchmodat)() {}
POST_SYSCALL(fchmodat)(register_t res, ) {}
PRE_SYSCALL(fchownat)() {}
POST_SYSCALL(fchownat)(register_t res, ) {}
PRE_SYSCALL(fexecve)() {}
POST_SYSCALL(fexecve)(register_t res, ) {}
PRE_SYSCALL(fstatat)() {}
POST_SYSCALL(fstatat)(register_t res, ) {}
PRE_SYSCALL(utimensat)() {}
POST_SYSCALL(utimensat)(register_t res, ) {}
PRE_SYSCALL(openat)() {}
POST_SYSCALL(openat)(register_t res, ) {}
PRE_SYSCALL(readlinkat)() {}
POST_SYSCALL(readlinkat)(register_t res, ) {}
PRE_SYSCALL(symlinkat)() {}
POST_SYSCALL(symlinkat)(register_t res, ) {}
PRE_SYSCALL(unlinkat)() {}
POST_SYSCALL(unlinkat)(register_t res, ) {}
PRE_SYSCALL(futimens)() {}
POST_SYSCALL(futimens)(register_t res, ) {}
PRE_SYSCALL(__quotactl)() {}
POST_SYSCALL(__quotactl)(register_t res, ) {}
PRE_SYSCALL(posix_spawn)() {}
POST_SYSCALL(posix_spawn)(register_t res, ) {}
PRE_SYSCALL(recvmmsg)() {}
POST_SYSCALL(recvmmsg)(register_t res, ) {}
PRE_SYSCALL(sendmmsg)() {}
POST_SYSCALL(sendmmsg)(register_t res, ) {}
PRE_SYSCALL(clock_nanosleep)() {}
POST_SYSCALL(clock_nanosleep)(register_t res, ) {}
PRE_SYSCALL(___lwp_park60)() {}
POST_SYSCALL(___lwp_park60)(register_t res, ) {}
PRE_SYSCALL(posix_fallocate)() {}
POST_SYSCALL(posix_fallocate)(register_t res, ) {}
PRE_SYSCALL(fdiscard)() {}
POST_SYSCALL(fdiscard)(register_t res, ) {}
PRE_SYSCALL(wait6)() {}
POST_SYSCALL(wait6)(register_t res, ) {}
PRE_SYSCALL(clock_getcpuclockid2)() {}
POST_SYSCALL(clock_getcpuclockid2)(register_t res, ) {}
}  // extern "C"

#undef PRE_SYSCALL
#undef PRE_READ
#undef PRE_WRITE
#undef POST_SYSCALL
#undef POST_READ
#undef POST_WRITE

#endif // SANITIZER_NETBSD
