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
PRE_SYSCALL(syscall)(int code, register_t args[SYS_MAXSYSARGS]) {}
POST_SYSCALL(syscall)
(register_t res, int code, register_t args[SYS_MAXSYSARGS]) {}
PRE_SYSCALL(exit)(int rval) {}
POST_SYSCALL(exit)(register_t res, int rval) {}
PRE_SYSCALL(fork)(void) {}
POST_SYSCALL(fork)(register_t res) {}
PRE_SYSCALL(read)(int fd, void *buf, size_t nbyte) {}
POST_SYSCALL(read)(register_t res, int fd, void *buf, size_t nbyte) {}
PRE_SYSCALL(write)(int fd, const void *buf, size_t nbyte) {}
POST_SYSCALL(write)(register_t res, int fd, const void *buf, size_t nbyte) {}
PRE_SYSCALL(open)(const char *path, int flags, mode_t mode) {}
POST_SYSCALL(open)(register_t res, const char *path, int flags, mode_t mode) {}
PRE_SYSCALL(close)(int fd) {}
POST_SYSCALL(close)(register_t res, int fd) {}
PRE_SYSCALL(compat_50_wait4)
(pid_t pid, int *status, int options, struct rusage50 *rusage) {}
POST_SYSCALL(compat_50_wait4)
(register_t res, pid_t pid, int *status, int options, struct rusage50 *rusage) {
}
PRE_SYSCALL(compat_43_ocreat)(const char *path, mode_t mode) {}
POST_SYSCALL(compat_43_ocreat)(register_t res, const char *path, mode_t mode) {}
PRE_SYSCALL(link)(const char *path, const char *link) {}
POST_SYSCALL(link)(register_t res, const char *path, const char *link) {}
PRE_SYSCALL(unlink)(const char *path) {}
POST_SYSCALL(unlink)(register_t res, const char *path) {}
/* syscall 11 has been skipped */
PRE_SYSCALL(chdir)(const char *path) {}
POST_SYSCALL(chdir)(register_t res, const char *path) {}
PRE_SYSCALL(fchdir)(int fd) {}
POST_SYSCALL(fchdir)(register_t res, int fd) {}
PRE_SYSCALL(compat_50_mknod)(const char *path, mode_t mode, uint32_t dev) {}
POST_SYSCALL(compat_50_mknod)
(register_t res, const char *path, mode_t mode, uint32_t dev) {}
PRE_SYSCALL(chmod)(const char *path, mode_t mode) {}
POST_SYSCALL(chmod)(register_t res, const char *path, mode_t mode) {}
PRE_SYSCALL(chown)(const char *path, uid_t uid, gid_t gid) {}
POST_SYSCALL(chown)(register_t res, const char *path, uid_t uid, gid_t gid) {}
PRE_SYSCALL(break)(char *nsize) {}
POST_SYSCALL(break)(register_t res, char *nsize) {}
PRE_SYSCALL(compat_20_getfsstat)
(struct statfs12 *buf, long bufsize, int flags) {}
POST_SYSCALL(compat_20_getfsstat)
(register_t res, struct statfs12 *buf, long bufsize, int flags) {}
PRE_SYSCALL(compat_43_olseek)(int fd, long offset, int whence) {}
POST_SYSCALL(compat_43_olseek)
(register_t res, int fd, long offset, int whence) {}
PRE_SYSCALL(getpid)(void) {}
POST_SYSCALL(getpid)(register_t res) {}
PRE_SYSCALL(compat_40_mount)
(const char *type, const char *path, int flags, void *data) {}
POST_SYSCALL(compat_40_mount)
(register_t res, const char *type, const char *path, int flags, void *data) {}
PRE_SYSCALL(unmount)(const char *path, int flags) {}
POST_SYSCALL(unmount)(register_t res, const char *path, int flags) {}
PRE_SYSCALL(setuid)(uid_t uid) {}
POST_SYSCALL(setuid)(register_t res, uid_t uid) {}
PRE_SYSCALL(getuid)(void) {}
POST_SYSCALL(getuid)(register_t res) {}
PRE_SYSCALL(geteuid)(void) {}
POST_SYSCALL(geteuid)(register_t res) {}
PRE_SYSCALL(ptrace)(int req, pid_t pid, void *addr, int data) {}
POST_SYSCALL(ptrace)
(register_t res, int req, pid_t pid, void *addr, int data) {}
PRE_SYSCALL(recvmsg)(int s, struct msghdr *msg, int flags) {}
POST_SYSCALL(recvmsg)(register_t res, int s, struct msghdr *msg, int flags) {}
PRE_SYSCALL(sendmsg)(int s, const struct msghdr *msg, int flags) {}
POST_SYSCALL(sendmsg)
(register_t res, int s, const struct msghdr *msg, int flags) {}
PRE_SYSCALL(recvfrom)
(int s, void *buf, size_t len, int flags, struct sockaddr *from,
 socklen_t *fromlenaddr) {}
POST_SYSCALL(recvfrom)
(register_t res, int s, void *buf, size_t len, int flags, struct sockaddr *from,
 socklen_t *fromlenaddr) {}
PRE_SYSCALL(accept)(int s, struct sockaddr *name, socklen_t *anamelen) {}
POST_SYSCALL(accept)
(register_t res, int s, struct sockaddr *name, socklen_t *anamelen) {}
PRE_SYSCALL(getpeername)(int fdes, struct sockaddr *asa, socklen_t *alen) {}
POST_SYSCALL(getpeername)
(register_t res, int fdes, struct sockaddr *asa, socklen_t *alen) {}
PRE_SYSCALL(getsockname)(int fdes, struct sockaddr *asa, socklen_t *alen) {}
POST_SYSCALL(getsockname)
(register_t res, int fdes, struct sockaddr *asa, socklen_t *alen) {}
PRE_SYSCALL(access)(const char *path, int flags) {}
POST_SYSCALL(access)(register_t res, const char *path, int flags) {}
PRE_SYSCALL(chflags)(const char *path, u_long flags) {}
POST_SYSCALL(chflags)(register_t res, const char *path, u_long flags) {}
PRE_SYSCALL(fchflags)(int fd, u_long flags) {}
POST_SYSCALL(fchflags)(register_t res, int fd, u_long flags) {}
PRE_SYSCALL(sync)(void) {}
POST_SYSCALL(sync)(register_t res) {}
PRE_SYSCALL(kill)(pid_t pid, int signum) {}
POST_SYSCALL(kill)(register_t res, pid_t pid, int signum) {}
PRE_SYSCALL(compat_43_stat43)(const char *path, struct stat43 *ub) {}
POST_SYSCALL(compat_43_stat43)
(register_t res, const char *path, struct stat43 *ub) {}
PRE_SYSCALL(getppid)(void) {}
POST_SYSCALL(getppid)(register_t res) {}
PRE_SYSCALL(compat_43_lstat43)(const char *path, struct stat43 *ub) {}
POST_SYSCALL(compat_43_lstat43)
(register_t res, const char *path, struct stat43 *ub) {}
PRE_SYSCALL(dup)(int fd) {}
POST_SYSCALL(dup)(register_t res, int fd) {}
PRE_SYSCALL(pipe)(void) {}
POST_SYSCALL(pipe)(register_t res) {}
PRE_SYSCALL(getegid)(void) {}
POST_SYSCALL(getegid)(register_t res) {}
PRE_SYSCALL(profil)(char *samples, size_t size, u_long offset, u_int scale) {}
POST_SYSCALL(profil)
(register_t res, char *samples, size_t size, u_long offset, u_int scale) {}
PRE_SYSCALL(ktrace)(const char *fname, int ops, int facs, pid_t pid) {}
POST_SYSCALL(ktrace)
(register_t res, const char *fname, int ops, int facs, pid_t pid) {}
PRE_SYSCALL(compat_13_sigaction13)
(int signum, const struct sigaction13 *nsa, struct sigaction13 *osa) {}
POST_SYSCALL(compat_13_sigaction13)
(register_t res, int signum, const struct sigaction13 *nsa,
 struct sigaction13 *osa) {}
PRE_SYSCALL(getgid)(void) {}
POST_SYSCALL(getgid)(register_t res) {}
PRE_SYSCALL(compat_13_sigprocmask13)(int how, int mask) {}
POST_SYSCALL(compat_13_sigprocmask13)(register_t res, int how, int mask) {}
PRE_SYSCALL(__getlogin)(char *namebuf, size_t namelen) {}
POST_SYSCALL(__getlogin)(register_t res, char *namebuf, size_t namelen) {}
PRE_SYSCALL(__setlogin)(const char *namebuf) {}
POST_SYSCALL(__setlogin)(register_t res, const char *namebuf) {}
PRE_SYSCALL(acct)(const char *path) {}
POST_SYSCALL(acct)(register_t res, const char *path) {}
PRE_SYSCALL(compat_13_sigpending13)(void) {}
POST_SYSCALL(compat_13_sigpending13)(register_t res) {}
PRE_SYSCALL(compat_13_sigaltstack13)
(const struct sigaltstack13 *nss, struct sigaltstack13 *oss) {}
POST_SYSCALL(compat_13_sigaltstack13)
(register_t res, const struct sigaltstack13 *nss, struct sigaltstack13 *oss) {}
PRE_SYSCALL(ioctl)(int fd, u_long com, void *data) {}
POST_SYSCALL(ioctl)(register_t res, int fd, u_long com, void *data) {}
PRE_SYSCALL(compat_12_oreboot)(int opt) {}
POST_SYSCALL(compat_12_oreboot)(register_t res, int opt) {}
PRE_SYSCALL(revoke)(const char *path) {}
POST_SYSCALL(revoke)(register_t res, const char *path) {}
PRE_SYSCALL(symlink)(const char *path, const char *link) {}
POST_SYSCALL(symlink)(register_t res, const char *path, const char *link) {}
PRE_SYSCALL(readlink)(const char *path, char *buf, size_t count) {}
POST_SYSCALL(readlink)
(register_t res, const char *path, char *buf, size_t count) {}
PRE_SYSCALL(execve)(const char *path, char *const *argp, char *const *envp) {}
POST_SYSCALL(execve)
(register_t res, const char *path, char *const *argp, char *const *envp) {}
PRE_SYSCALL(umask)(mode_t newmask) {}
POST_SYSCALL(umask)(register_t res, mode_t newmask) {}
PRE_SYSCALL(chroot)(const char *path) {}
POST_SYSCALL(chroot)(register_t res, const char *path) {}
PRE_SYSCALL(compat_43_fstat43)(int fd, struct stat43 *sb) {}
POST_SYSCALL(compat_43_fstat43)(register_t res, int fd, struct stat43 *sb) {}
PRE_SYSCALL(compat_43_ogetkerninfo)(int op, char *where, int *size, int arg) {}
POST_SYSCALL(compat_43_ogetkerninfo)
(register_t res, int op, char *where, int *size, int arg) {}
PRE_SYSCALL(compat_43_ogetpagesize)(void) {}
POST_SYSCALL(compat_43_ogetpagesize)(register_t res) {}
PRE_SYSCALL(compat_12_msync)(void *addr, size_t len) {}
POST_SYSCALL(compat_12_msync)(register_t res, void *addr, size_t len) {}
PRE_SYSCALL(vfork)(void) {}
POST_SYSCALL(vfork)(register_t res) {}
/* syscall 67 has been skipped */
/* syscall 68 has been skipped */
PRE_SYSCALL(sbrk)(intptr_t incr) {}
POST_SYSCALL(sbrk)(register_t res, intptr_t incr) {}
PRE_SYSCALL(sstk)(int incr) {}
POST_SYSCALL(sstk)(register_t res, int incr) {}
PRE_SYSCALL(compat_43_ommap)
(void *addr, size_t len, int prot, int flags, int fd, long pos) {}
POST_SYSCALL(compat_43_ommap)
(register_t res, void *addr, size_t len, int prot, int flags, int fd,
 long pos) {}
PRE_SYSCALL(vadvise)(int anom) {}
POST_SYSCALL(vadvise)(register_t res, int anom) {}
PRE_SYSCALL(munmap)(void *addr, size_t len) {}
POST_SYSCALL(munmap)(register_t res, void *addr, size_t len) {}
PRE_SYSCALL(mprotect)(void *addr, size_t len, int prot) {}
POST_SYSCALL(mprotect)(register_t res, void *addr, size_t len, int prot) {}
PRE_SYSCALL(madvise)(void *addr, size_t len, int behav) {}
POST_SYSCALL(madvise)(register_t res, void *addr, size_t len, int behav) {}
/* syscall 76 has been skipped */
/* syscall 77 has been skipped */
PRE_SYSCALL(mincore)(void *addr, size_t len, char *vec) {}
POST_SYSCALL(mincore)(register_t res, void *addr, size_t len, char *vec) {}
PRE_SYSCALL(getgroups)(int gidsetsize, gid_t *gidset) {}
POST_SYSCALL(getgroups)(register_t res, int gidsetsize, gid_t *gidset) {}
PRE_SYSCALL(setgroups)(int gidsetsize, const gid_t *gidset) {}
POST_SYSCALL(setgroups)(register_t res, int gidsetsize, const gid_t *gidset) {}
PRE_SYSCALL(getpgrp)(void) {}
POST_SYSCALL(getpgrp)(register_t res) {}
PRE_SYSCALL(setpgid)(pid_t pid, pid_t pgid) {}
POST_SYSCALL(setpgid)(register_t res, pid_t pid, pid_t pgid) {}
PRE_SYSCALL(compat_50_setitimer)
(int which, const struct itimerval50 *itv, struct itimerval50 *oitv) {}
POST_SYSCALL(compat_50_setitimer)
(register_t res, int which, const struct itimerval50 *itv,
 struct itimerval50 *oitv) {}
PRE_SYSCALL(compat_43_owait)(void) {}
POST_SYSCALL(compat_43_owait)(register_t res) {}
PRE_SYSCALL(compat_12_oswapon)(const char *name) {}
POST_SYSCALL(compat_12_oswapon)(register_t res, const char *name) {}
PRE_SYSCALL(compat_50_getitimer)(int which, struct itimerval50 *itv) {}
POST_SYSCALL(compat_50_getitimer)
(register_t res, int which, struct itimerval50 *itv) {}
PRE_SYSCALL(compat_43_ogethostname)(char *hostname, u_int len) {}
POST_SYSCALL(compat_43_ogethostname)
(register_t res, char *hostname, u_int len) {}
PRE_SYSCALL(compat_43_osethostname)(char *hostname, u_int len) {}
POST_SYSCALL(compat_43_osethostname)
(register_t res, char *hostname, u_int len) {}
PRE_SYSCALL(compat_43_ogetdtablesize)(void) {}
POST_SYSCALL(compat_43_ogetdtablesize)(register_t res) {}
PRE_SYSCALL(dup2)(int from, int to) {}
POST_SYSCALL(dup2)(register_t res, int from, int to) {}
/* syscall 91 has been skipped */
PRE_SYSCALL(fcntl)(int fd, int cmd, void *arg) {}
POST_SYSCALL(fcntl)(register_t res, int fd, int cmd, void *arg) {}
PRE_SYSCALL(compat_50_select)
(int nd, fd_set *in, fd_set *ou, fd_set *ex, struct timeval50 *tv) {}
POST_SYSCALL(compat_50_select)
(register_t res, int nd, fd_set *in, fd_set *ou, fd_set *ex,
 struct timeval50 *tv) {}
/* syscall 94 has been skipped */
PRE_SYSCALL(fsync)(int fd) {}
POST_SYSCALL(fsync)(register_t res, int fd) {}
PRE_SYSCALL(setpriority)(int which, id_t who, int prio) {}
POST_SYSCALL(setpriority)(register_t res, int which, id_t who, int prio) {}
PRE_SYSCALL(compat_30_socket)(int domain, int type, int protocol) {}
POST_SYSCALL(compat_30_socket)
(register_t res, int domain, int type, int protocol) {}
PRE_SYSCALL(connect)(int s, const struct sockaddr *name, socklen_t namelen) {}
POST_SYSCALL(connect)
(register_t res, int s, const struct sockaddr *name, socklen_t namelen) {}
PRE_SYSCALL(compat_43_oaccept)(int s, void *name, socklen_t *anamelen) {}
POST_SYSCALL(compat_43_oaccept)
(register_t res, int s, void *name, socklen_t *anamelen) {}
PRE_SYSCALL(getpriority)(int which, id_t who) {}
POST_SYSCALL(getpriority)(register_t res, int which, id_t who) {}
PRE_SYSCALL(compat_43_osend)(int s, void *buf, int len, int flags) {}
POST_SYSCALL(compat_43_osend)
(register_t res, int s, void *buf, int len, int flags) {}
PRE_SYSCALL(compat_43_orecv)(int s, void *buf, int len, int flags) {}
POST_SYSCALL(compat_43_orecv)
(register_t res, int s, void *buf, int len, int flags) {}
PRE_SYSCALL(compat_13_sigreturn13)(struct sigcontext13 *sigcntxp) {}
POST_SYSCALL(compat_13_sigreturn13)
(register_t res, struct sigcontext13 *sigcntxp) {}
PRE_SYSCALL(bind)(int s, const struct sockaddr *name, socklen_t namelen) {}
POST_SYSCALL(bind)
(register_t res, int s, const struct sockaddr *name, socklen_t namelen) {}
PRE_SYSCALL(setsockopt)
(int s, int level, int name, const void *val, socklen_t valsize) {}
POST_SYSCALL(setsockopt)
(register_t res, int s, int level, int name, const void *val,
 socklen_t valsize) {}
PRE_SYSCALL(listen)(int s, int backlog) {}
POST_SYSCALL(listen)(register_t res, int s, int backlog) {}
/* syscall 107 has been skipped */
PRE_SYSCALL(compat_43_osigvec)
(int signum, struct sigvec *nsv, struct sigvec *osv) {}
POST_SYSCALL(compat_43_osigvec)
(register_t res, int signum, struct sigvec *nsv, struct sigvec *osv) {}
PRE_SYSCALL(compat_43_osigblock)(int mask) {}
POST_SYSCALL(compat_43_osigblock)(register_t res, int mask) {}
PRE_SYSCALL(compat_43_osigsetmask)(int mask) {}
POST_SYSCALL(compat_43_osigsetmask)(register_t res, int mask) {}
PRE_SYSCALL(compat_13_sigsuspend13)(int mask) {}
POST_SYSCALL(compat_13_sigsuspend13)(register_t res, int mask) {}
PRE_SYSCALL(compat_43_osigstack)(struct sigstack *nss, struct sigstack *oss) {}
POST_SYSCALL(compat_43_osigstack)
(register_t res, struct sigstack *nss, struct sigstack *oss) {}
PRE_SYSCALL(compat_43_orecvmsg)(int s, struct omsghdr *msg, int flags) {}
POST_SYSCALL(compat_43_orecvmsg)
(register_t res, int s, struct omsghdr *msg, int flags) {}
PRE_SYSCALL(compat_43_osendmsg)(int s, void *msg, int flags) {}
POST_SYSCALL(compat_43_osendmsg)(register_t res, int s, void *msg, int flags) {}
/* syscall 115 has been skipped */
PRE_SYSCALL(compat_50_gettimeofday)(struct timeval50 *tp, void *tzp) {}
POST_SYSCALL(compat_50_gettimeofday)
(register_t res, struct timeval50 *tp, void *tzp) {}
PRE_SYSCALL(compat_50_getrusage)(int who, struct rusage50 *rusage) {}
POST_SYSCALL(compat_50_getrusage)
(register_t res, int who, struct rusage50 *rusage) {}
PRE_SYSCALL(getsockopt)
(int s, int level, int name, void *val, socklen_t *avalsize) {}
POST_SYSCALL(getsockopt)
(register_t res, int s, int level, int name, void *val, socklen_t *avalsize) {}
/* syscall 119 has been skipped */
PRE_SYSCALL(readv)(int fd, const struct iovec *iovp, int iovcnt) {}
POST_SYSCALL(readv)
(register_t res, int fd, const struct iovec *iovp, int iovcnt) {}
PRE_SYSCALL(writev)(int fd, const struct iovec *iovp, int iovcnt) {}
POST_SYSCALL(writev)
(register_t res, int fd, const struct iovec *iovp, int iovcnt) {}
PRE_SYSCALL(compat_50_settimeofday)
(const struct timeval50 *tv, const void *tzp) {}
POST_SYSCALL(compat_50_settimeofday)
(register_t res, const struct timeval50 *tv, const void *tzp) {}
PRE_SYSCALL(fchown)(int fd, uid_t uid, gid_t gid) {}
POST_SYSCALL(fchown)(register_t res, int fd, uid_t uid, gid_t gid) {}
PRE_SYSCALL(fchmod)(int fd, mode_t mode) {}
POST_SYSCALL(fchmod)(register_t res, int fd, mode_t mode) {}
PRE_SYSCALL(compat_43_orecvfrom)
(int s, void *buf, size_t len, int flags, void *from, socklen_t *fromlenaddr) {}
POST_SYSCALL(compat_43_orecvfrom)
(register_t res, int s, void *buf, size_t len, int flags, void *from,
 socklen_t *fromlenaddr) {}
PRE_SYSCALL(setreuid)(uid_t ruid, uid_t euid) {}
POST_SYSCALL(setreuid)(register_t res, uid_t ruid, uid_t euid) {}
PRE_SYSCALL(setregid)(gid_t rgid, gid_t egid) {}
POST_SYSCALL(setregid)(register_t res, gid_t rgid, gid_t egid) {}
PRE_SYSCALL(rename)(const char *from, const char *to) {}
POST_SYSCALL(rename)(register_t res, const char *from, const char *to) {}
PRE_SYSCALL(compat_43_otruncate)(const char *path, long length) {}
POST_SYSCALL(compat_43_otruncate)
(register_t res, const char *path, long length) {}
PRE_SYSCALL(compat_43_oftruncate)(int fd, long length) {}
POST_SYSCALL(compat_43_oftruncate)(register_t res, int fd, long length) {}
PRE_SYSCALL(flock)(int fd, int how) {}
POST_SYSCALL(flock)(register_t res, int fd, int how) {}
PRE_SYSCALL(mkfifo)(const char *path, mode_t mode) {}
POST_SYSCALL(mkfifo)(register_t res, const char *path, mode_t mode) {}
PRE_SYSCALL(sendto)
(int s, const void *buf, size_t len, int flags, const struct sockaddr *to,
 socklen_t tolen) {}
POST_SYSCALL(sendto)
(register_t res, int s, const void *buf, size_t len, int flags,
 const struct sockaddr *to, socklen_t tolen) {}
PRE_SYSCALL(shutdown)(int s, int how) {}
POST_SYSCALL(shutdown)(register_t res, int s, int how) {}
PRE_SYSCALL(socketpair)(int domain, int type, int protocol, int *rsv) {}
POST_SYSCALL(socketpair)
(register_t res, int domain, int type, int protocol, int *rsv) {}
PRE_SYSCALL(mkdir)(const char *path, mode_t mode) {}
POST_SYSCALL(mkdir)(register_t res, const char *path, mode_t mode) {}
PRE_SYSCALL(rmdir)(const char *path) {}
POST_SYSCALL(rmdir)(register_t res, const char *path) {}
PRE_SYSCALL(compat_50_utimes)(const char *path, const struct timeval50 *tptr) {}
POST_SYSCALL(compat_50_utimes)
(register_t res, const char *path, const struct timeval50 *tptr) {}
/* syscall 139 has been skipped */
PRE_SYSCALL(compat_50_adjtime)
(const struct timeval50 *delta, struct timeval50 *olddelta) {}
POST_SYSCALL(compat_50_adjtime)
(register_t res, const struct timeval50 *delta, struct timeval50 *olddelta) {}
PRE_SYSCALL(compat_43_ogetpeername)(int fdes, void *asa, socklen_t *alen) {}
POST_SYSCALL(compat_43_ogetpeername)
(register_t res, int fdes, void *asa, socklen_t *alen) {}
PRE_SYSCALL(compat_43_ogethostid)(void) {}
POST_SYSCALL(compat_43_ogethostid)(register_t res) {}
PRE_SYSCALL(compat_43_osethostid)(int32_t hostid) {}
POST_SYSCALL(compat_43_osethostid)(register_t res, int32_t hostid) {}
PRE_SYSCALL(compat_43_ogetrlimit)(int which, struct orlimit *rlp) {}
POST_SYSCALL(compat_43_ogetrlimit)
(register_t res, int which, struct orlimit *rlp) {}
PRE_SYSCALL(compat_43_osetrlimit)(int which, const struct orlimit *rlp) {}
POST_SYSCALL(compat_43_osetrlimit)
(register_t res, int which, const struct orlimit *rlp) {}
PRE_SYSCALL(compat_43_okillpg)(int pgid, int signum) {}
POST_SYSCALL(compat_43_okillpg)(register_t res, int pgid, int signum) {}
PRE_SYSCALL(setsid)(void) {}
POST_SYSCALL(setsid)(register_t res) {}
PRE_SYSCALL(compat_50_quotactl)
(const char *path, int cmd, int uid, void *arg) {}
POST_SYSCALL(compat_50_quotactl)
(register_t res, const char *path, int cmd, int uid, void *arg) {}
PRE_SYSCALL(compat_43_oquota)(void) {}
POST_SYSCALL(compat_43_oquota)(register_t res) {}
PRE_SYSCALL(compat_43_ogetsockname)(int fdec, void *asa, socklen_t *alen) {}
POST_SYSCALL(compat_43_ogetsockname)
(register_t res, int fdec, void *asa, socklen_t *alen) {}
/* syscall 151 has been skipped */
/* syscall 152 has been skipped */
/* syscall 153 has been skipped */
/* syscall 154 has been skipped */
PRE_SYSCALL(nfssvc)(int flag, void *argp) {}
POST_SYSCALL(nfssvc)(register_t res, int flag, void *argp) {}
PRE_SYSCALL(compat_43_ogetdirentries)
(int fd, char *buf, u_int count, long *basep) {}
POST_SYSCALL(compat_43_ogetdirentries)
(register_t res, int fd, char *buf, u_int count, long *basep) {}
PRE_SYSCALL(compat_20_statfs)(const char *path, struct statfs12 *buf) {}
POST_SYSCALL(compat_20_statfs)
(register_t res, const char *path, struct statfs12 *buf) {}
PRE_SYSCALL(compat_20_fstatfs)(int fd, struct statfs12 *buf) {}
POST_SYSCALL(compat_20_fstatfs)(register_t res, int fd, struct statfs12 *buf) {}
/* syscall 159 has been skipped */
/* syscall 160 has been skipped */
PRE_SYSCALL(compat_30_getfh)
(const char *fname, struct compat_30_fhandle *fhp) {}
POST_SYSCALL(compat_30_getfh)
(register_t res, const char *fname, struct compat_30_fhandle *fhp) {}
PRE_SYSCALL(compat_09_ogetdomainname)(char *domainname, int len) {}
POST_SYSCALL(compat_09_ogetdomainname)
(register_t res, char *domainname, int len) {}
PRE_SYSCALL(compat_09_osetdomainname)(char *domainname, int len) {}
POST_SYSCALL(compat_09_osetdomainname)
(register_t res, char *domainname, int len) {}
PRE_SYSCALL(compat_09_ouname)(struct outsname *name) {}
POST_SYSCALL(compat_09_ouname)(register_t res, struct outsname *name) {}
PRE_SYSCALL(sysarch)(int op, void *parms) {}
POST_SYSCALL(sysarch)(register_t res, int op, void *parms) {}
/* syscall 166 has been skipped */
/* syscall 167 has been skipped */
/* syscall 168 has been skipped */
#if !defined(_LP64)
PRE_SYSCALL(compat_10_osemsys)(int which, int a2, int a3, int a4, int a5) {}
POST_SYSCALL(compat_10_osemsys)
(register_t res, int which, int a2, int a3, int a4, int a5) {}
#else
/* syscall 169 has been skipped */
#if !defined(_LP64)
PRE_SYSCALL(compat_10_omsgsys)(int which, int a2, int a3, int a4, 			    int a5, int a6) {}
POST_SYSCALL(compat_10_omsgsys)(register_t res, int which, int a2, int a3, int a4, 			    int a5, int a6) {}
#else
/* syscall 170 has been skipped */
#if !defined(_LP64)
PRE_SYSCALL(compat_10_oshmsys)(int which, int a2, int a3, int a4) {}
POST_SYSCALL(compat_10_oshmsys)(register_t res, int which, int a2, int a3, int a4) {}
#else
/* syscall 171 has been skipped */
#endif
/* syscall 172 has been skipped */
PRE_SYSCALL(pread)(int fd, void *buf, 			    size_t nbyte, int PAD, off_t offset) {}
POST_SYSCALL(pread)(register_t res, int fd, void *buf, 			    size_t nbyte, int PAD, off_t offset) {}
PRE_SYSCALL(pwrite)(int fd, const void *buf, 			    size_t nbyte, int PAD, off_t offset) {}
POST_SYSCALL(pwrite)(register_t res, int fd, const void *buf, 			    size_t nbyte, int PAD, off_t offset) {}
PRE_SYSCALL(compat_30_ntp_gettime)(struct ntptimeval30 *ntvp) {}
POST_SYSCALL(compat_30_ntp_gettime)(register_t res, struct ntptimeval30 *ntvp) {}
#if defined(NTP) || !defined(_KERNEL_OPT)
PRE_SYSCALL(ntp_adjtime)(struct timex *tp) {}
POST_SYSCALL(ntp_adjtime)(register_t res, struct timex *tp) {}
#else
/* syscall 176 has been skipped */
#endif
/* syscall 177 has been skipped */
/* syscall 178 has been skipped */
/* syscall 179 has been skipped */
/* syscall 180 has been skipped */
PRE_SYSCALL(setgid)(gid_t gid) {}
POST_SYSCALL(setgid)(register_t res, gid_t gid) {}
PRE_SYSCALL(setegid)(gid_t egid) {}
POST_SYSCALL(setegid)(register_t res, gid_t egid) {}
PRE_SYSCALL(seteuid)(uid_t euid) {}
POST_SYSCALL(seteuid)(register_t res, uid_t euid) {}
PRE_SYSCALL(lfs_bmapv)(fsid_t *fsidp, 			    struct block_info *blkiov, int blkcnt) {}
POST_SYSCALL(lfs_bmapv)(register_t res, fsid_t *fsidp, 			    struct block_info *blkiov, int blkcnt) {}
PRE_SYSCALL(lfs_markv)(fsid_t *fsidp, 			    struct block_info *blkiov, int blkcnt) {}
POST_SYSCALL(lfs_markv)(register_t res, fsid_t *fsidp, 			    struct block_info *blkiov, int blkcnt) {}
PRE_SYSCALL(lfs_segclean)(fsid_t *fsidp, u_long segment) {}
POST_SYSCALL(lfs_segclean)(register_t res, fsid_t *fsidp, u_long segment) {}
PRE_SYSCALL(compat_50_lfs_segwait)(fsid_t *fsidp, 			    struct timeval50 *tv) {}
POST_SYSCALL(compat_50_lfs_segwait)(register_t res, fsid_t *fsidp, 			    struct timeval50 *tv) {}
PRE_SYSCALL(compat_12_stat12)(const char *path, struct stat12 *ub) {}
POST_SYSCALL(compat_12_stat12)(register_t res, const char *path, struct stat12 *ub) {}
PRE_SYSCALL(compat_12_fstat12)(int fd, struct stat12 *sb) {}
POST_SYSCALL(compat_12_fstat12)(register_t res, int fd, struct stat12 *sb) {}
PRE_SYSCALL(compat_12_lstat12)(const char *path, 			    struct stat12 *ub) {}
POST_SYSCALL(compat_12_lstat12)(register_t res, const char *path, 			    struct stat12 *ub) {}
PRE_SYSCALL(pathconf)(const char *path, int name) {}
POST_SYSCALL(pathconf)(register_t res, const char *path, int name) {}
PRE_SYSCALL(fpathconf)(int fd, int name) {}
POST_SYSCALL(fpathconf)(register_t res, int fd, int name) {}
/* syscall 193 has been skipped */
PRE_SYSCALL(getrlimit)(int which, 			    struct rlimit *rlp) {}
POST_SYSCALL(getrlimit)(register_t res, int which, 			    struct rlimit *rlp) {}
PRE_SYSCALL(setrlimit)(int which, 			    const struct rlimit *rlp) {}
POST_SYSCALL(setrlimit)(register_t res, int which, 			    const struct rlimit *rlp) {}
PRE_SYSCALL(compat_12_getdirentries)(int fd, char *buf, 			    u_int count, long *basep) {}
POST_SYSCALL(compat_12_getdirentries)(register_t res, int fd, char *buf, 			    u_int count, long *basep) {}
PRE_SYSCALL(mmap)(void *addr, size_t len, int prot, 			    int flags, int fd, long PAD, off_t pos) {}
POST_SYSCALL(mmap)(register_t res, void *addr, size_t len, int prot, 			    int flags, int fd, long PAD, off_t pos) {}
PRE_SYSCALL(__syscall)(quad_t code, 			     register_t args[SYS_MAXSYSARGS]) {}
POST_SYSCALL(__syscall)(register_t res, quad_t code, 			     register_t args[SYS_MAXSYSARGS]) {}
PRE_SYSCALL(lseek)(int fd, int PAD, off_t offset, 			    int whence) {}
POST_SYSCALL(lseek)(register_t res, int fd, int PAD, off_t offset, 			    int whence) {}
PRE_SYSCALL(truncate)(const char *path, int PAD, 			    off_t length) {}
POST_SYSCALL(truncate)(register_t res, const char *path, int PAD, 			    off_t length) {}
PRE_SYSCALL(ftruncate)(int fd, int PAD, off_t length) {}
POST_SYSCALL(ftruncate)(register_t res, int fd, int PAD, off_t length) {}
PRE_SYSCALL(__sysctl)(const int *name, u_int namelen, 			    void *oldv, size_t *oldlenp, const void *newv, 			    size_t newlen) {}
POST_SYSCALL(__sysctl)(register_t res, const int *name, u_int namelen, 			    void *oldv, size_t *oldlenp, const void *newv, 			    size_t newlen) {}
PRE_SYSCALL(mlock)(const void *addr, size_t len) {}
POST_SYSCALL(mlock)(register_t res, const void *addr, size_t len) {}
PRE_SYSCALL(munlock)(const void *addr, size_t len) {}
POST_SYSCALL(munlock)(register_t res, const void *addr, size_t len) {}
PRE_SYSCALL(undelete)(const char *path) {}
POST_SYSCALL(undelete)(register_t res, const char *path) {}
PRE_SYSCALL(compat_50_futimes)(int fd, 			    const struct timeval50 *tptr) {}
POST_SYSCALL(compat_50_futimes)(register_t res, int fd, 			    const struct timeval50 *tptr) {}
PRE_SYSCALL(getpgid)(pid_t pid) {}
POST_SYSCALL(getpgid)(register_t res, pid_t pid) {}
PRE_SYSCALL(reboot)(int opt, char *bootstr) {}
POST_SYSCALL(reboot)(register_t res, int opt, char *bootstr) {}
PRE_SYSCALL(poll)(struct pollfd *fds, u_int nfds, 			    int timeout) {}
POST_SYSCALL(poll)(register_t res, struct pollfd *fds, u_int nfds, 			    int timeout) {}
PRE_SYSCALL(afssys)(long id, long a1, long a2, 			  long a3, long a4, long a5, long a6) {}
POST_SYSCALL(afssys)(register_t res, long id, long a1, long a2, 			  long a3, long a4, long a5, long a6) {}
/* syscall 211 has been skipped */
/* syscall 212 has been skipped */
/* syscall 213 has been skipped */
/* syscall 214 has been skipped */
/* syscall 215 has been skipped */
/* syscall 216 has been skipped */
/* syscall 217 has been skipped */
/* syscall 218 has been skipped */
/* syscall 219 has been skipped */
PRE_SYSCALL(compat_14___semctl)(int semid, int semnum, int cmd, 			    union __semun *arg) {}
POST_SYSCALL(compat_14___semctl)(register_t res, int semid, int semnum, int cmd, 			    union __semun *arg) {}
PRE_SYSCALL(semget)(key_t key, int nsems, 			    int semflg) {}
POST_SYSCALL(semget)(register_t res, key_t key, int nsems, 			    int semflg) {}
PRE_SYSCALL(semop)(int semid, struct sembuf *sops, 			    size_t nsops) {}
POST_SYSCALL(semop)(register_t res, int semid, struct sembuf *sops, 			    size_t nsops) {}
PRE_SYSCALL(semconfig)(int flag) {}
POST_SYSCALL(semconfig)(register_t res, int flag) {}
PRE_SYSCALL(compat_14_msgctl)(int msqid, int cmd, 			    struct msqid_ds14 *buf) {}
POST_SYSCALL(compat_14_msgctl)(register_t res, int msqid, int cmd, 			    struct msqid_ds14 *buf) {}
PRE_SYSCALL(msgget)(key_t key, int msgflg) {}
POST_SYSCALL(msgget)(register_t res, key_t key, int msgflg) {}
PRE_SYSCALL(msgsnd)(int msqid, const void *msgp, 			    size_t msgsz, int msgflg) {}
POST_SYSCALL(msgsnd)(register_t res, int msqid, const void *msgp, 			    size_t msgsz, int msgflg) {}
PRE_SYSCALL(msgrcv)(int msqid, void *msgp, 			    size_t msgsz, long msgtyp, int msgflg) {}
POST_SYSCALL(msgrcv)(register_t res, int msqid, void *msgp, 			    size_t msgsz, long msgtyp, int msgflg) {}
PRE_SYSCALL(shmat)(int shmid,				    const void *shmaddr, int shmflg) {}
POST_SYSCALL(shmat)(register_t res, int shmid,				    const void *shmaddr, int shmflg) {}
PRE_SYSCALL(compat_14_shmctl)(int shmid, int cmd, 			    struct shmid_ds14 *buf) {}
POST_SYSCALL(compat_14_shmctl)(register_t res, int shmid, int cmd, 			    struct shmid_ds14 *buf) {}
PRE_SYSCALL(shmdt)(const void *shmaddr) {}
POST_SYSCALL(shmdt)(register_t res, const void *shmaddr) {}
PRE_SYSCALL(shmget)(key_t key, size_t size,				    int shmflg) {}
POST_SYSCALL(shmget)(register_t res, key_t key, size_t size,				    int shmflg) {}
PRE_SYSCALL(compat_50_clock_gettime)(clockid_t clock_id, 			    struct timespec50 *tp) {}
POST_SYSCALL(compat_50_clock_gettime)(register_t res, clockid_t clock_id, 			    struct timespec50 *tp) {}
PRE_SYSCALL(compat_50_clock_settime)(clockid_t clock_id, 			    const struct timespec50 *tp) {}
POST_SYSCALL(compat_50_clock_settime)(register_t res, clockid_t clock_id, 			    const struct timespec50 *tp) {}
PRE_SYSCALL(compat_50_clock_getres)(clockid_t clock_id, 			    struct timespec50 *tp) {}
POST_SYSCALL(compat_50_clock_getres)(register_t res, clockid_t clock_id, 			    struct timespec50 *tp) {}
PRE_SYSCALL(timer_create)(clockid_t clock_id, 			    struct sigevent *evp, timer_t *timerid) {}
POST_SYSCALL(timer_create)(register_t res, clockid_t clock_id, 			    struct sigevent *evp, timer_t *timerid) {}
PRE_SYSCALL(timer_delete)(timer_t timerid) {}
POST_SYSCALL(timer_delete)(register_t res, timer_t timerid) {}
PRE_SYSCALL(compat_50_timer_settime)(timer_t timerid, 			    int flags, const struct itimerspec50 *value, 			    struct itimerspec50 *ovalue) {}
POST_SYSCALL(compat_50_timer_settime)(register_t res, timer_t timerid, 			    int flags, const struct itimerspec50 *value, 			    struct itimerspec50 *ovalue) {}
PRE_SYSCALL(compat_50_timer_gettime)(timer_t timerid, 			    struct itimerspec50 *value) {}
POST_SYSCALL(compat_50_timer_gettime)(register_t res, timer_t timerid, 			    struct itimerspec50 *value) {}
PRE_SYSCALL(timer_getoverrun)(timer_t timerid) {}
POST_SYSCALL(timer_getoverrun)(register_t res, timer_t timerid) {}
PRE_SYSCALL(compat_50_nanosleep)(const struct timespec50 *rqtp, 			    struct timespec50 *rmtp) {}
POST_SYSCALL(compat_50_nanosleep)(register_t res, const struct timespec50 *rqtp, 			    struct timespec50 *rmtp) {}
PRE_SYSCALL(fdatasync)(int fd) {}
POST_SYSCALL(fdatasync)(register_t res, int fd) {}
PRE_SYSCALL(mlockall)(int flags) {}
POST_SYSCALL(mlockall)(register_t res, int flags) {}
PRE_SYSCALL(munlockall)(void) {}
POST_SYSCALL(munlockall)(register_t res) {}
PRE_SYSCALL(compat_50___sigtimedwait)(const sigset_t *set, 			    siginfo_t *info, struct timespec50 *timeout) {}
POST_SYSCALL(compat_50___sigtimedwait)(register_t res, const sigset_t *set, 			    siginfo_t *info, struct timespec50 *timeout) {}
PRE_SYSCALL(sigqueueinfo)(pid_t pid, 			    const siginfo_t *info) {}
POST_SYSCALL(sigqueueinfo)(register_t res, pid_t pid, 			    const siginfo_t *info) {}
PRE_SYSCALL(modctl)(int cmd, void *arg) {}
POST_SYSCALL(modctl)(register_t res, int cmd, void *arg) {}
PRE_SYSCALL(_ksem_init)(unsigned int value, intptr_t *idp) {}
POST_SYSCALL(_ksem_init)(register_t res, unsigned int value, intptr_t *idp) {}
PRE_SYSCALL(_ksem_open)(const char *name, int oflag, 			    mode_t mode, unsigned int value, intptr_t *idp) {}
POST_SYSCALL(_ksem_open)(register_t res, const char *name, int oflag, 			    mode_t mode, unsigned int value, intptr_t *idp) {}
PRE_SYSCALL(_ksem_unlink)(const char *name) {}
POST_SYSCALL(_ksem_unlink)(register_t res, const char *name) {}
PRE_SYSCALL(_ksem_close)(intptr_t id) {}
POST_SYSCALL(_ksem_close)(register_t res, intptr_t id) {}
PRE_SYSCALL(_ksem_post)(intptr_t id) {}
POST_SYSCALL(_ksem_post)(register_t res, intptr_t id) {}
PRE_SYSCALL(_ksem_wait)(intptr_t id) {}
POST_SYSCALL(_ksem_wait)(register_t res, intptr_t id) {}
PRE_SYSCALL(_ksem_trywait)(intptr_t id) {}
POST_SYSCALL(_ksem_trywait)(register_t res, intptr_t id) {}
PRE_SYSCALL(_ksem_getvalue)(intptr_t id, 			    unsigned int *value) {}
POST_SYSCALL(_ksem_getvalue)(register_t res, intptr_t id, 			    unsigned int *value) {}
PRE_SYSCALL(_ksem_destroy)(intptr_t id) {}
POST_SYSCALL(_ksem_destroy)(register_t res, intptr_t id) {}
PRE_SYSCALL(_ksem_timedwait)(intptr_t id, 				const struct timespec *abstime) {}
POST_SYSCALL(_ksem_timedwait)(register_t res, intptr_t id, 				const struct timespec *abstime) {}
PRE_SYSCALL(mq_open)(const char * name, int oflag, 			    mode_t mode, struct mq_attr *attr) {}
POST_SYSCALL(mq_open)(register_t res, const char * name, int oflag, 			    mode_t mode, struct mq_attr *attr) {}
PRE_SYSCALL(mq_close)(mqd_t mqdes) {}
POST_SYSCALL(mq_close)(register_t res, mqd_t mqdes) {}
PRE_SYSCALL(mq_unlink)(const char *name) {}
POST_SYSCALL(mq_unlink)(register_t res, const char *name) {}
PRE_SYSCALL(mq_getattr)(mqd_t mqdes, 			    struct mq_attr *mqstat) {}
POST_SYSCALL(mq_getattr)(register_t res, mqd_t mqdes, 			    struct mq_attr *mqstat) {}
PRE_SYSCALL(mq_setattr)(mqd_t mqdes, 			    const struct mq_attr *mqstat, 			    struct mq_attr *omqstat) {}
POST_SYSCALL(mq_setattr)(register_t res, mqd_t mqdes, 			    const struct mq_attr *mqstat, 			    struct mq_attr *omqstat) {}
PRE_SYSCALL(mq_notify)(mqd_t mqdes, 			    const struct sigevent *notification) {}
POST_SYSCALL(mq_notify)(register_t res, mqd_t mqdes, 			    const struct sigevent *notification) {}
PRE_SYSCALL(mq_send)(mqd_t mqdes, const char *msg_ptr, 			    size_t msg_len, unsigned msg_prio) {}
POST_SYSCALL(mq_send)(register_t res, mqd_t mqdes, const char *msg_ptr, 			    size_t msg_len, unsigned msg_prio) {}
PRE_SYSCALL(mq_receive)(mqd_t mqdes, char *msg_ptr, 			    size_t msg_len, unsigned *msg_prio) {}
POST_SYSCALL(mq_receive)(register_t res, mqd_t mqdes, char *msg_ptr, 			    size_t msg_len, unsigned *msg_prio) {}
PRE_SYSCALL(compat_50_mq_timedsend)(mqd_t mqdes, 			    const char *msg_ptr, size_t msg_len, 			    unsigned msg_prio, 			    const struct timespec50 *abs_timeout) {}
POST_SYSCALL(compat_50_mq_timedsend)(register_t res, mqd_t mqdes, 			    const char *msg_ptr, size_t msg_len, 			    unsigned msg_prio, 			    const struct timespec50 *abs_timeout) {}
PRE_SYSCALL(compat_50_mq_timedreceive)(mqd_t mqdes, 			    char *msg_ptr, size_t msg_len, unsigned *msg_prio, 			    const struct timespec50 *abs_timeout) {}
POST_SYSCALL(compat_50_mq_timedreceive)(register_t res, mqd_t mqdes, 			    char *msg_ptr, size_t msg_len, unsigned *msg_prio, 			    const struct timespec50 *abs_timeout) {}
/* syscall 267 has been skipped */
/* syscall 268 has been skipped */
/* syscall 269 has been skipped */
PRE_SYSCALL(__posix_rename)(const char *from, 			    const char *to) {}
POST_SYSCALL(__posix_rename)(register_t res, const char *from, 			    const char *to) {}
PRE_SYSCALL(swapctl)(int cmd, void *arg, int misc) {}
POST_SYSCALL(swapctl)(register_t res, int cmd, void *arg, int misc) {}
PRE_SYSCALL(compat_30_getdents)(int fd, char *buf, size_t count) {}
POST_SYSCALL(compat_30_getdents)(register_t res, int fd, char *buf, size_t count) {}
PRE_SYSCALL(minherit)(void *addr, size_t len, 			    int inherit) {}
POST_SYSCALL(minherit)(register_t res, void *addr, size_t len, 			    int inherit) {}
PRE_SYSCALL(lchmod)(const char *path, mode_t mode) {}
POST_SYSCALL(lchmod)(register_t res, const char *path, mode_t mode) {}
PRE_SYSCALL(lchown)(const char *path, uid_t uid, 			    gid_t gid) {}
POST_SYSCALL(lchown)(register_t res, const char *path, uid_t uid, 			    gid_t gid) {}
PRE_SYSCALL(compat_50_lutimes)(const char *path, 			    const struct timeval50 *tptr) {}
POST_SYSCALL(compat_50_lutimes)(register_t res, const char *path, 			    const struct timeval50 *tptr) {}
PRE_SYSCALL(__msync13)(void *addr, size_t len, int flags) {}
POST_SYSCALL(__msync13)(register_t res, void *addr, size_t len, int flags) {}
PRE_SYSCALL(compat_30___stat13)(const char *path, struct stat13 *ub) {}
POST_SYSCALL(compat_30___stat13)(register_t res, const char *path, struct stat13 *ub) {}
PRE_SYSCALL(compat_30___fstat13)(int fd, struct stat13 *sb) {}
POST_SYSCALL(compat_30___fstat13)(register_t res, int fd, struct stat13 *sb) {}
PRE_SYSCALL(compat_30___lstat13)(const char *path, struct stat13 *ub) {}
POST_SYSCALL(compat_30___lstat13)(register_t res, const char *path, struct stat13 *ub) {}
PRE_SYSCALL(__sigaltstack14)( 			    const struct sigaltstack *nss, 			    struct sigaltstack *oss) {}
POST_SYSCALL(__sigaltstack14)(register_t res,  			    const struct sigaltstack *nss, 			    struct sigaltstack *oss) {}
PRE_SYSCALL(__vfork14)(void) {}
POST_SYSCALL(__vfork14)(register_t res) {}
PRE_SYSCALL(__posix_chown)(const char *path, uid_t uid, 			    gid_t gid) {}
POST_SYSCALL(__posix_chown)(register_t res, const char *path, uid_t uid, 			    gid_t gid) {}
PRE_SYSCALL(__posix_fchown)(int fd, uid_t uid, 			    gid_t gid) {}
POST_SYSCALL(__posix_fchown)(register_t res, int fd, uid_t uid, 			    gid_t gid) {}
PRE_SYSCALL(__posix_lchown)(const char *path, uid_t uid, 			    gid_t gid) {}
POST_SYSCALL(__posix_lchown)(register_t res, const char *path, uid_t uid, 			    gid_t gid) {}
PRE_SYSCALL(getsid)(pid_t pid) {}
POST_SYSCALL(getsid)(register_t res, pid_t pid) {}
PRE_SYSCALL(__clone)(int flags, void *stack) {}
POST_SYSCALL(__clone)(register_t res, int flags, void *stack) {}
PRE_SYSCALL(fktrace)(int fd, int ops, 			    int facs, pid_t pid) {}
POST_SYSCALL(fktrace)(register_t res, int fd, int ops, 			    int facs, pid_t pid) {}
PRE_SYSCALL(preadv)(int fd, 			    const struct iovec *iovp, int iovcnt, 			    int PAD, off_t offset) {}
POST_SYSCALL(preadv)(register_t res, int fd, 			    const struct iovec *iovp, int iovcnt, 			    int PAD, off_t offset) {}
PRE_SYSCALL(pwritev)(int fd, 			    const struct iovec *iovp, int iovcnt, 			    int PAD, off_t offset) {}
POST_SYSCALL(pwritev)(register_t res, int fd, 			    const struct iovec *iovp, int iovcnt, 			    int PAD, off_t offset) {}
PRE_SYSCALL(compat_16___sigaction14)(int signum, 			    const struct sigaction *nsa, 			    struct sigaction *osa) {}
POST_SYSCALL(compat_16___sigaction14)(register_t res, int signum, 			    const struct sigaction *nsa, 			    struct sigaction *osa) {}
PRE_SYSCALL(__sigpending14)(sigset_t *set) {}
POST_SYSCALL(__sigpending14)(register_t res, sigset_t *set) {}
PRE_SYSCALL(__sigprocmask14)(int how, 			    const sigset_t *set, 			    sigset_t *oset) {}
POST_SYSCALL(__sigprocmask14)(register_t res, int how, 			    const sigset_t *set, 			    sigset_t *oset) {}
PRE_SYSCALL(__sigsuspend14)(const sigset_t *set) {}
POST_SYSCALL(__sigsuspend14)(register_t res, const sigset_t *set) {}
PRE_SYSCALL(compat_16___sigreturn14)(struct sigcontext *sigcntxp) {}
POST_SYSCALL(compat_16___sigreturn14)(register_t res, struct sigcontext *sigcntxp) {}
PRE_SYSCALL(__getcwd)(char *bufp, size_t length) {}
POST_SYSCALL(__getcwd)(register_t res, char *bufp, size_t length) {}
PRE_SYSCALL(fchroot)(int fd) {}
POST_SYSCALL(fchroot)(register_t res, int fd) {}
PRE_SYSCALL(compat_30_fhopen)(const struct compat_30_fhandle *fhp, int flags) {}
POST_SYSCALL(compat_30_fhopen)(register_t res, const struct compat_30_fhandle *fhp, int flags) {}
PRE_SYSCALL(compat_30_fhstat)(const struct compat_30_fhandle *fhp, 			    struct stat13 *sb) {}
POST_SYSCALL(compat_30_fhstat)(register_t res, const struct compat_30_fhandle *fhp, 			    struct stat13 *sb) {}
PRE_SYSCALL(compat_20_fhstatfs)(const struct compat_30_fhandle *fhp, 			    struct statfs12 *buf) {}
POST_SYSCALL(compat_20_fhstatfs)(register_t res, const struct compat_30_fhandle *fhp, 			    struct statfs12 *buf) {}
PRE_SYSCALL(compat_50_____semctl13)(int semid, int semnum, int cmd, 			     union __semun *arg) {}
POST_SYSCALL(compat_50_____semctl13)(register_t res, int semid, int semnum, int cmd, 			     union __semun *arg) {}
PRE_SYSCALL(compat_50___msgctl13)(int msqid, int cmd, 			    struct msqid_ds *buf) {}
POST_SYSCALL(compat_50___msgctl13)(register_t res, int msqid, int cmd, 			    struct msqid_ds *buf) {}
PRE_SYSCALL(compat_50___shmctl13)(int shmid, int cmd, 			    struct shmid_ds13 *buf) {}
POST_SYSCALL(compat_50___shmctl13)(register_t res, int shmid, int cmd, 			    struct shmid_ds13 *buf) {}
PRE_SYSCALL(lchflags)(const char *path, u_long flags) {}
POST_SYSCALL(lchflags)(register_t res, const char *path, u_long flags) {}
PRE_SYSCALL(issetugid)(void) {}
POST_SYSCALL(issetugid)(register_t res) {}
PRE_SYSCALL(utrace)(const char *label, void *addr, 				size_t len) {}
POST_SYSCALL(utrace)(register_t res, const char *label, void *addr, 				size_t len) {}
PRE_SYSCALL(getcontext)(struct __ucontext *ucp) {}
POST_SYSCALL(getcontext)(register_t res, struct __ucontext *ucp) {}
PRE_SYSCALL(setcontext)(const struct __ucontext *ucp) {}
POST_SYSCALL(setcontext)(register_t res, const struct __ucontext *ucp) {}
PRE_SYSCALL(_lwp_create)(const struct __ucontext *ucp, 				u_long flags, lwpid_t *new_lwp) {}
POST_SYSCALL(_lwp_create)(register_t res, const struct __ucontext *ucp, 				u_long flags, lwpid_t *new_lwp) {}
PRE_SYSCALL(_lwp_exit)(void) {}
POST_SYSCALL(_lwp_exit)(register_t res) {}
PRE_SYSCALL(_lwp_self)(void) {}
POST_SYSCALL(_lwp_self)(register_t res) {}
PRE_SYSCALL(_lwp_wait)(lwpid_t wait_for, 				lwpid_t *departed) {}
POST_SYSCALL(_lwp_wait)(register_t res, lwpid_t wait_for, 				lwpid_t *departed) {}
PRE_SYSCALL(_lwp_suspend)(lwpid_t target) {}
POST_SYSCALL(_lwp_suspend)(register_t res, lwpid_t target) {}
PRE_SYSCALL(_lwp_continue)(lwpid_t target) {}
POST_SYSCALL(_lwp_continue)(register_t res, lwpid_t target) {}
PRE_SYSCALL(_lwp_wakeup)(lwpid_t target) {}
POST_SYSCALL(_lwp_wakeup)(register_t res, lwpid_t target) {}
PRE_SYSCALL(_lwp_getprivate)(void) {}
POST_SYSCALL(_lwp_getprivate)(register_t res) {}
PRE_SYSCALL(_lwp_setprivate)(void *ptr) {}
POST_SYSCALL(_lwp_setprivate)(register_t res, void *ptr) {}
PRE_SYSCALL(_lwp_kill)(lwpid_t target, int signo) {}
POST_SYSCALL(_lwp_kill)(register_t res, lwpid_t target, int signo) {}
PRE_SYSCALL(_lwp_detach)(lwpid_t target) {}
POST_SYSCALL(_lwp_detach)(register_t res, lwpid_t target) {}
PRE_SYSCALL(compat_50__lwp_park)(const struct timespec50 *ts, 				lwpid_t unpark, const void *hint, 				const void *unparkhint) {}
POST_SYSCALL(compat_50__lwp_park)(register_t res, const struct timespec50 *ts, 				lwpid_t unpark, const void *hint, 				const void *unparkhint) {}
PRE_SYSCALL(_lwp_unpark)(lwpid_t target, const void *hint) {}
POST_SYSCALL(_lwp_unpark)(register_t res, lwpid_t target, const void *hint) {}
PRE_SYSCALL(_lwp_unpark_all)(const lwpid_t *targets, 				size_t ntargets, const void *hint) {}
POST_SYSCALL(_lwp_unpark_all)(register_t res, const lwpid_t *targets, 				size_t ntargets, const void *hint) {}
PRE_SYSCALL(_lwp_setname)(lwpid_t target, 				const char *name) {}
POST_SYSCALL(_lwp_setname)(register_t res, lwpid_t target, 				const char *name) {}
PRE_SYSCALL(_lwp_getname)(lwpid_t target, 				char *name, size_t len) {}
POST_SYSCALL(_lwp_getname)(register_t res, lwpid_t target, 				char *name, size_t len) {}
PRE_SYSCALL(_lwp_ctl)(int features, 				struct lwpctl **address) {}
POST_SYSCALL(_lwp_ctl)(register_t res, int features, 				struct lwpctl **address) {}
/* syscall 326 has been skipped */
/* syscall 327 has been skipped */
/* syscall 328 has been skipped */
/* syscall 329 has been skipped */
PRE_SYSCALL(compat_60_sa_register)(void *newv, void **oldv, 				int flags, ssize_t stackinfo_offset) {}
POST_SYSCALL(compat_60_sa_register)(register_t res, void *newv, void **oldv, 				int flags, ssize_t stackinfo_offset) {}
PRE_SYSCALL(compat_60_sa_stacks)(int num, stack_t *stacks) {}
POST_SYSCALL(compat_60_sa_stacks)(register_t res, int num, stack_t *stacks) {}
PRE_SYSCALL(compat_60_sa_enable)(void) {}
POST_SYSCALL(compat_60_sa_enable)(register_t res) {}
PRE_SYSCALL(compat_60_sa_setconcurrency)(int concurrency) {}
POST_SYSCALL(compat_60_sa_setconcurrency)(register_t res, int concurrency) {}
PRE_SYSCALL(compat_60_sa_yield)(void) {}
POST_SYSCALL(compat_60_sa_yield)(register_t res) {}
PRE_SYSCALL(compat_60_sa_preempt)(int sa_id) {}
POST_SYSCALL(compat_60_sa_preempt)(register_t res, int sa_id) {}
/* syscall 336 has been skipped */
/* syscall 337 has been skipped */
/* syscall 338 has been skipped */
/* syscall 339 has been skipped */
PRE_SYSCALL(__sigaction_sigtramp)(int signum, 			    const struct sigaction *nsa, 			    struct sigaction *osa, 			    const void *tramp, int vers) {}
POST_SYSCALL(__sigaction_sigtramp)(register_t res, int signum, 			    const struct sigaction *nsa, 			    struct sigaction *osa, 			    const void *tramp, int vers) {}
PRE_SYSCALL(pmc_get_info)(int ctr, int op, void *args) {}
POST_SYSCALL(pmc_get_info)(register_t res, int ctr, int op, void *args) {}
PRE_SYSCALL(pmc_control)(int ctr, int op, void *args) {}
POST_SYSCALL(pmc_control)(register_t res, int ctr, int op, void *args) {}
PRE_SYSCALL(rasctl)(void *addr, size_t len, int op) {}
POST_SYSCALL(rasctl)(register_t res, void *addr, size_t len, int op) {}
PRE_SYSCALL(kqueue)(void) {}
POST_SYSCALL(kqueue)(register_t res) {}
PRE_SYSCALL(compat_50_kevent)(int fd, 			    const struct kevent *changelist, size_t nchanges, 			    struct kevent *eventlist, size_t nevents, 			    const struct timespec50 *timeout) {}
POST_SYSCALL(compat_50_kevent)(register_t res, int fd, 			    const struct kevent *changelist, size_t nchanges, 			    struct kevent *eventlist, size_t nevents, 			    const struct timespec50 *timeout) {}
PRE_SYSCALL(_sched_setparam)(pid_t pid, lwpid_t lid, 			    int policy, const struct sched_param *params) {}
POST_SYSCALL(_sched_setparam)(register_t res, pid_t pid, lwpid_t lid, 			    int policy, const struct sched_param *params) {}
PRE_SYSCALL(_sched_getparam)(pid_t pid, lwpid_t lid, 			    int *policy, struct sched_param *params) {}
POST_SYSCALL(_sched_getparam)(register_t res, pid_t pid, lwpid_t lid, 			    int *policy, struct sched_param *params) {}
PRE_SYSCALL(_sched_setaffinity)(pid_t pid, lwpid_t lid, 			    size_t size, const cpuset_t *cpuset) {}
POST_SYSCALL(_sched_setaffinity)(register_t res, pid_t pid, lwpid_t lid, 			    size_t size, const cpuset_t *cpuset) {}
PRE_SYSCALL(_sched_getaffinity)(pid_t pid, lwpid_t lid, 			    size_t size, cpuset_t *cpuset) {}
POST_SYSCALL(_sched_getaffinity)(register_t res, pid_t pid, lwpid_t lid, 			    size_t size, cpuset_t *cpuset) {}
PRE_SYSCALL(sched_yield)(void) {}
POST_SYSCALL(sched_yield)(register_t res) {}
PRE_SYSCALL(_sched_protect)(int priority) {}
POST_SYSCALL(_sched_protect)(register_t res, int priority) {}
/* syscall 352 has been skipped */
/* syscall 353 has been skipped */
PRE_SYSCALL(fsync_range)(int fd, int flags, off_t start, 			    off_t length) {}
POST_SYSCALL(fsync_range)(register_t res, int fd, int flags, off_t start, 			    off_t length) {}
PRE_SYSCALL(uuidgen)(struct uuid *store, int count) {}
POST_SYSCALL(uuidgen)(register_t res, struct uuid *store, int count) {}
PRE_SYSCALL(getvfsstat)(struct statvfs *buf, 			    size_t bufsize, int flags) {}
POST_SYSCALL(getvfsstat)(register_t res, struct statvfs *buf, 			    size_t bufsize, int flags) {}
PRE_SYSCALL(statvfs1)(const char *path, 			    struct statvfs *buf, int flags) {}
POST_SYSCALL(statvfs1)(register_t res, const char *path, 			    struct statvfs *buf, int flags) {}
PRE_SYSCALL(fstatvfs1)(int fd, struct statvfs *buf, 			    int flags) {}
POST_SYSCALL(fstatvfs1)(register_t res, int fd, struct statvfs *buf, 			    int flags) {}
PRE_SYSCALL(compat_30_fhstatvfs1)(const struct compat_30_fhandle *fhp, 			    struct statvfs *buf, int flags) {}
POST_SYSCALL(compat_30_fhstatvfs1)(register_t res, const struct compat_30_fhandle *fhp, 			    struct statvfs *buf, int flags) {}
PRE_SYSCALL(extattrctl)(const char *path, int cmd, 			    const char *filename, int attrnamespace, 			    const char *attrname) {}
POST_SYSCALL(extattrctl)(register_t res, const char *path, int cmd, 			    const char *filename, int attrnamespace, 			    const char *attrname) {}
PRE_SYSCALL(extattr_set_file)(const char *path, 			    int attrnamespace, const char *attrname, 			    const void *data, size_t nbytes) {}
POST_SYSCALL(extattr_set_file)(register_t res, const char *path, 			    int attrnamespace, const char *attrname, 			    const void *data, size_t nbytes) {}
PRE_SYSCALL(extattr_get_file)(const char *path, 			    int attrnamespace, const char *attrname, 			    void *data, size_t nbytes) {}
POST_SYSCALL(extattr_get_file)(register_t res, const char *path, 			    int attrnamespace, const char *attrname, 			    void *data, size_t nbytes) {}
PRE_SYSCALL(extattr_delete_file)(const char *path, 			    int attrnamespace, const char *attrname) {}
POST_SYSCALL(extattr_delete_file)(register_t res, const char *path, 			    int attrnamespace, const char *attrname) {}
PRE_SYSCALL(extattr_set_fd)(int fd, 			    int attrnamespace, const char *attrname, 			    const void *data, size_t nbytes) {}
POST_SYSCALL(extattr_set_fd)(register_t res, int fd, 			    int attrnamespace, const char *attrname, 			    const void *data, size_t nbytes) {}
PRE_SYSCALL(extattr_get_fd)(int fd, 			    int attrnamespace, const char *attrname, 			    void *data, size_t nbytes) {}
POST_SYSCALL(extattr_get_fd)(register_t res, int fd, 			    int attrnamespace, const char *attrname, 			    void *data, size_t nbytes) {}
PRE_SYSCALL(extattr_delete_fd)(int fd, 			    int attrnamespace, const char *attrname) {}
POST_SYSCALL(extattr_delete_fd)(register_t res, int fd, 			    int attrnamespace, const char *attrname) {}
PRE_SYSCALL(extattr_set_link)(const char *path, 			    int attrnamespace, const char *attrname, 			    const void *data, size_t nbytes) {}
POST_SYSCALL(extattr_set_link)(register_t res, const char *path, 			    int attrnamespace, const char *attrname, 			    const void *data, size_t nbytes) {}
PRE_SYSCALL(extattr_get_link)(const char *path, 			    int attrnamespace, const char *attrname, 			    void *data, size_t nbytes) {}
POST_SYSCALL(extattr_get_link)(register_t res, const char *path, 			    int attrnamespace, const char *attrname, 			    void *data, size_t nbytes) {}
PRE_SYSCALL(extattr_delete_link)(const char *path, 			    int attrnamespace, const char *attrname) {}
POST_SYSCALL(extattr_delete_link)(register_t res, const char *path, 			    int attrnamespace, const char *attrname) {}
PRE_SYSCALL(extattr_list_fd)(int fd, 			    int attrnamespace, void *data, size_t nbytes) {}
POST_SYSCALL(extattr_list_fd)(register_t res, int fd, 			    int attrnamespace, void *data, size_t nbytes) {}
PRE_SYSCALL(extattr_list_file)(const char *path, 			    int attrnamespace, void *data, size_t nbytes) {}
POST_SYSCALL(extattr_list_file)(register_t res, const char *path, 			    int attrnamespace, void *data, size_t nbytes) {}
PRE_SYSCALL(extattr_list_link)(const char *path, 			    int attrnamespace, void *data, size_t nbytes) {}
POST_SYSCALL(extattr_list_link)(register_t res, const char *path, 			    int attrnamespace, void *data, size_t nbytes) {}
PRE_SYSCALL(compat_50_pselect)(int nd, fd_set *in, fd_set *ou, 			    fd_set *ex, const struct timespec50 *ts, 			    const sigset_t *mask) {}
POST_SYSCALL(compat_50_pselect)(register_t res, int nd, fd_set *in, fd_set *ou, 			    fd_set *ex, const struct timespec50 *ts, 			    const sigset_t *mask) {}
PRE_SYSCALL(compat_50_pollts)(struct pollfd *fds, u_int nfds, 			    const struct timespec50 *ts, const sigset_t *mask) {}
POST_SYSCALL(compat_50_pollts)(register_t res, struct pollfd *fds, u_int nfds, 			    const struct timespec50 *ts, const sigset_t *mask) {}
PRE_SYSCALL(setxattr)(const char *path, 			    const char *name, const void *value, size_t size, 			    int flags) {}
POST_SYSCALL(setxattr)(register_t res, const char *path, 			    const char *name, const void *value, size_t size, 			    int flags) {}
PRE_SYSCALL(lsetxattr)(const char *path, 			    const char *name, const void *value, size_t size, 			    int flags) {}
POST_SYSCALL(lsetxattr)(register_t res, const char *path, 			    const char *name, const void *value, size_t size, 			    int flags) {}
PRE_SYSCALL(fsetxattr)(int fd, 			    const char *name, const void *value, size_t size, 			    int flags) {}
POST_SYSCALL(fsetxattr)(register_t res, int fd, 			    const char *name, const void *value, size_t size, 			    int flags) {}
PRE_SYSCALL(getxattr)(const char *path, 			    const char *name, void *value, size_t size) {}
POST_SYSCALL(getxattr)(register_t res, const char *path, 			    const char *name, void *value, size_t size) {}
PRE_SYSCALL(lgetxattr)(const char *path, 			    const char *name, void *value, size_t size) {}
POST_SYSCALL(lgetxattr)(register_t res, const char *path, 			    const char *name, void *value, size_t size) {}
PRE_SYSCALL(fgetxattr)(int fd, 			    const char *name, void *value, size_t size) {}
POST_SYSCALL(fgetxattr)(register_t res, int fd, 			    const char *name, void *value, size_t size) {}
PRE_SYSCALL(listxattr)(const char *path, 			    char *list, size_t size) {}
POST_SYSCALL(listxattr)(register_t res, const char *path, 			    char *list, size_t size) {}
PRE_SYSCALL(llistxattr)(const char *path, 			    char *list, size_t size) {}
POST_SYSCALL(llistxattr)(register_t res, const char *path, 			    char *list, size_t size) {}
PRE_SYSCALL(flistxattr)(int fd, 			    char *list, size_t size) {}
POST_SYSCALL(flistxattr)(register_t res, int fd, 			    char *list, size_t size) {}
PRE_SYSCALL(removexattr)(const char *path, 			    const char *name) {}
POST_SYSCALL(removexattr)(register_t res, const char *path, 			    const char *name) {}
PRE_SYSCALL(lremovexattr)(const char *path, 			    const char *name) {}
POST_SYSCALL(lremovexattr)(register_t res, const char *path, 			    const char *name) {}
PRE_SYSCALL(fremovexattr)(int fd, 			    const char *name) {}
POST_SYSCALL(fremovexattr)(register_t res, int fd, 			    const char *name) {}
PRE_SYSCALL(compat_50___stat30)(const char *path, struct stat30 *ub) {}
POST_SYSCALL(compat_50___stat30)(register_t res, const char *path, struct stat30 *ub) {}
PRE_SYSCALL(compat_50___fstat30)(int fd, struct stat30 *sb) {}
POST_SYSCALL(compat_50___fstat30)(register_t res, int fd, struct stat30 *sb) {}
PRE_SYSCALL(compat_50___lstat30)(const char *path, struct stat30 *ub) {}
POST_SYSCALL(compat_50___lstat30)(register_t res, const char *path, struct stat30 *ub) {}
PRE_SYSCALL(__getdents30)(int fd, char *buf, size_t count) {}
POST_SYSCALL(__getdents30)(register_t res, int fd, char *buf, size_t count) {}
PRE_SYSCALL(posix_fadvise)() {}
POST_SYSCALL(posix_fadvise)(register_t res, ) {}
PRE_SYSCALL(compat_30___fhstat30)(const struct compat_30_fhandle 			    *fhp, struct stat30 *sb) {}
POST_SYSCALL(compat_30___fhstat30)(register_t res, const struct compat_30_fhandle 			    *fhp, struct stat30 *sb) {}
PRE_SYSCALL(compat_50___ntp_gettime30)(struct ntptimeval50 *ntvp) {}
POST_SYSCALL(compat_50___ntp_gettime30)(register_t res, struct ntptimeval50 *ntvp) {}
PRE_SYSCALL(__socket30)(int domain, int type, int protocol) {}
POST_SYSCALL(__socket30)(register_t res, int domain, int type, int protocol) {}
PRE_SYSCALL(__getfh30)(const char *fname, void *fhp, 			    size_t *fh_size) {}
POST_SYSCALL(__getfh30)(register_t res, const char *fname, void *fhp, 			    size_t *fh_size) {}
PRE_SYSCALL(__fhopen40)(const void *fhp, size_t fh_size,			    int flags) {}
POST_SYSCALL(__fhopen40)(register_t res, const void *fhp, size_t fh_size,			    int flags) {}
PRE_SYSCALL(__fhstatvfs140)(const void *fhp, 			    size_t fh_size, struct statvfs *buf, int flags) {}
POST_SYSCALL(__fhstatvfs140)(register_t res, const void *fhp, 			    size_t fh_size, struct statvfs *buf, int flags) {}
PRE_SYSCALL(compat_50___fhstat40)(const void *fhp, 			    size_t fh_size, struct stat30 *sb) {}
POST_SYSCALL(compat_50___fhstat40)(register_t res, const void *fhp, 			    size_t fh_size, struct stat30 *sb) {}
PRE_SYSCALL(aio_cancel)(int fildes, struct aiocb *aiocbp) {}
POST_SYSCALL(aio_cancel)(register_t res, int fildes, struct aiocb *aiocbp) {}
PRE_SYSCALL(aio_error)(const struct aiocb *aiocbp) {}
POST_SYSCALL(aio_error)(register_t res, const struct aiocb *aiocbp) {}
PRE_SYSCALL(aio_fsync)(int op, struct aiocb *aiocbp) {}
POST_SYSCALL(aio_fsync)(register_t res, int op, struct aiocb *aiocbp) {}
PRE_SYSCALL(aio_read)(struct aiocb *aiocbp) {}
POST_SYSCALL(aio_read)(register_t res, struct aiocb *aiocbp) {}
PRE_SYSCALL(aio_return)(struct aiocb *aiocbp) {}
POST_SYSCALL(aio_return)(register_t res, struct aiocb *aiocbp) {}
PRE_SYSCALL(compat_50_aio_suspend)(const struct aiocb *const *list, 		    int nent, const struct timespec50 *timeout) {}
POST_SYSCALL(compat_50_aio_suspend)(register_t res, const struct aiocb *const *list, 		    int nent, const struct timespec50 *timeout) {}
PRE_SYSCALL(aio_write)(struct aiocb *aiocbp) {}
POST_SYSCALL(aio_write)(register_t res, struct aiocb *aiocbp) {}
PRE_SYSCALL(lio_listio)(int mode, struct aiocb *const *list, 		    int nent, struct sigevent *sig) {}
POST_SYSCALL(lio_listio)(register_t res, int mode, struct aiocb *const *list, 		    int nent, struct sigevent *sig) {}
/* syscall 407 has been skipped */
/* syscall 408 has been skipped */
/* syscall 409 has been skipped */
PRE_SYSCALL(__mount50)(const char *type, 			    const char *path, int flags, void *data, 			    size_t data_len) {}
POST_SYSCALL(__mount50)(register_t res, const char *type, 			    const char *path, int flags, void *data, 			    size_t data_len) {}
PRE_SYSCALL(mremap)(void *old_address, size_t old_size, 			    void *new_address, size_t new_size, int flags) {}
POST_SYSCALL(mremap)(register_t res, void *old_address, size_t old_size, 			    void *new_address, size_t new_size, int flags) {}
PRE_SYSCALL(pset_create)(psetid_t *psid) {}
POST_SYSCALL(pset_create)(register_t res, psetid_t *psid) {}
PRE_SYSCALL(pset_destroy)(psetid_t psid) {}
POST_SYSCALL(pset_destroy)(register_t res, psetid_t psid) {}
PRE_SYSCALL(pset_assign)(psetid_t psid, cpuid_t cpuid, 			    psetid_t *opsid) {}
POST_SYSCALL(pset_assign)(register_t res, psetid_t psid, cpuid_t cpuid, 			    psetid_t *opsid) {}
PRE_SYSCALL(_pset_bind)(idtype_t idtype, id_t first_id, 			    id_t second_id, psetid_t psid, psetid_t *opsid) {}
POST_SYSCALL(_pset_bind)(register_t res, idtype_t idtype, id_t first_id, 			    id_t second_id, psetid_t psid, psetid_t *opsid) {}
PRE_SYSCALL(__posix_fadvise50)(int fd, int PAD, 			    off_t offset, off_t len, int advice) {}
POST_SYSCALL(__posix_fadvise50)(register_t res, int fd, int PAD, 			    off_t offset, off_t len, int advice) {}
PRE_SYSCALL(__select50)(int nd, fd_set *in, fd_set *ou, 			    fd_set *ex, struct timeval *tv) {}
POST_SYSCALL(__select50)(register_t res, int nd, fd_set *in, fd_set *ou, 			    fd_set *ex, struct timeval *tv) {}
PRE_SYSCALL(__gettimeofday50)(struct timeval *tp, 			    void *tzp) {}
POST_SYSCALL(__gettimeofday50)(register_t res, struct timeval *tp, 			    void *tzp) {}
PRE_SYSCALL(__settimeofday50)(const struct timeval *tv, 			    const void *tzp) {}
POST_SYSCALL(__settimeofday50)(register_t res, const struct timeval *tv, 			    const void *tzp) {}
PRE_SYSCALL(__utimes50)(const char *path, 			    const struct timeval *tptr) {}
POST_SYSCALL(__utimes50)(register_t res, const char *path, 			    const struct timeval *tptr) {}
PRE_SYSCALL(__adjtime50)(const struct timeval *delta, 			    struct timeval *olddelta) {}
POST_SYSCALL(__adjtime50)(register_t res, const struct timeval *delta, 			    struct timeval *olddelta) {}
PRE_SYSCALL(__lfs_segwait50)(fsid_t *fsidp, 			    struct timeval *tv) {}
POST_SYSCALL(__lfs_segwait50)(register_t res, fsid_t *fsidp, 			    struct timeval *tv) {}
PRE_SYSCALL(__futimes50)(int fd, 			    const struct timeval *tptr) {}
POST_SYSCALL(__futimes50)(register_t res, int fd, 			    const struct timeval *tptr) {}
PRE_SYSCALL(__lutimes50)(const char *path, 			    const struct timeval *tptr) {}
POST_SYSCALL(__lutimes50)(register_t res, const char *path, 			    const struct timeval *tptr) {}
PRE_SYSCALL(__setitimer50)(int which, 			    const struct itimerval *itv, 			    struct itimerval *oitv) {}
POST_SYSCALL(__setitimer50)(register_t res, int which, 			    const struct itimerval *itv, 			    struct itimerval *oitv) {}
PRE_SYSCALL(__getitimer50)(int which, 			    struct itimerval *itv) {}
POST_SYSCALL(__getitimer50)(register_t res, int which, 			    struct itimerval *itv) {}
PRE_SYSCALL(__clock_gettime50)(clockid_t clock_id, 			    struct timespec *tp) {}
POST_SYSCALL(__clock_gettime50)(register_t res, clockid_t clock_id, 			    struct timespec *tp) {}
PRE_SYSCALL(__clock_settime50)(clockid_t clock_id, 			    const struct timespec *tp) {}
POST_SYSCALL(__clock_settime50)(register_t res, clockid_t clock_id, 			    const struct timespec *tp) {}
PRE_SYSCALL(__clock_getres50)(clockid_t clock_id, 			    struct timespec *tp) {}
POST_SYSCALL(__clock_getres50)(register_t res, clockid_t clock_id, 			    struct timespec *tp) {}
PRE_SYSCALL(__nanosleep50)(const struct timespec *rqtp, 			    struct timespec *rmtp) {}
POST_SYSCALL(__nanosleep50)(register_t res, const struct timespec *rqtp, 			    struct timespec *rmtp) {}
PRE_SYSCALL(____sigtimedwait50)(const sigset_t *set, 			    siginfo_t *info, 			    struct timespec *timeout) {}
POST_SYSCALL(____sigtimedwait50)(register_t res, const sigset_t *set, 			    siginfo_t *info, 			    struct timespec *timeout) {}
PRE_SYSCALL(__mq_timedsend50)(mqd_t mqdes, 			    const char *msg_ptr, size_t msg_len, 			    unsigned msg_prio, 			    const struct timespec *abs_timeout) {}
POST_SYSCALL(__mq_timedsend50)(register_t res, mqd_t mqdes, 			    const char *msg_ptr, size_t msg_len, 			    unsigned msg_prio, 			    const struct timespec *abs_timeout) {}
PRE_SYSCALL(__mq_timedreceive50)(mqd_t mqdes, 			    char *msg_ptr, size_t msg_len, unsigned *msg_prio, 			    const struct timespec *abs_timeout) {}
POST_SYSCALL(__mq_timedreceive50)(register_t res, mqd_t mqdes, 			    char *msg_ptr, size_t msg_len, unsigned *msg_prio, 			    const struct timespec *abs_timeout) {}
PRE_SYSCALL(compat_60__lwp_park)(const struct timespec *ts, 				lwpid_t unpark, const void *hint, 				const void *unparkhint) {}
POST_SYSCALL(compat_60__lwp_park)(register_t res, const struct timespec *ts, 				lwpid_t unpark, const void *hint, 				const void *unparkhint) {}
PRE_SYSCALL(__kevent50)(int fd, 			    const struct kevent *changelist, size_t nchanges, 			    struct kevent *eventlist, size_t nevents, 			    const struct timespec *timeout) {}
POST_SYSCALL(__kevent50)(register_t res, int fd, 			    const struct kevent *changelist, size_t nchanges, 			    struct kevent *eventlist, size_t nevents, 			    const struct timespec *timeout) {}
PRE_SYSCALL(__pselect50)(int nd, fd_set *in, fd_set *ou, 			    fd_set *ex, const struct timespec *ts, 			    const sigset_t *mask) {}
POST_SYSCALL(__pselect50)(register_t res, int nd, fd_set *in, fd_set *ou, 			    fd_set *ex, const struct timespec *ts, 			    const sigset_t *mask) {}
PRE_SYSCALL(__pollts50)(struct pollfd *fds, u_int nfds, 			    const struct timespec *ts, const sigset_t *mask) {}
POST_SYSCALL(__pollts50)(register_t res, struct pollfd *fds, u_int nfds, 			    const struct timespec *ts, const sigset_t *mask) {}
PRE_SYSCALL(__aio_suspend50)( 			    const struct aiocb *const *list, 			    int nent, const struct timespec *timeout) {}
POST_SYSCALL(__aio_suspend50)(register_t res,  			    const struct aiocb *const *list, 			    int nent, const struct timespec *timeout) {}
PRE_SYSCALL(__stat50)(const char *path, struct stat *ub) {}
POST_SYSCALL(__stat50)(register_t res, const char *path, struct stat *ub) {}
PRE_SYSCALL(__fstat50)(int fd, struct stat *sb) {}
POST_SYSCALL(__fstat50)(register_t res, int fd, struct stat *sb) {}
PRE_SYSCALL(__lstat50)(const char *path, struct stat *ub) {}
POST_SYSCALL(__lstat50)(register_t res, const char *path, struct stat *ub) {}
PRE_SYSCALL(____semctl50)(int semid, int semnum, 			    int cmd,  union __semun *arg) {}
POST_SYSCALL(____semctl50)(register_t res, int semid, int semnum, 			    int cmd,  union __semun *arg) {}
PRE_SYSCALL(__shmctl50)(int shmid, int cmd, 			    struct shmid_ds *buf) {}
POST_SYSCALL(__shmctl50)(register_t res, int shmid, int cmd, 			    struct shmid_ds *buf) {}
PRE_SYSCALL(__msgctl50)(int msqid, int cmd, 			    struct msqid_ds *buf) {}
POST_SYSCALL(__msgctl50)(register_t res, int msqid, int cmd, 			    struct msqid_ds *buf) {}
PRE_SYSCALL(__getrusage50)(int who, struct rusage *rusage) {}
POST_SYSCALL(__getrusage50)(register_t res, int who, struct rusage *rusage) {}
PRE_SYSCALL(__timer_settime50)(timer_t timerid, 			    int flags, const struct itimerspec *value, 			    struct itimerspec *ovalue) {}
POST_SYSCALL(__timer_settime50)(register_t res, timer_t timerid, 			    int flags, const struct itimerspec *value, 			    struct itimerspec *ovalue) {}
PRE_SYSCALL(__timer_gettime50)(timer_t timerid, struct 			    itimerspec *value) {}
POST_SYSCALL(__timer_gettime50)(register_t res, timer_t timerid, struct 			    itimerspec *value) {}
#if defined(NTP) || !defined(_KERNEL_OPT)
PRE_SYSCALL(__ntp_gettime50)(struct ntptimeval *ntvp) {}
POST_SYSCALL(__ntp_gettime50)(register_t res, struct ntptimeval *ntvp) {}
#else
/* syscall 448 has been skipped */
#endif
PRE_SYSCALL(__wait450)(pid_t pid, int *status, 				    int options, struct rusage *rusage) {}
POST_SYSCALL(__wait450)(register_t res, pid_t pid, int *status, 				    int options, struct rusage *rusage) {}
PRE_SYSCALL(__mknod50)(const char *path, mode_t mode, 			    dev_t dev) {}
POST_SYSCALL(__mknod50)(register_t res, const char *path, mode_t mode, 			    dev_t dev) {}
PRE_SYSCALL(__fhstat50)(const void *fhp, 			    size_t fh_size, struct stat *sb) {}
POST_SYSCALL(__fhstat50)(register_t res, const void *fhp, 			    size_t fh_size, struct stat *sb) {}
/* syscall 452 has been skipped */
PRE_SYSCALL(pipe2)(int *fildes, int flags) {}
POST_SYSCALL(pipe2)(register_t res, int *fildes, int flags) {}
PRE_SYSCALL(dup3)(int from, int to, int flags) {}
POST_SYSCALL(dup3)(register_t res, int from, int to, int flags) {}
PRE_SYSCALL(kqueue1)(int flags) {}
POST_SYSCALL(kqueue1)(register_t res, int flags) {}
PRE_SYSCALL(paccept)(int s, struct sockaddr *name, 			    socklen_t *anamelen, const sigset_t *mask, 			    int flags) {}
POST_SYSCALL(paccept)(register_t res, int s, struct sockaddr *name, 			    socklen_t *anamelen, const sigset_t *mask, 			    int flags) {}
PRE_SYSCALL(linkat)(int fd1, const char *name1, 			    int fd2, const char *name2, int flags) {}
POST_SYSCALL(linkat)(register_t res, int fd1, const char *name1, 			    int fd2, const char *name2, int flags) {}
PRE_SYSCALL(renameat)(int fromfd, const char *from, 			    int tofd, const char *to) {}
POST_SYSCALL(renameat)(register_t res, int fromfd, const char *from, 			    int tofd, const char *to) {}
PRE_SYSCALL(mkfifoat)(int fd, const char *path, 			    mode_t mode) {}
POST_SYSCALL(mkfifoat)(register_t res, int fd, const char *path, 			    mode_t mode) {}
PRE_SYSCALL(mknodat)(int fd, const char *path, 			    mode_t mode, int PAD, dev_t dev) {}
POST_SYSCALL(mknodat)(register_t res, int fd, const char *path, 			    mode_t mode, int PAD, dev_t dev) {}
PRE_SYSCALL(mkdirat)(int fd, const char *path, 			    mode_t mode) {}
POST_SYSCALL(mkdirat)(register_t res, int fd, const char *path, 			    mode_t mode) {}
PRE_SYSCALL(faccessat)(int fd, const char *path, 			    int amode, int flag) {}
POST_SYSCALL(faccessat)(register_t res, int fd, const char *path, 			    int amode, int flag) {}
PRE_SYSCALL(fchmodat)(int fd, const char *path, 			    mode_t mode, int flag) {}
POST_SYSCALL(fchmodat)(register_t res, int fd, const char *path, 			    mode_t mode, int flag) {}
PRE_SYSCALL(fchownat)(int fd, const char *path, 			    uid_t owner, gid_t group, int flag) {}
POST_SYSCALL(fchownat)(register_t res, int fd, const char *path, 			    uid_t owner, gid_t group, int flag) {}
PRE_SYSCALL(fexecve)(int fd, 			    char * const *argp, char * const *envp) {}
POST_SYSCALL(fexecve)(register_t res, int fd, 			    char * const *argp, char * const *envp) {}
PRE_SYSCALL(fstatat)(int fd, const char *path, 			    struct stat *buf, int flag) {}
POST_SYSCALL(fstatat)(register_t res, int fd, const char *path, 			    struct stat *buf, int flag) {}
PRE_SYSCALL(utimensat)(int fd, const char *path, 			    const struct timespec *tptr, int flag) {}
POST_SYSCALL(utimensat)(register_t res, int fd, const char *path, 			    const struct timespec *tptr, int flag) {}
PRE_SYSCALL(openat)(int fd, const char *path, 			    int oflags,  mode_t mode) {}
POST_SYSCALL(openat)(register_t res, int fd, const char *path, 			    int oflags,  mode_t mode) {}
PRE_SYSCALL(readlinkat)(int fd, const char *path, 			    char *buf, size_t bufsize) {}
POST_SYSCALL(readlinkat)(register_t res, int fd, const char *path, 			    char *buf, size_t bufsize) {}
PRE_SYSCALL(symlinkat)(const char *path1, int fd, 			    const char *path2) {}
POST_SYSCALL(symlinkat)(register_t res, const char *path1, int fd, 			    const char *path2) {}
PRE_SYSCALL(unlinkat)(int fd, const char *path, 			    int flag) {}
POST_SYSCALL(unlinkat)(register_t res, int fd, const char *path, 			    int flag) {}
PRE_SYSCALL(futimens)(int fd, 			    const struct timespec *tptr) {}
POST_SYSCALL(futimens)(register_t res, int fd, 			    const struct timespec *tptr) {}
PRE_SYSCALL(__quotactl)(const char *path, 			    struct quotactl_args *args) {}
POST_SYSCALL(__quotactl)(register_t res, const char *path, 			    struct quotactl_args *args) {}
PRE_SYSCALL(posix_spawn)(pid_t *pid, const char *path, 			    const struct posix_spawn_file_actions *file_actions, 			    const struct posix_spawnattr *attrp, 			    char *const *argv, char *const *envp) {}
POST_SYSCALL(posix_spawn)(register_t res, pid_t *pid, const char *path, 			    const struct posix_spawn_file_actions *file_actions, 			    const struct posix_spawnattr *attrp, 			    char *const *argv, char *const *envp) {}
PRE_SYSCALL(recvmmsg)(int s, struct mmsghdr *mmsg, 			    unsigned int vlen, unsigned int flags, 			    struct timespec *timeout) {}
POST_SYSCALL(recvmmsg)(register_t res, int s, struct mmsghdr *mmsg, 			    unsigned int vlen, unsigned int flags, 			    struct timespec *timeout) {}
PRE_SYSCALL(sendmmsg)(int s, struct mmsghdr *mmsg, 			    unsigned int vlen, unsigned int flags) {}
POST_SYSCALL(sendmmsg)(register_t res, int s, struct mmsghdr *mmsg, 			    unsigned int vlen, unsigned int flags) {}
PRE_SYSCALL(clock_nanosleep)(clockid_t clock_id, 			    int flags, const struct timespec *rqtp, 			    struct timespec *rmtp) {}
POST_SYSCALL(clock_nanosleep)(register_t res, clockid_t clock_id, 			    int flags, const struct timespec *rqtp, 			    struct timespec *rmtp) {}
PRE_SYSCALL(___lwp_park60)(clockid_t clock_id, int flags, 			    struct timespec *ts, lwpid_t unpark, 			    const void *hint, const void *unparkhint) {}
POST_SYSCALL(___lwp_park60)(register_t res, clockid_t clock_id, int flags, 			    struct timespec *ts, lwpid_t unpark, 			    const void *hint, const void *unparkhint) {}
PRE_SYSCALL(posix_fallocate)(int fd, int PAD, off_t pos, 			    off_t len) {}
POST_SYSCALL(posix_fallocate)(register_t res, int fd, int PAD, off_t pos, 			    off_t len) {}
PRE_SYSCALL(fdiscard)(int fd, int PAD, off_t pos, 			    off_t len) {}
POST_SYSCALL(fdiscard)(register_t res, int fd, int PAD, off_t pos, 			    off_t len) {}
PRE_SYSCALL(wait6)(idtype_t idtype, id_t id, 			    int *status, int options, struct wrusage *wru, 			    siginfo_t *info) {}
POST_SYSCALL(wait6)(register_t res, idtype_t idtype, id_t id, 			    int *status, int options, struct wrusage *wru, 			    siginfo_t *info) {}
PRE_SYSCALL(clock_getcpuclockid2)(idtype_t idtype, 			    id_t id, clockid_t *clock_id) {}
POST_SYSCALL(clock_getcpuclockid2)(register_t res, idtype_t idtype, 			    id_t id, clockid_t *clock_id) {}
}  // extern "C"

#undef PRE_SYSCALL
#undef PRE_READ
#undef PRE_WRITE
#undef POST_SYSCALL
#undef POST_READ
#undef POST_WRITE

#endif // SANITIZER_NETBSD
