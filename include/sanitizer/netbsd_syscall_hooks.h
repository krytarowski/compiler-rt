//===-- netbsd_syscall_hooks.h --------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of public sanitizer interface.
//
// System call handlers.
//
// Interface methods declared in this header implement pre- and post- syscall
// actions for the active sanitizer.
// Usage:
//   __sanitizer_syscall_pre_getfoo(...args...);
//   long res = syscall(SYS_getfoo, ...args...);
//   __sanitizer_syscall_post_getfoo(res, ...args...);
//
// DO NOT EDIT! THIS FILE HAS BEEN AUTOMATICALLY GENERATED
//
//===----------------------------------------------------------------------===//
#ifndef SANITIZER_NETBSD_SYSCALL_HOOKS_H
#define SANITIZER_NETBSD_SYSCALL_HOOKS_H

#define __sanitizer_syscall_pre_syscall() \
  __sanitizer_syscall_pre_impl_syscall()
#define __sanitizer_syscall_post_syscall() \
  __sanitizer_syscall_post_impl_syscall()
#define __sanitizer_syscall_pre_exit() \
  __sanitizer_syscall_pre_impl_exit()
#define __sanitizer_syscall_post_exit() \
  __sanitizer_syscall_post_impl_exit()
#define __sanitizer_syscall_pre_fork() \
  __sanitizer_syscall_pre_impl_fork()
#define __sanitizer_syscall_post_fork() \
  __sanitizer_syscall_post_impl_fork()
#define __sanitizer_syscall_pre_read() \
  __sanitizer_syscall_pre_impl_read()
#define __sanitizer_syscall_post_read() \
  __sanitizer_syscall_post_impl_read()
#define __sanitizer_syscall_pre_write() \
  __sanitizer_syscall_pre_impl_write()
#define __sanitizer_syscall_post_write() \
  __sanitizer_syscall_post_impl_write()
#define __sanitizer_syscall_pre_open() \
  __sanitizer_syscall_pre_impl_open()
#define __sanitizer_syscall_post_open() \
  __sanitizer_syscall_post_impl_open()
#define __sanitizer_syscall_pre_close() \
  __sanitizer_syscall_pre_impl_close()
#define __sanitizer_syscall_post_close() \
  __sanitizer_syscall_post_impl_close()
#define __sanitizer_syscall_pre_compat_50_wait4() \
  __sanitizer_syscall_pre_impl_compat_50_wait4()
#define __sanitizer_syscall_post_compat_50_wait4() \
  __sanitizer_syscall_post_impl_compat_50_wait4()
#define __sanitizer_syscall_pre_compat_43_ocreat() \
  __sanitizer_syscall_pre_impl_compat_43_ocreat()
#define __sanitizer_syscall_post_compat_43_ocreat() \
  __sanitizer_syscall_post_impl_compat_43_ocreat()
#define __sanitizer_syscall_pre_link() \
  __sanitizer_syscall_pre_impl_link()
#define __sanitizer_syscall_post_link() \
  __sanitizer_syscall_post_impl_link()
#define __sanitizer_syscall_pre_unlink() \
  __sanitizer_syscall_pre_impl_unlink()
#define __sanitizer_syscall_post_unlink() \
  __sanitizer_syscall_post_impl_unlink()
/* syscall 11 has been skipped */
#define __sanitizer_syscall_pre_chdir() \
  __sanitizer_syscall_pre_impl_chdir()
#define __sanitizer_syscall_post_chdir() \
  __sanitizer_syscall_post_impl_chdir()
#define __sanitizer_syscall_pre_fchdir() \
  __sanitizer_syscall_pre_impl_fchdir()
#define __sanitizer_syscall_post_fchdir() \
  __sanitizer_syscall_post_impl_fchdir()
#define __sanitizer_syscall_pre_compat_50_mknod() \
  __sanitizer_syscall_pre_impl_compat_50_mknod()
#define __sanitizer_syscall_post_compat_50_mknod() \
  __sanitizer_syscall_post_impl_compat_50_mknod()
#define __sanitizer_syscall_pre_chmod() \
  __sanitizer_syscall_pre_impl_chmod()
#define __sanitizer_syscall_post_chmod() \
  __sanitizer_syscall_post_impl_chmod()
#define __sanitizer_syscall_pre_chown() \
  __sanitizer_syscall_pre_impl_chown()
#define __sanitizer_syscall_post_chown() \
  __sanitizer_syscall_post_impl_chown()
#define __sanitizer_syscall_pre_break() \
  __sanitizer_syscall_pre_impl_break()
#define __sanitizer_syscall_post_break() \
  __sanitizer_syscall_post_impl_break()
#define __sanitizer_syscall_pre_compat_20_getfsstat() \
  __sanitizer_syscall_pre_impl_compat_20_getfsstat()
#define __sanitizer_syscall_post_compat_20_getfsstat() \
  __sanitizer_syscall_post_impl_compat_20_getfsstat()
#define __sanitizer_syscall_pre_compat_43_olseek() \
  __sanitizer_syscall_pre_impl_compat_43_olseek()
#define __sanitizer_syscall_post_compat_43_olseek() \
  __sanitizer_syscall_post_impl_compat_43_olseek()
#define __sanitizer_syscall_pre_getpid() \
  __sanitizer_syscall_pre_impl_getpid()
#define __sanitizer_syscall_post_getpid() \
  __sanitizer_syscall_post_impl_getpid()
#define __sanitizer_syscall_pre_compat_40_mount() \
  __sanitizer_syscall_pre_impl_compat_40_mount()
#define __sanitizer_syscall_post_compat_40_mount() \
  __sanitizer_syscall_post_impl_compat_40_mount()
#define __sanitizer_syscall_pre_unmount() \
  __sanitizer_syscall_pre_impl_unmount()
#define __sanitizer_syscall_post_unmount() \
  __sanitizer_syscall_post_impl_unmount()
#define __sanitizer_syscall_pre_setuid() \
  __sanitizer_syscall_pre_impl_setuid()
#define __sanitizer_syscall_post_setuid() \
  __sanitizer_syscall_post_impl_setuid()
#define __sanitizer_syscall_pre_getuid() \
  __sanitizer_syscall_pre_impl_getuid()
#define __sanitizer_syscall_post_getuid() \
  __sanitizer_syscall_post_impl_getuid()
#define __sanitizer_syscall_pre_geteuid() \
  __sanitizer_syscall_pre_impl_geteuid()
#define __sanitizer_syscall_post_geteuid() \
  __sanitizer_syscall_post_impl_geteuid()
#define __sanitizer_syscall_pre_ptrace() \
  __sanitizer_syscall_pre_impl_ptrace()
#define __sanitizer_syscall_post_ptrace() \
  __sanitizer_syscall_post_impl_ptrace()
#define __sanitizer_syscall_pre_recvmsg() \
  __sanitizer_syscall_pre_impl_recvmsg()
#define __sanitizer_syscall_post_recvmsg() \
  __sanitizer_syscall_post_impl_recvmsg()
#define __sanitizer_syscall_pre_sendmsg() \
  __sanitizer_syscall_pre_impl_sendmsg()
#define __sanitizer_syscall_post_sendmsg() \
  __sanitizer_syscall_post_impl_sendmsg()
#define __sanitizer_syscall_pre_recvfrom() \
  __sanitizer_syscall_pre_impl_recvfrom()
#define __sanitizer_syscall_post_recvfrom() \
  __sanitizer_syscall_post_impl_recvfrom()
#define __sanitizer_syscall_pre_accept() \
  __sanitizer_syscall_pre_impl_accept()
#define __sanitizer_syscall_post_accept() \
  __sanitizer_syscall_post_impl_accept()
#define __sanitizer_syscall_pre_getpeername() \
  __sanitizer_syscall_pre_impl_getpeername()
#define __sanitizer_syscall_post_getpeername() \
  __sanitizer_syscall_post_impl_getpeername()
#define __sanitizer_syscall_pre_getsockname() \
  __sanitizer_syscall_pre_impl_getsockname()
#define __sanitizer_syscall_post_getsockname() \
  __sanitizer_syscall_post_impl_getsockname()
#define __sanitizer_syscall_pre_access() \
  __sanitizer_syscall_pre_impl_access()
#define __sanitizer_syscall_post_access() \
  __sanitizer_syscall_post_impl_access()
#define __sanitizer_syscall_pre_chflags() \
  __sanitizer_syscall_pre_impl_chflags()
#define __sanitizer_syscall_post_chflags() \
  __sanitizer_syscall_post_impl_chflags()
#define __sanitizer_syscall_pre_fchflags() \
  __sanitizer_syscall_pre_impl_fchflags()
#define __sanitizer_syscall_post_fchflags() \
  __sanitizer_syscall_post_impl_fchflags()
#define __sanitizer_syscall_pre_sync() \
  __sanitizer_syscall_pre_impl_sync()
#define __sanitizer_syscall_post_sync() \
  __sanitizer_syscall_post_impl_sync()
#define __sanitizer_syscall_pre_kill() \
  __sanitizer_syscall_pre_impl_kill()
#define __sanitizer_syscall_post_kill() \
  __sanitizer_syscall_post_impl_kill()
#define __sanitizer_syscall_pre_compat_43_stat43() \
  __sanitizer_syscall_pre_impl_compat_43_stat43()
#define __sanitizer_syscall_post_compat_43_stat43() \
  __sanitizer_syscall_post_impl_compat_43_stat43()
#define __sanitizer_syscall_pre_getppid() \
  __sanitizer_syscall_pre_impl_getppid()
#define __sanitizer_syscall_post_getppid() \
  __sanitizer_syscall_post_impl_getppid()
#define __sanitizer_syscall_pre_compat_43_lstat43() \
  __sanitizer_syscall_pre_impl_compat_43_lstat43()
#define __sanitizer_syscall_post_compat_43_lstat43() \
  __sanitizer_syscall_post_impl_compat_43_lstat43()
#define __sanitizer_syscall_pre_dup() \
  __sanitizer_syscall_pre_impl_dup()
#define __sanitizer_syscall_post_dup() \
  __sanitizer_syscall_post_impl_dup()
#define __sanitizer_syscall_pre_pipe() \
  __sanitizer_syscall_pre_impl_pipe()
#define __sanitizer_syscall_post_pipe() \
  __sanitizer_syscall_post_impl_pipe()
#define __sanitizer_syscall_pre_getegid() \
  __sanitizer_syscall_pre_impl_getegid()
#define __sanitizer_syscall_post_getegid() \
  __sanitizer_syscall_post_impl_getegid()
#define __sanitizer_syscall_pre_profil() \
  __sanitizer_syscall_pre_impl_profil()
#define __sanitizer_syscall_post_profil() \
  __sanitizer_syscall_post_impl_profil()
#define __sanitizer_syscall_pre_ktrace() \
  __sanitizer_syscall_pre_impl_ktrace()
#define __sanitizer_syscall_post_ktrace() \
  __sanitizer_syscall_post_impl_ktrace()
#define __sanitizer_syscall_pre_compat_13_sigaction13() \
  __sanitizer_syscall_pre_impl_compat_13_sigaction13()
#define __sanitizer_syscall_post_compat_13_sigaction13() \
  __sanitizer_syscall_post_impl_compat_13_sigaction13()
#define __sanitizer_syscall_pre_getgid() \
  __sanitizer_syscall_pre_impl_getgid()
#define __sanitizer_syscall_post_getgid() \
  __sanitizer_syscall_post_impl_getgid()
#define __sanitizer_syscall_pre_compat_13_sigprocmask13() \
  __sanitizer_syscall_pre_impl_compat_13_sigprocmask13()
#define __sanitizer_syscall_post_compat_13_sigprocmask13() \
  __sanitizer_syscall_post_impl_compat_13_sigprocmask13()
#define __sanitizer_syscall_pre___getlogin() \
  __sanitizer_syscall_pre_impl___getlogin()
#define __sanitizer_syscall_post___getlogin() \
  __sanitizer_syscall_post_impl___getlogin()
#define __sanitizer_syscall_pre___setlogin() \
  __sanitizer_syscall_pre_impl___setlogin()
#define __sanitizer_syscall_post___setlogin() \
  __sanitizer_syscall_post_impl___setlogin()
#define __sanitizer_syscall_pre_acct() \
  __sanitizer_syscall_pre_impl_acct()
#define __sanitizer_syscall_post_acct() \
  __sanitizer_syscall_post_impl_acct()
#define __sanitizer_syscall_pre_compat_13_sigpending13() \
  __sanitizer_syscall_pre_impl_compat_13_sigpending13()
#define __sanitizer_syscall_post_compat_13_sigpending13() \
  __sanitizer_syscall_post_impl_compat_13_sigpending13()
#define __sanitizer_syscall_pre_compat_13_sigaltstack13() \
  __sanitizer_syscall_pre_impl_compat_13_sigaltstack13()
#define __sanitizer_syscall_post_compat_13_sigaltstack13() \
  __sanitizer_syscall_post_impl_compat_13_sigaltstack13()
#define __sanitizer_syscall_pre_ioctl() \
  __sanitizer_syscall_pre_impl_ioctl()
#define __sanitizer_syscall_post_ioctl() \
  __sanitizer_syscall_post_impl_ioctl()
#define __sanitizer_syscall_pre_compat_12_oreboot() \
  __sanitizer_syscall_pre_impl_compat_12_oreboot()
#define __sanitizer_syscall_post_compat_12_oreboot() \
  __sanitizer_syscall_post_impl_compat_12_oreboot()
#define __sanitizer_syscall_pre_revoke() \
  __sanitizer_syscall_pre_impl_revoke()
#define __sanitizer_syscall_post_revoke() \
  __sanitizer_syscall_post_impl_revoke()
#define __sanitizer_syscall_pre_symlink() \
  __sanitizer_syscall_pre_impl_symlink()
#define __sanitizer_syscall_post_symlink() \
  __sanitizer_syscall_post_impl_symlink()
#define __sanitizer_syscall_pre_readlink() \
  __sanitizer_syscall_pre_impl_readlink()
#define __sanitizer_syscall_post_readlink() \
  __sanitizer_syscall_post_impl_readlink()
#define __sanitizer_syscall_pre_execve() \
  __sanitizer_syscall_pre_impl_execve()
#define __sanitizer_syscall_post_execve() \
  __sanitizer_syscall_post_impl_execve()
#define __sanitizer_syscall_pre_umask() \
  __sanitizer_syscall_pre_impl_umask()
#define __sanitizer_syscall_post_umask() \
  __sanitizer_syscall_post_impl_umask()
#define __sanitizer_syscall_pre_chroot() \
  __sanitizer_syscall_pre_impl_chroot()
#define __sanitizer_syscall_post_chroot() \
  __sanitizer_syscall_post_impl_chroot()
#define __sanitizer_syscall_pre_compat_43_fstat43() \
  __sanitizer_syscall_pre_impl_compat_43_fstat43()
#define __sanitizer_syscall_post_compat_43_fstat43() \
  __sanitizer_syscall_post_impl_compat_43_fstat43()
#define __sanitizer_syscall_pre_compat_43_ogetkerninfo() \
  __sanitizer_syscall_pre_impl_compat_43_ogetkerninfo()
#define __sanitizer_syscall_post_compat_43_ogetkerninfo() \
  __sanitizer_syscall_post_impl_compat_43_ogetkerninfo()
#define __sanitizer_syscall_pre_compat_43_ogetpagesize() \
  __sanitizer_syscall_pre_impl_compat_43_ogetpagesize()
#define __sanitizer_syscall_post_compat_43_ogetpagesize() \
  __sanitizer_syscall_post_impl_compat_43_ogetpagesize()
#define __sanitizer_syscall_pre_compat_12_msync() \
  __sanitizer_syscall_pre_impl_compat_12_msync()
#define __sanitizer_syscall_post_compat_12_msync() \
  __sanitizer_syscall_post_impl_compat_12_msync()
#define __sanitizer_syscall_pre_vfork() \
  __sanitizer_syscall_pre_impl_vfork()
#define __sanitizer_syscall_post_vfork() \
  __sanitizer_syscall_post_impl_vfork()
/* syscall 67 has been skipped */
/* syscall 68 has been skipped */
#define __sanitizer_syscall_pre_sbrk() \
  __sanitizer_syscall_pre_impl_sbrk()
#define __sanitizer_syscall_post_sbrk() \
  __sanitizer_syscall_post_impl_sbrk()
#define __sanitizer_syscall_pre_sstk() \
  __sanitizer_syscall_pre_impl_sstk()
#define __sanitizer_syscall_post_sstk() \
  __sanitizer_syscall_post_impl_sstk()
#define __sanitizer_syscall_pre_compat_43_ommap() \
  __sanitizer_syscall_pre_impl_compat_43_ommap()
#define __sanitizer_syscall_post_compat_43_ommap() \
  __sanitizer_syscall_post_impl_compat_43_ommap()
#define __sanitizer_syscall_pre_vadvise() \
  __sanitizer_syscall_pre_impl_vadvise()
#define __sanitizer_syscall_post_vadvise() \
  __sanitizer_syscall_post_impl_vadvise()
#define __sanitizer_syscall_pre_munmap() \
  __sanitizer_syscall_pre_impl_munmap()
#define __sanitizer_syscall_post_munmap() \
  __sanitizer_syscall_post_impl_munmap()
#define __sanitizer_syscall_pre_mprotect() \
  __sanitizer_syscall_pre_impl_mprotect()
#define __sanitizer_syscall_post_mprotect() \
  __sanitizer_syscall_post_impl_mprotect()
#define __sanitizer_syscall_pre_madvise() \
  __sanitizer_syscall_pre_impl_madvise()
#define __sanitizer_syscall_post_madvise() \
  __sanitizer_syscall_post_impl_madvise()
/* syscall 76 has been skipped */
/* syscall 77 has been skipped */
#define __sanitizer_syscall_pre_mincore() \
  __sanitizer_syscall_pre_impl_mincore()
#define __sanitizer_syscall_post_mincore() \
  __sanitizer_syscall_post_impl_mincore()
#define __sanitizer_syscall_pre_getgroups() \
  __sanitizer_syscall_pre_impl_getgroups()
#define __sanitizer_syscall_post_getgroups() \
  __sanitizer_syscall_post_impl_getgroups()
#define __sanitizer_syscall_pre_setgroups() \
  __sanitizer_syscall_pre_impl_setgroups()
#define __sanitizer_syscall_post_setgroups() \
  __sanitizer_syscall_post_impl_setgroups()
#define __sanitizer_syscall_pre_getpgrp() \
  __sanitizer_syscall_pre_impl_getpgrp()
#define __sanitizer_syscall_post_getpgrp() \
  __sanitizer_syscall_post_impl_getpgrp()
#define __sanitizer_syscall_pre_setpgid() \
  __sanitizer_syscall_pre_impl_setpgid()
#define __sanitizer_syscall_post_setpgid() \
  __sanitizer_syscall_post_impl_setpgid()
#define __sanitizer_syscall_pre_compat_50_setitimer() \
  __sanitizer_syscall_pre_impl_compat_50_setitimer()
#define __sanitizer_syscall_post_compat_50_setitimer() \
  __sanitizer_syscall_post_impl_compat_50_setitimer()
#define __sanitizer_syscall_pre_compat_43_owait() \
  __sanitizer_syscall_pre_impl_compat_43_owait()
#define __sanitizer_syscall_post_compat_43_owait() \
  __sanitizer_syscall_post_impl_compat_43_owait()
#define __sanitizer_syscall_pre_compat_12_oswapon() \
  __sanitizer_syscall_pre_impl_compat_12_oswapon()
#define __sanitizer_syscall_post_compat_12_oswapon() \
  __sanitizer_syscall_post_impl_compat_12_oswapon()
#define __sanitizer_syscall_pre_compat_50_getitimer() \
  __sanitizer_syscall_pre_impl_compat_50_getitimer()
#define __sanitizer_syscall_post_compat_50_getitimer() \
  __sanitizer_syscall_post_impl_compat_50_getitimer()
#define __sanitizer_syscall_pre_compat_43_ogethostname() \
  __sanitizer_syscall_pre_impl_compat_43_ogethostname()
#define __sanitizer_syscall_post_compat_43_ogethostname() \
  __sanitizer_syscall_post_impl_compat_43_ogethostname()
#define __sanitizer_syscall_pre_compat_43_osethostname() \
  __sanitizer_syscall_pre_impl_compat_43_osethostname()
#define __sanitizer_syscall_post_compat_43_osethostname() \
  __sanitizer_syscall_post_impl_compat_43_osethostname()
#define __sanitizer_syscall_pre_compat_43_ogetdtablesize() \
  __sanitizer_syscall_pre_impl_compat_43_ogetdtablesize()
#define __sanitizer_syscall_post_compat_43_ogetdtablesize() \
  __sanitizer_syscall_post_impl_compat_43_ogetdtablesize()
#define __sanitizer_syscall_pre_dup2() \
  __sanitizer_syscall_pre_impl_dup2()
#define __sanitizer_syscall_post_dup2() \
  __sanitizer_syscall_post_impl_dup2()
/* syscall 91 has been skipped */
#define __sanitizer_syscall_pre_fcntl() \
  __sanitizer_syscall_pre_impl_fcntl()
#define __sanitizer_syscall_post_fcntl() \
  __sanitizer_syscall_post_impl_fcntl()
#define __sanitizer_syscall_pre_compat_50_select() \
  __sanitizer_syscall_pre_impl_compat_50_select()
#define __sanitizer_syscall_post_compat_50_select() \
  __sanitizer_syscall_post_impl_compat_50_select()
/* syscall 94 has been skipped */
#define __sanitizer_syscall_pre_fsync() \
  __sanitizer_syscall_pre_impl_fsync()
#define __sanitizer_syscall_post_fsync() \
  __sanitizer_syscall_post_impl_fsync()
#define __sanitizer_syscall_pre_setpriority() \
  __sanitizer_syscall_pre_impl_setpriority()
#define __sanitizer_syscall_post_setpriority() \
  __sanitizer_syscall_post_impl_setpriority()
#define __sanitizer_syscall_pre_compat_30_socket() \
  __sanitizer_syscall_pre_impl_compat_30_socket()
#define __sanitizer_syscall_post_compat_30_socket() \
  __sanitizer_syscall_post_impl_compat_30_socket()
#define __sanitizer_syscall_pre_connect() \
  __sanitizer_syscall_pre_impl_connect()
#define __sanitizer_syscall_post_connect() \
  __sanitizer_syscall_post_impl_connect()
#define __sanitizer_syscall_pre_compat_43_oaccept() \
  __sanitizer_syscall_pre_impl_compat_43_oaccept()
#define __sanitizer_syscall_post_compat_43_oaccept() \
  __sanitizer_syscall_post_impl_compat_43_oaccept()
#define __sanitizer_syscall_pre_getpriority() \
  __sanitizer_syscall_pre_impl_getpriority()
#define __sanitizer_syscall_post_getpriority() \
  __sanitizer_syscall_post_impl_getpriority()
#define __sanitizer_syscall_pre_compat_43_osend() \
  __sanitizer_syscall_pre_impl_compat_43_osend()
#define __sanitizer_syscall_post_compat_43_osend() \
  __sanitizer_syscall_post_impl_compat_43_osend()
#define __sanitizer_syscall_pre_compat_43_orecv() \
  __sanitizer_syscall_pre_impl_compat_43_orecv()
#define __sanitizer_syscall_post_compat_43_orecv() \
  __sanitizer_syscall_post_impl_compat_43_orecv()
#define __sanitizer_syscall_pre_compat_13_sigreturn13() \
  __sanitizer_syscall_pre_impl_compat_13_sigreturn13()
#define __sanitizer_syscall_post_compat_13_sigreturn13() \
  __sanitizer_syscall_post_impl_compat_13_sigreturn13()
#define __sanitizer_syscall_pre_bind() \
  __sanitizer_syscall_pre_impl_bind()
#define __sanitizer_syscall_post_bind() \
  __sanitizer_syscall_post_impl_bind()
#define __sanitizer_syscall_pre_setsockopt() \
  __sanitizer_syscall_pre_impl_setsockopt()
#define __sanitizer_syscall_post_setsockopt() \
  __sanitizer_syscall_post_impl_setsockopt()
#define __sanitizer_syscall_pre_listen() \
  __sanitizer_syscall_pre_impl_listen()
#define __sanitizer_syscall_post_listen() \
  __sanitizer_syscall_post_impl_listen()
/* syscall 107 has been skipped */
#define __sanitizer_syscall_pre_compat_43_osigvec() \
  __sanitizer_syscall_pre_impl_compat_43_osigvec()
#define __sanitizer_syscall_post_compat_43_osigvec() \
  __sanitizer_syscall_post_impl_compat_43_osigvec()
#define __sanitizer_syscall_pre_compat_43_osigblock() \
  __sanitizer_syscall_pre_impl_compat_43_osigblock()
#define __sanitizer_syscall_post_compat_43_osigblock() \
  __sanitizer_syscall_post_impl_compat_43_osigblock()
#define __sanitizer_syscall_pre_compat_43_osigsetmask() \
  __sanitizer_syscall_pre_impl_compat_43_osigsetmask()
#define __sanitizer_syscall_post_compat_43_osigsetmask() \
  __sanitizer_syscall_post_impl_compat_43_osigsetmask()
#define __sanitizer_syscall_pre_compat_13_sigsuspend13() \
  __sanitizer_syscall_pre_impl_compat_13_sigsuspend13()
#define __sanitizer_syscall_post_compat_13_sigsuspend13() \
  __sanitizer_syscall_post_impl_compat_13_sigsuspend13()
#define __sanitizer_syscall_pre_compat_43_osigstack() \
  __sanitizer_syscall_pre_impl_compat_43_osigstack()
#define __sanitizer_syscall_post_compat_43_osigstack() \
  __sanitizer_syscall_post_impl_compat_43_osigstack()
#define __sanitizer_syscall_pre_compat_43_orecvmsg() \
  __sanitizer_syscall_pre_impl_compat_43_orecvmsg()
#define __sanitizer_syscall_post_compat_43_orecvmsg() \
  __sanitizer_syscall_post_impl_compat_43_orecvmsg()
#define __sanitizer_syscall_pre_compat_43_osendmsg() \
  __sanitizer_syscall_pre_impl_compat_43_osendmsg()
#define __sanitizer_syscall_post_compat_43_osendmsg() \
  __sanitizer_syscall_post_impl_compat_43_osendmsg()
/* syscall 115 has been skipped */
#define __sanitizer_syscall_pre_compat_50_gettimeofday() \
  __sanitizer_syscall_pre_impl_compat_50_gettimeofday()
#define __sanitizer_syscall_post_compat_50_gettimeofday() \
  __sanitizer_syscall_post_impl_compat_50_gettimeofday()
#define __sanitizer_syscall_pre_compat_50_getrusage() \
  __sanitizer_syscall_pre_impl_compat_50_getrusage()
#define __sanitizer_syscall_post_compat_50_getrusage() \
  __sanitizer_syscall_post_impl_compat_50_getrusage()
#define __sanitizer_syscall_pre_getsockopt() \
  __sanitizer_syscall_pre_impl_getsockopt()
#define __sanitizer_syscall_post_getsockopt() \
  __sanitizer_syscall_post_impl_getsockopt()
/* syscall 119 has been skipped */
#define __sanitizer_syscall_pre_readv() \
  __sanitizer_syscall_pre_impl_readv()
#define __sanitizer_syscall_post_readv() \
  __sanitizer_syscall_post_impl_readv()
#define __sanitizer_syscall_pre_writev() \
  __sanitizer_syscall_pre_impl_writev()
#define __sanitizer_syscall_post_writev() \
  __sanitizer_syscall_post_impl_writev()
#define __sanitizer_syscall_pre_compat_50_settimeofday() \
  __sanitizer_syscall_pre_impl_compat_50_settimeofday()
#define __sanitizer_syscall_post_compat_50_settimeofday() \
  __sanitizer_syscall_post_impl_compat_50_settimeofday()
#define __sanitizer_syscall_pre_fchown() \
  __sanitizer_syscall_pre_impl_fchown()
#define __sanitizer_syscall_post_fchown() \
  __sanitizer_syscall_post_impl_fchown()
#define __sanitizer_syscall_pre_fchmod() \
  __sanitizer_syscall_pre_impl_fchmod()
#define __sanitizer_syscall_post_fchmod() \
  __sanitizer_syscall_post_impl_fchmod()
#define __sanitizer_syscall_pre_compat_43_orecvfrom() \
  __sanitizer_syscall_pre_impl_compat_43_orecvfrom()
#define __sanitizer_syscall_post_compat_43_orecvfrom() \
  __sanitizer_syscall_post_impl_compat_43_orecvfrom()
#define __sanitizer_syscall_pre_setreuid() \
  __sanitizer_syscall_pre_impl_setreuid()
#define __sanitizer_syscall_post_setreuid() \
  __sanitizer_syscall_post_impl_setreuid()
#define __sanitizer_syscall_pre_setregid() \
  __sanitizer_syscall_pre_impl_setregid()
#define __sanitizer_syscall_post_setregid() \
  __sanitizer_syscall_post_impl_setregid()
#define __sanitizer_syscall_pre_rename() \
  __sanitizer_syscall_pre_impl_rename()
#define __sanitizer_syscall_post_rename() \
  __sanitizer_syscall_post_impl_rename()
#define __sanitizer_syscall_pre_compat_43_otruncate() \
  __sanitizer_syscall_pre_impl_compat_43_otruncate()
#define __sanitizer_syscall_post_compat_43_otruncate() \
  __sanitizer_syscall_post_impl_compat_43_otruncate()
#define __sanitizer_syscall_pre_compat_43_oftruncate() \
  __sanitizer_syscall_pre_impl_compat_43_oftruncate()
#define __sanitizer_syscall_post_compat_43_oftruncate() \
  __sanitizer_syscall_post_impl_compat_43_oftruncate()
#define __sanitizer_syscall_pre_flock() \
  __sanitizer_syscall_pre_impl_flock()
#define __sanitizer_syscall_post_flock() \
  __sanitizer_syscall_post_impl_flock()
#define __sanitizer_syscall_pre_mkfifo() \
  __sanitizer_syscall_pre_impl_mkfifo()
#define __sanitizer_syscall_post_mkfifo() \
  __sanitizer_syscall_post_impl_mkfifo()
#define __sanitizer_syscall_pre_sendto() \
  __sanitizer_syscall_pre_impl_sendto()
#define __sanitizer_syscall_post_sendto() \
  __sanitizer_syscall_post_impl_sendto()
#define __sanitizer_syscall_pre_shutdown() \
  __sanitizer_syscall_pre_impl_shutdown()
#define __sanitizer_syscall_post_shutdown() \
  __sanitizer_syscall_post_impl_shutdown()
#define __sanitizer_syscall_pre_socketpair() \
  __sanitizer_syscall_pre_impl_socketpair()
#define __sanitizer_syscall_post_socketpair() \
  __sanitizer_syscall_post_impl_socketpair()
#define __sanitizer_syscall_pre_mkdir() \
  __sanitizer_syscall_pre_impl_mkdir()
#define __sanitizer_syscall_post_mkdir() \
  __sanitizer_syscall_post_impl_mkdir()
#define __sanitizer_syscall_pre_rmdir() \
  __sanitizer_syscall_pre_impl_rmdir()
#define __sanitizer_syscall_post_rmdir() \
  __sanitizer_syscall_post_impl_rmdir()
#define __sanitizer_syscall_pre_compat_50_utimes() \
  __sanitizer_syscall_pre_impl_compat_50_utimes()
#define __sanitizer_syscall_post_compat_50_utimes() \
  __sanitizer_syscall_post_impl_compat_50_utimes()
/* syscall 139 has been skipped */
#define __sanitizer_syscall_pre_compat_50_adjtime() \
  __sanitizer_syscall_pre_impl_compat_50_adjtime()
#define __sanitizer_syscall_post_compat_50_adjtime() \
  __sanitizer_syscall_post_impl_compat_50_adjtime()
#define __sanitizer_syscall_pre_compat_43_ogetpeername() \
  __sanitizer_syscall_pre_impl_compat_43_ogetpeername()
#define __sanitizer_syscall_post_compat_43_ogetpeername() \
  __sanitizer_syscall_post_impl_compat_43_ogetpeername()
#define __sanitizer_syscall_pre_compat_43_ogethostid() \
  __sanitizer_syscall_pre_impl_compat_43_ogethostid()
#define __sanitizer_syscall_post_compat_43_ogethostid() \
  __sanitizer_syscall_post_impl_compat_43_ogethostid()
#define __sanitizer_syscall_pre_compat_43_osethostid() \
  __sanitizer_syscall_pre_impl_compat_43_osethostid()
#define __sanitizer_syscall_post_compat_43_osethostid() \
  __sanitizer_syscall_post_impl_compat_43_osethostid()
#define __sanitizer_syscall_pre_compat_43_ogetrlimit() \
  __sanitizer_syscall_pre_impl_compat_43_ogetrlimit()
#define __sanitizer_syscall_post_compat_43_ogetrlimit() \
  __sanitizer_syscall_post_impl_compat_43_ogetrlimit()
#define __sanitizer_syscall_pre_compat_43_osetrlimit() \
  __sanitizer_syscall_pre_impl_compat_43_osetrlimit()
#define __sanitizer_syscall_post_compat_43_osetrlimit() \
  __sanitizer_syscall_post_impl_compat_43_osetrlimit()
#define __sanitizer_syscall_pre_compat_43_okillpg() \
  __sanitizer_syscall_pre_impl_compat_43_okillpg()
#define __sanitizer_syscall_post_compat_43_okillpg() \
  __sanitizer_syscall_post_impl_compat_43_okillpg()
#define __sanitizer_syscall_pre_setsid() \
  __sanitizer_syscall_pre_impl_setsid()
#define __sanitizer_syscall_post_setsid() \
  __sanitizer_syscall_post_impl_setsid()
#define __sanitizer_syscall_pre_compat_50_quotactl() \
  __sanitizer_syscall_pre_impl_compat_50_quotactl()
#define __sanitizer_syscall_post_compat_50_quotactl() \
  __sanitizer_syscall_post_impl_compat_50_quotactl()
#define __sanitizer_syscall_pre_compat_43_oquota() \
  __sanitizer_syscall_pre_impl_compat_43_oquota()
#define __sanitizer_syscall_post_compat_43_oquota() \
  __sanitizer_syscall_post_impl_compat_43_oquota()
#define __sanitizer_syscall_pre_compat_43_ogetsockname() \
  __sanitizer_syscall_pre_impl_compat_43_ogetsockname()
#define __sanitizer_syscall_post_compat_43_ogetsockname() \
  __sanitizer_syscall_post_impl_compat_43_ogetsockname()
/* syscall 151 has been skipped */
/* syscall 152 has been skipped */
/* syscall 153 has been skipped */
/* syscall 154 has been skipped */
#define __sanitizer_syscall_pre_nfssvc() \
  __sanitizer_syscall_pre_impl_nfssvc()
#define __sanitizer_syscall_post_nfssvc() \
  __sanitizer_syscall_post_impl_nfssvc()
#define __sanitizer_syscall_pre_compat_43_ogetdirentries() \
  __sanitizer_syscall_pre_impl_compat_43_ogetdirentries()
#define __sanitizer_syscall_post_compat_43_ogetdirentries() \
  __sanitizer_syscall_post_impl_compat_43_ogetdirentries()
#define __sanitizer_syscall_pre_compat_20_statfs() \
  __sanitizer_syscall_pre_impl_compat_20_statfs()
#define __sanitizer_syscall_post_compat_20_statfs() \
  __sanitizer_syscall_post_impl_compat_20_statfs()
#define __sanitizer_syscall_pre_compat_20_fstatfs() \
  __sanitizer_syscall_pre_impl_compat_20_fstatfs()
#define __sanitizer_syscall_post_compat_20_fstatfs() \
  __sanitizer_syscall_post_impl_compat_20_fstatfs()
/* syscall 159 has been skipped */
/* syscall 160 has been skipped */
#define __sanitizer_syscall_pre_compat_30_getfh() \
  __sanitizer_syscall_pre_impl_compat_30_getfh()
#define __sanitizer_syscall_post_compat_30_getfh() \
  __sanitizer_syscall_post_impl_compat_30_getfh()
#define __sanitizer_syscall_pre_compat_09_ogetdomainname() \
  __sanitizer_syscall_pre_impl_compat_09_ogetdomainname()
#define __sanitizer_syscall_post_compat_09_ogetdomainname() \
  __sanitizer_syscall_post_impl_compat_09_ogetdomainname()
#define __sanitizer_syscall_pre_compat_09_osetdomainname() \
  __sanitizer_syscall_pre_impl_compat_09_osetdomainname()
#define __sanitizer_syscall_post_compat_09_osetdomainname() \
  __sanitizer_syscall_post_impl_compat_09_osetdomainname()
#define __sanitizer_syscall_pre_compat_09_ouname() \
  __sanitizer_syscall_pre_impl_compat_09_ouname()
#define __sanitizer_syscall_post_compat_09_ouname() \
  __sanitizer_syscall_post_impl_compat_09_ouname()
#define __sanitizer_syscall_pre_sysarch() \
  __sanitizer_syscall_pre_impl_sysarch()
#define __sanitizer_syscall_post_sysarch() \
  __sanitizer_syscall_post_impl_sysarch()
/* syscall 166 has been skipped */
/* syscall 167 has been skipped */
/* syscall 168 has been skipped */
#if !defined(_LP64)
#define __sanitizer_syscall_pre_compat_10_osemsys() \
  __sanitizer_syscall_pre_impl_compat_10_osemsys()
#define __sanitizer_syscall_post_compat_10_osemsys() \
  __sanitizer_syscall_post_impl_compat_10_osemsys()
#else
/* syscall 169 has been skipped */
#if !defined(_LP64)
#define __sanitizer_syscall_pre_compat_10_omsgsys() \
  __sanitizer_syscall_pre_impl_compat_10_omsgsys()
#define __sanitizer_syscall_post_compat_10_omsgsys() \
  __sanitizer_syscall_post_impl_compat_10_omsgsys()
#else
/* syscall 170 has been skipped */
#if !defined(_LP64)
#define __sanitizer_syscall_pre_compat_10_oshmsys() \
  __sanitizer_syscall_pre_impl_compat_10_oshmsys()
#define __sanitizer_syscall_post_compat_10_oshmsys() \
  __sanitizer_syscall_post_impl_compat_10_oshmsys()
#else
/* syscall 171 has been skipped */
#endif
/* syscall 172 has been skipped */
#define __sanitizer_syscall_pre_pread() \
  __sanitizer_syscall_pre_impl_pread()
#define __sanitizer_syscall_post_pread() \
  __sanitizer_syscall_post_impl_pread()
#define __sanitizer_syscall_pre_pwrite() \
  __sanitizer_syscall_pre_impl_pwrite()
#define __sanitizer_syscall_post_pwrite() \
  __sanitizer_syscall_post_impl_pwrite()
#define __sanitizer_syscall_pre_compat_30_ntp_gettime() \
  __sanitizer_syscall_pre_impl_compat_30_ntp_gettime()
#define __sanitizer_syscall_post_compat_30_ntp_gettime() \
  __sanitizer_syscall_post_impl_compat_30_ntp_gettime()
#if defined(NTP) || !defined(_KERNEL_OPT)
#define __sanitizer_syscall_pre_ntp_adjtime() \
  __sanitizer_syscall_pre_impl_ntp_adjtime()
#define __sanitizer_syscall_post_ntp_adjtime() \
  __sanitizer_syscall_post_impl_ntp_adjtime()
#else
/* syscall 176 has been skipped */
#endif
/* syscall 177 has been skipped */
/* syscall 178 has been skipped */
/* syscall 179 has been skipped */
/* syscall 180 has been skipped */
#define __sanitizer_syscall_pre_setgid() \
  __sanitizer_syscall_pre_impl_setgid()
#define __sanitizer_syscall_post_setgid() \
  __sanitizer_syscall_post_impl_setgid()
#define __sanitizer_syscall_pre_setegid() \
  __sanitizer_syscall_pre_impl_setegid()
#define __sanitizer_syscall_post_setegid() \
  __sanitizer_syscall_post_impl_setegid()
#define __sanitizer_syscall_pre_seteuid() \
  __sanitizer_syscall_pre_impl_seteuid()
#define __sanitizer_syscall_post_seteuid() \
  __sanitizer_syscall_post_impl_seteuid()
#define __sanitizer_syscall_pre_lfs_bmapv() \
  __sanitizer_syscall_pre_impl_lfs_bmapv()
#define __sanitizer_syscall_post_lfs_bmapv() \
  __sanitizer_syscall_post_impl_lfs_bmapv()
#define __sanitizer_syscall_pre_lfs_markv() \
  __sanitizer_syscall_pre_impl_lfs_markv()
#define __sanitizer_syscall_post_lfs_markv() \
  __sanitizer_syscall_post_impl_lfs_markv()
#define __sanitizer_syscall_pre_lfs_segclean() \
  __sanitizer_syscall_pre_impl_lfs_segclean()
#define __sanitizer_syscall_post_lfs_segclean() \
  __sanitizer_syscall_post_impl_lfs_segclean()
#define __sanitizer_syscall_pre_compat_50_lfs_segwait() \
  __sanitizer_syscall_pre_impl_compat_50_lfs_segwait()
#define __sanitizer_syscall_post_compat_50_lfs_segwait() \
  __sanitizer_syscall_post_impl_compat_50_lfs_segwait()
#define __sanitizer_syscall_pre_compat_12_stat12() \
  __sanitizer_syscall_pre_impl_compat_12_stat12()
#define __sanitizer_syscall_post_compat_12_stat12() \
  __sanitizer_syscall_post_impl_compat_12_stat12()
#define __sanitizer_syscall_pre_compat_12_fstat12() \
  __sanitizer_syscall_pre_impl_compat_12_fstat12()
#define __sanitizer_syscall_post_compat_12_fstat12() \
  __sanitizer_syscall_post_impl_compat_12_fstat12()
#define __sanitizer_syscall_pre_compat_12_lstat12() \
  __sanitizer_syscall_pre_impl_compat_12_lstat12()
#define __sanitizer_syscall_post_compat_12_lstat12() \
  __sanitizer_syscall_post_impl_compat_12_lstat12()
#define __sanitizer_syscall_pre_pathconf() \
  __sanitizer_syscall_pre_impl_pathconf()
#define __sanitizer_syscall_post_pathconf() \
  __sanitizer_syscall_post_impl_pathconf()
#define __sanitizer_syscall_pre_fpathconf() \
  __sanitizer_syscall_pre_impl_fpathconf()
#define __sanitizer_syscall_post_fpathconf() \
  __sanitizer_syscall_post_impl_fpathconf()
/* syscall 193 has been skipped */
#define __sanitizer_syscall_pre_getrlimit() \
  __sanitizer_syscall_pre_impl_getrlimit()
#define __sanitizer_syscall_post_getrlimit() \
  __sanitizer_syscall_post_impl_getrlimit()
#define __sanitizer_syscall_pre_setrlimit() \
  __sanitizer_syscall_pre_impl_setrlimit()
#define __sanitizer_syscall_post_setrlimit() \
  __sanitizer_syscall_post_impl_setrlimit()
#define __sanitizer_syscall_pre_compat_12_getdirentries() \
  __sanitizer_syscall_pre_impl_compat_12_getdirentries()
#define __sanitizer_syscall_post_compat_12_getdirentries() \
  __sanitizer_syscall_post_impl_compat_12_getdirentries()
#define __sanitizer_syscall_pre_mmap() \
  __sanitizer_syscall_pre_impl_mmap()
#define __sanitizer_syscall_post_mmap() \
  __sanitizer_syscall_post_impl_mmap()
#define __sanitizer_syscall_pre___syscall() \
  __sanitizer_syscall_pre_impl___syscall()
#define __sanitizer_syscall_post___syscall() \
  __sanitizer_syscall_post_impl___syscall()
#define __sanitizer_syscall_pre_lseek() \
  __sanitizer_syscall_pre_impl_lseek()
#define __sanitizer_syscall_post_lseek() \
  __sanitizer_syscall_post_impl_lseek()
#define __sanitizer_syscall_pre_truncate() \
  __sanitizer_syscall_pre_impl_truncate()
#define __sanitizer_syscall_post_truncate() \
  __sanitizer_syscall_post_impl_truncate()
#define __sanitizer_syscall_pre_ftruncate() \
  __sanitizer_syscall_pre_impl_ftruncate()
#define __sanitizer_syscall_post_ftruncate() \
  __sanitizer_syscall_post_impl_ftruncate()
#define __sanitizer_syscall_pre___sysctl() \
  __sanitizer_syscall_pre_impl___sysctl()
#define __sanitizer_syscall_post___sysctl() \
  __sanitizer_syscall_post_impl___sysctl()
#define __sanitizer_syscall_pre_mlock() \
  __sanitizer_syscall_pre_impl_mlock()
#define __sanitizer_syscall_post_mlock() \
  __sanitizer_syscall_post_impl_mlock()
#define __sanitizer_syscall_pre_munlock() \
  __sanitizer_syscall_pre_impl_munlock()
#define __sanitizer_syscall_post_munlock() \
  __sanitizer_syscall_post_impl_munlock()
#define __sanitizer_syscall_pre_undelete() \
  __sanitizer_syscall_pre_impl_undelete()
#define __sanitizer_syscall_post_undelete() \
  __sanitizer_syscall_post_impl_undelete()
#define __sanitizer_syscall_pre_compat_50_futimes() \
  __sanitizer_syscall_pre_impl_compat_50_futimes()
#define __sanitizer_syscall_post_compat_50_futimes() \
  __sanitizer_syscall_post_impl_compat_50_futimes()
#define __sanitizer_syscall_pre_getpgid() \
  __sanitizer_syscall_pre_impl_getpgid()
#define __sanitizer_syscall_post_getpgid() \
  __sanitizer_syscall_post_impl_getpgid()
#define __sanitizer_syscall_pre_reboot() \
  __sanitizer_syscall_pre_impl_reboot()
#define __sanitizer_syscall_post_reboot() \
  __sanitizer_syscall_post_impl_reboot()
#define __sanitizer_syscall_pre_poll() \
  __sanitizer_syscall_pre_impl_poll()
#define __sanitizer_syscall_post_poll() \
  __sanitizer_syscall_post_impl_poll()
#define __sanitizer_syscall_pre_afssys() \
  __sanitizer_syscall_pre_impl_afssys()
#define __sanitizer_syscall_post_afssys() \
  __sanitizer_syscall_post_impl_afssys()
/* syscall 211 has been skipped */
/* syscall 212 has been skipped */
/* syscall 213 has been skipped */
/* syscall 214 has been skipped */
/* syscall 215 has been skipped */
/* syscall 216 has been skipped */
/* syscall 217 has been skipped */
/* syscall 218 has been skipped */
/* syscall 219 has been skipped */
#define __sanitizer_syscall_pre_compat_14___semctl() \
  __sanitizer_syscall_pre_impl_compat_14___semctl()
#define __sanitizer_syscall_post_compat_14___semctl() \
  __sanitizer_syscall_post_impl_compat_14___semctl()
#define __sanitizer_syscall_pre_semget() \
  __sanitizer_syscall_pre_impl_semget()
#define __sanitizer_syscall_post_semget() \
  __sanitizer_syscall_post_impl_semget()
#define __sanitizer_syscall_pre_semop() \
  __sanitizer_syscall_pre_impl_semop()
#define __sanitizer_syscall_post_semop() \
  __sanitizer_syscall_post_impl_semop()
#define __sanitizer_syscall_pre_semconfig() \
  __sanitizer_syscall_pre_impl_semconfig()
#define __sanitizer_syscall_post_semconfig() \
  __sanitizer_syscall_post_impl_semconfig()
#define __sanitizer_syscall_pre_compat_14_msgctl() \
  __sanitizer_syscall_pre_impl_compat_14_msgctl()
#define __sanitizer_syscall_post_compat_14_msgctl() \
  __sanitizer_syscall_post_impl_compat_14_msgctl()
#define __sanitizer_syscall_pre_msgget() \
  __sanitizer_syscall_pre_impl_msgget()
#define __sanitizer_syscall_post_msgget() \
  __sanitizer_syscall_post_impl_msgget()
#define __sanitizer_syscall_pre_msgsnd() \
  __sanitizer_syscall_pre_impl_msgsnd()
#define __sanitizer_syscall_post_msgsnd() \
  __sanitizer_syscall_post_impl_msgsnd()
#define __sanitizer_syscall_pre_msgrcv() \
  __sanitizer_syscall_pre_impl_msgrcv()
#define __sanitizer_syscall_post_msgrcv() \
  __sanitizer_syscall_post_impl_msgrcv()
#define __sanitizer_syscall_pre_shmat() \
  __sanitizer_syscall_pre_impl_shmat()
#define __sanitizer_syscall_post_shmat() \
  __sanitizer_syscall_post_impl_shmat()
#define __sanitizer_syscall_pre_compat_14_shmctl() \
  __sanitizer_syscall_pre_impl_compat_14_shmctl()
#define __sanitizer_syscall_post_compat_14_shmctl() \
  __sanitizer_syscall_post_impl_compat_14_shmctl()
#define __sanitizer_syscall_pre_shmdt() \
  __sanitizer_syscall_pre_impl_shmdt()
#define __sanitizer_syscall_post_shmdt() \
  __sanitizer_syscall_post_impl_shmdt()
#define __sanitizer_syscall_pre_shmget() \
  __sanitizer_syscall_pre_impl_shmget()
#define __sanitizer_syscall_post_shmget() \
  __sanitizer_syscall_post_impl_shmget()
#define __sanitizer_syscall_pre_compat_50_clock_gettime() \
  __sanitizer_syscall_pre_impl_compat_50_clock_gettime()
#define __sanitizer_syscall_post_compat_50_clock_gettime() \
  __sanitizer_syscall_post_impl_compat_50_clock_gettime()
#define __sanitizer_syscall_pre_compat_50_clock_settime() \
  __sanitizer_syscall_pre_impl_compat_50_clock_settime()
#define __sanitizer_syscall_post_compat_50_clock_settime() \
  __sanitizer_syscall_post_impl_compat_50_clock_settime()
#define __sanitizer_syscall_pre_compat_50_clock_getres() \
  __sanitizer_syscall_pre_impl_compat_50_clock_getres()
#define __sanitizer_syscall_post_compat_50_clock_getres() \
  __sanitizer_syscall_post_impl_compat_50_clock_getres()
#define __sanitizer_syscall_pre_timer_create() \
  __sanitizer_syscall_pre_impl_timer_create()
#define __sanitizer_syscall_post_timer_create() \
  __sanitizer_syscall_post_impl_timer_create()
#define __sanitizer_syscall_pre_timer_delete() \
  __sanitizer_syscall_pre_impl_timer_delete()
#define __sanitizer_syscall_post_timer_delete() \
  __sanitizer_syscall_post_impl_timer_delete()
#define __sanitizer_syscall_pre_compat_50_timer_settime() \
  __sanitizer_syscall_pre_impl_compat_50_timer_settime()
#define __sanitizer_syscall_post_compat_50_timer_settime() \
  __sanitizer_syscall_post_impl_compat_50_timer_settime()
#define __sanitizer_syscall_pre_compat_50_timer_gettime() \
  __sanitizer_syscall_pre_impl_compat_50_timer_gettime()
#define __sanitizer_syscall_post_compat_50_timer_gettime() \
  __sanitizer_syscall_post_impl_compat_50_timer_gettime()
#define __sanitizer_syscall_pre_timer_getoverrun() \
  __sanitizer_syscall_pre_impl_timer_getoverrun()
#define __sanitizer_syscall_post_timer_getoverrun() \
  __sanitizer_syscall_post_impl_timer_getoverrun()
#define __sanitizer_syscall_pre_compat_50_nanosleep() \
  __sanitizer_syscall_pre_impl_compat_50_nanosleep()
#define __sanitizer_syscall_post_compat_50_nanosleep() \
  __sanitizer_syscall_post_impl_compat_50_nanosleep()
#define __sanitizer_syscall_pre_fdatasync() \
  __sanitizer_syscall_pre_impl_fdatasync()
#define __sanitizer_syscall_post_fdatasync() \
  __sanitizer_syscall_post_impl_fdatasync()
#define __sanitizer_syscall_pre_mlockall() \
  __sanitizer_syscall_pre_impl_mlockall()
#define __sanitizer_syscall_post_mlockall() \
  __sanitizer_syscall_post_impl_mlockall()
#define __sanitizer_syscall_pre_munlockall() \
  __sanitizer_syscall_pre_impl_munlockall()
#define __sanitizer_syscall_post_munlockall() \
  __sanitizer_syscall_post_impl_munlockall()
#define __sanitizer_syscall_pre_compat_50___sigtimedwait() \
  __sanitizer_syscall_pre_impl_compat_50___sigtimedwait()
#define __sanitizer_syscall_post_compat_50___sigtimedwait() \
  __sanitizer_syscall_post_impl_compat_50___sigtimedwait()
#define __sanitizer_syscall_pre_sigqueueinfo() \
  __sanitizer_syscall_pre_impl_sigqueueinfo()
#define __sanitizer_syscall_post_sigqueueinfo() \
  __sanitizer_syscall_post_impl_sigqueueinfo()
#define __sanitizer_syscall_pre_modctl() \
  __sanitizer_syscall_pre_impl_modctl()
#define __sanitizer_syscall_post_modctl() \
  __sanitizer_syscall_post_impl_modctl()
#define __sanitizer_syscall_pre__ksem_init() \
  __sanitizer_syscall_pre_impl__ksem_init()
#define __sanitizer_syscall_post__ksem_init() \
  __sanitizer_syscall_post_impl__ksem_init()
#define __sanitizer_syscall_pre__ksem_open() \
  __sanitizer_syscall_pre_impl__ksem_open()
#define __sanitizer_syscall_post__ksem_open() \
  __sanitizer_syscall_post_impl__ksem_open()
#define __sanitizer_syscall_pre__ksem_unlink() \
  __sanitizer_syscall_pre_impl__ksem_unlink()
#define __sanitizer_syscall_post__ksem_unlink() \
  __sanitizer_syscall_post_impl__ksem_unlink()
#define __sanitizer_syscall_pre__ksem_close() \
  __sanitizer_syscall_pre_impl__ksem_close()
#define __sanitizer_syscall_post__ksem_close() \
  __sanitizer_syscall_post_impl__ksem_close()
#define __sanitizer_syscall_pre__ksem_post() \
  __sanitizer_syscall_pre_impl__ksem_post()
#define __sanitizer_syscall_post__ksem_post() \
  __sanitizer_syscall_post_impl__ksem_post()
#define __sanitizer_syscall_pre__ksem_wait() \
  __sanitizer_syscall_pre_impl__ksem_wait()
#define __sanitizer_syscall_post__ksem_wait() \
  __sanitizer_syscall_post_impl__ksem_wait()
#define __sanitizer_syscall_pre__ksem_trywait() \
  __sanitizer_syscall_pre_impl__ksem_trywait()
#define __sanitizer_syscall_post__ksem_trywait() \
  __sanitizer_syscall_post_impl__ksem_trywait()
#define __sanitizer_syscall_pre__ksem_getvalue() \
  __sanitizer_syscall_pre_impl__ksem_getvalue()
#define __sanitizer_syscall_post__ksem_getvalue() \
  __sanitizer_syscall_post_impl__ksem_getvalue()
#define __sanitizer_syscall_pre__ksem_destroy() \
  __sanitizer_syscall_pre_impl__ksem_destroy()
#define __sanitizer_syscall_post__ksem_destroy() \
  __sanitizer_syscall_post_impl__ksem_destroy()
#define __sanitizer_syscall_pre__ksem_timedwait() \
  __sanitizer_syscall_pre_impl__ksem_timedwait()
#define __sanitizer_syscall_post__ksem_timedwait() \
  __sanitizer_syscall_post_impl__ksem_timedwait()
#define __sanitizer_syscall_pre_mq_open() \
  __sanitizer_syscall_pre_impl_mq_open()
#define __sanitizer_syscall_post_mq_open() \
  __sanitizer_syscall_post_impl_mq_open()
#define __sanitizer_syscall_pre_mq_close() \
  __sanitizer_syscall_pre_impl_mq_close()
#define __sanitizer_syscall_post_mq_close() \
  __sanitizer_syscall_post_impl_mq_close()
#define __sanitizer_syscall_pre_mq_unlink() \
  __sanitizer_syscall_pre_impl_mq_unlink()
#define __sanitizer_syscall_post_mq_unlink() \
  __sanitizer_syscall_post_impl_mq_unlink()
#define __sanitizer_syscall_pre_mq_getattr() \
  __sanitizer_syscall_pre_impl_mq_getattr()
#define __sanitizer_syscall_post_mq_getattr() \
  __sanitizer_syscall_post_impl_mq_getattr()
#define __sanitizer_syscall_pre_mq_setattr() \
  __sanitizer_syscall_pre_impl_mq_setattr()
#define __sanitizer_syscall_post_mq_setattr() \
  __sanitizer_syscall_post_impl_mq_setattr()
#define __sanitizer_syscall_pre_mq_notify() \
  __sanitizer_syscall_pre_impl_mq_notify()
#define __sanitizer_syscall_post_mq_notify() \
  __sanitizer_syscall_post_impl_mq_notify()
#define __sanitizer_syscall_pre_mq_send() \
  __sanitizer_syscall_pre_impl_mq_send()
#define __sanitizer_syscall_post_mq_send() \
  __sanitizer_syscall_post_impl_mq_send()
#define __sanitizer_syscall_pre_mq_receive() \
  __sanitizer_syscall_pre_impl_mq_receive()
#define __sanitizer_syscall_post_mq_receive() \
  __sanitizer_syscall_post_impl_mq_receive()
#define __sanitizer_syscall_pre_compat_50_mq_timedsend() \
  __sanitizer_syscall_pre_impl_compat_50_mq_timedsend()
#define __sanitizer_syscall_post_compat_50_mq_timedsend() \
  __sanitizer_syscall_post_impl_compat_50_mq_timedsend()
#define __sanitizer_syscall_pre_compat_50_mq_timedreceive() \
  __sanitizer_syscall_pre_impl_compat_50_mq_timedreceive()
#define __sanitizer_syscall_post_compat_50_mq_timedreceive() \
  __sanitizer_syscall_post_impl_compat_50_mq_timedreceive()
/* syscall 267 has been skipped */
/* syscall 268 has been skipped */
/* syscall 269 has been skipped */
#define __sanitizer_syscall_pre___posix_rename() \
  __sanitizer_syscall_pre_impl___posix_rename()
#define __sanitizer_syscall_post___posix_rename() \
  __sanitizer_syscall_post_impl___posix_rename()
#define __sanitizer_syscall_pre_swapctl() \
  __sanitizer_syscall_pre_impl_swapctl()
#define __sanitizer_syscall_post_swapctl() \
  __sanitizer_syscall_post_impl_swapctl()
#define __sanitizer_syscall_pre_compat_30_getdents() \
  __sanitizer_syscall_pre_impl_compat_30_getdents()
#define __sanitizer_syscall_post_compat_30_getdents() \
  __sanitizer_syscall_post_impl_compat_30_getdents()
#define __sanitizer_syscall_pre_minherit() \
  __sanitizer_syscall_pre_impl_minherit()
#define __sanitizer_syscall_post_minherit() \
  __sanitizer_syscall_post_impl_minherit()
#define __sanitizer_syscall_pre_lchmod() \
  __sanitizer_syscall_pre_impl_lchmod()
#define __sanitizer_syscall_post_lchmod() \
  __sanitizer_syscall_post_impl_lchmod()
#define __sanitizer_syscall_pre_lchown() \
  __sanitizer_syscall_pre_impl_lchown()
#define __sanitizer_syscall_post_lchown() \
  __sanitizer_syscall_post_impl_lchown()
#define __sanitizer_syscall_pre_compat_50_lutimes() \
  __sanitizer_syscall_pre_impl_compat_50_lutimes()
#define __sanitizer_syscall_post_compat_50_lutimes() \
  __sanitizer_syscall_post_impl_compat_50_lutimes()
#define __sanitizer_syscall_pre___msync13() \
  __sanitizer_syscall_pre_impl___msync13()
#define __sanitizer_syscall_post___msync13() \
  __sanitizer_syscall_post_impl___msync13()
#define __sanitizer_syscall_pre_compat_30___stat13() \
  __sanitizer_syscall_pre_impl_compat_30___stat13()
#define __sanitizer_syscall_post_compat_30___stat13() \
  __sanitizer_syscall_post_impl_compat_30___stat13()
#define __sanitizer_syscall_pre_compat_30___fstat13() \
  __sanitizer_syscall_pre_impl_compat_30___fstat13()
#define __sanitizer_syscall_post_compat_30___fstat13() \
  __sanitizer_syscall_post_impl_compat_30___fstat13()
#define __sanitizer_syscall_pre_compat_30___lstat13() \
  __sanitizer_syscall_pre_impl_compat_30___lstat13()
#define __sanitizer_syscall_post_compat_30___lstat13() \
  __sanitizer_syscall_post_impl_compat_30___lstat13()
#define __sanitizer_syscall_pre___sigaltstack14() \
  __sanitizer_syscall_pre_impl___sigaltstack14()
#define __sanitizer_syscall_post___sigaltstack14() \
  __sanitizer_syscall_post_impl___sigaltstack14()
#define __sanitizer_syscall_pre___vfork14() \
  __sanitizer_syscall_pre_impl___vfork14()
#define __sanitizer_syscall_post___vfork14() \
  __sanitizer_syscall_post_impl___vfork14()
#define __sanitizer_syscall_pre___posix_chown() \
  __sanitizer_syscall_pre_impl___posix_chown()
#define __sanitizer_syscall_post___posix_chown() \
  __sanitizer_syscall_post_impl___posix_chown()
#define __sanitizer_syscall_pre___posix_fchown() \
  __sanitizer_syscall_pre_impl___posix_fchown()
#define __sanitizer_syscall_post___posix_fchown() \
  __sanitizer_syscall_post_impl___posix_fchown()
#define __sanitizer_syscall_pre___posix_lchown() \
  __sanitizer_syscall_pre_impl___posix_lchown()
#define __sanitizer_syscall_post___posix_lchown() \
  __sanitizer_syscall_post_impl___posix_lchown()
#define __sanitizer_syscall_pre_getsid() \
  __sanitizer_syscall_pre_impl_getsid()
#define __sanitizer_syscall_post_getsid() \
  __sanitizer_syscall_post_impl_getsid()
#define __sanitizer_syscall_pre___clone() \
  __sanitizer_syscall_pre_impl___clone()
#define __sanitizer_syscall_post___clone() \
  __sanitizer_syscall_post_impl___clone()
#define __sanitizer_syscall_pre_fktrace() \
  __sanitizer_syscall_pre_impl_fktrace()
#define __sanitizer_syscall_post_fktrace() \
  __sanitizer_syscall_post_impl_fktrace()
#define __sanitizer_syscall_pre_preadv() \
  __sanitizer_syscall_pre_impl_preadv()
#define __sanitizer_syscall_post_preadv() \
  __sanitizer_syscall_post_impl_preadv()
#define __sanitizer_syscall_pre_pwritev() \
  __sanitizer_syscall_pre_impl_pwritev()
#define __sanitizer_syscall_post_pwritev() \
  __sanitizer_syscall_post_impl_pwritev()
#define __sanitizer_syscall_pre_compat_16___sigaction14() \
  __sanitizer_syscall_pre_impl_compat_16___sigaction14()
#define __sanitizer_syscall_post_compat_16___sigaction14() \
  __sanitizer_syscall_post_impl_compat_16___sigaction14()
#define __sanitizer_syscall_pre___sigpending14() \
  __sanitizer_syscall_pre_impl___sigpending14()
#define __sanitizer_syscall_post___sigpending14() \
  __sanitizer_syscall_post_impl___sigpending14()
#define __sanitizer_syscall_pre___sigprocmask14() \
  __sanitizer_syscall_pre_impl___sigprocmask14()
#define __sanitizer_syscall_post___sigprocmask14() \
  __sanitizer_syscall_post_impl___sigprocmask14()
#define __sanitizer_syscall_pre___sigsuspend14() \
  __sanitizer_syscall_pre_impl___sigsuspend14()
#define __sanitizer_syscall_post___sigsuspend14() \
  __sanitizer_syscall_post_impl___sigsuspend14()
#define __sanitizer_syscall_pre_compat_16___sigreturn14() \
  __sanitizer_syscall_pre_impl_compat_16___sigreturn14()
#define __sanitizer_syscall_post_compat_16___sigreturn14() \
  __sanitizer_syscall_post_impl_compat_16___sigreturn14()
#define __sanitizer_syscall_pre___getcwd() \
  __sanitizer_syscall_pre_impl___getcwd()
#define __sanitizer_syscall_post___getcwd() \
  __sanitizer_syscall_post_impl___getcwd()
#define __sanitizer_syscall_pre_fchroot() \
  __sanitizer_syscall_pre_impl_fchroot()
#define __sanitizer_syscall_post_fchroot() \
  __sanitizer_syscall_post_impl_fchroot()
#define __sanitizer_syscall_pre_compat_30_fhopen() \
  __sanitizer_syscall_pre_impl_compat_30_fhopen()
#define __sanitizer_syscall_post_compat_30_fhopen() \
  __sanitizer_syscall_post_impl_compat_30_fhopen()
#define __sanitizer_syscall_pre_compat_30_fhstat() \
  __sanitizer_syscall_pre_impl_compat_30_fhstat()
#define __sanitizer_syscall_post_compat_30_fhstat() \
  __sanitizer_syscall_post_impl_compat_30_fhstat()
#define __sanitizer_syscall_pre_compat_20_fhstatfs() \
  __sanitizer_syscall_pre_impl_compat_20_fhstatfs()
#define __sanitizer_syscall_post_compat_20_fhstatfs() \
  __sanitizer_syscall_post_impl_compat_20_fhstatfs()
#define __sanitizer_syscall_pre_compat_50_____semctl13() \
  __sanitizer_syscall_pre_impl_compat_50_____semctl13()
#define __sanitizer_syscall_post_compat_50_____semctl13() \
  __sanitizer_syscall_post_impl_compat_50_____semctl13()
#define __sanitizer_syscall_pre_compat_50___msgctl13() \
  __sanitizer_syscall_pre_impl_compat_50___msgctl13()
#define __sanitizer_syscall_post_compat_50___msgctl13() \
  __sanitizer_syscall_post_impl_compat_50___msgctl13()
#define __sanitizer_syscall_pre_compat_50___shmctl13() \
  __sanitizer_syscall_pre_impl_compat_50___shmctl13()
#define __sanitizer_syscall_post_compat_50___shmctl13() \
  __sanitizer_syscall_post_impl_compat_50___shmctl13()
#define __sanitizer_syscall_pre_lchflags() \
  __sanitizer_syscall_pre_impl_lchflags()
#define __sanitizer_syscall_post_lchflags() \
  __sanitizer_syscall_post_impl_lchflags()
#define __sanitizer_syscall_pre_issetugid() \
  __sanitizer_syscall_pre_impl_issetugid()
#define __sanitizer_syscall_post_issetugid() \
  __sanitizer_syscall_post_impl_issetugid()
#define __sanitizer_syscall_pre_utrace() \
  __sanitizer_syscall_pre_impl_utrace()
#define __sanitizer_syscall_post_utrace() \
  __sanitizer_syscall_post_impl_utrace()
#define __sanitizer_syscall_pre_getcontext() \
  __sanitizer_syscall_pre_impl_getcontext()
#define __sanitizer_syscall_post_getcontext() \
  __sanitizer_syscall_post_impl_getcontext()
#define __sanitizer_syscall_pre_setcontext() \
  __sanitizer_syscall_pre_impl_setcontext()
#define __sanitizer_syscall_post_setcontext() \
  __sanitizer_syscall_post_impl_setcontext()
#define __sanitizer_syscall_pre__lwp_create() \
  __sanitizer_syscall_pre_impl__lwp_create()
#define __sanitizer_syscall_post__lwp_create() \
  __sanitizer_syscall_post_impl__lwp_create()
#define __sanitizer_syscall_pre__lwp_exit() \
  __sanitizer_syscall_pre_impl__lwp_exit()
#define __sanitizer_syscall_post__lwp_exit() \
  __sanitizer_syscall_post_impl__lwp_exit()
#define __sanitizer_syscall_pre__lwp_self() \
  __sanitizer_syscall_pre_impl__lwp_self()
#define __sanitizer_syscall_post__lwp_self() \
  __sanitizer_syscall_post_impl__lwp_self()
#define __sanitizer_syscall_pre__lwp_wait() \
  __sanitizer_syscall_pre_impl__lwp_wait()
#define __sanitizer_syscall_post__lwp_wait() \
  __sanitizer_syscall_post_impl__lwp_wait()
#define __sanitizer_syscall_pre__lwp_suspend() \
  __sanitizer_syscall_pre_impl__lwp_suspend()
#define __sanitizer_syscall_post__lwp_suspend() \
  __sanitizer_syscall_post_impl__lwp_suspend()
#define __sanitizer_syscall_pre__lwp_continue() \
  __sanitizer_syscall_pre_impl__lwp_continue()
#define __sanitizer_syscall_post__lwp_continue() \
  __sanitizer_syscall_post_impl__lwp_continue()
#define __sanitizer_syscall_pre__lwp_wakeup() \
  __sanitizer_syscall_pre_impl__lwp_wakeup()
#define __sanitizer_syscall_post__lwp_wakeup() \
  __sanitizer_syscall_post_impl__lwp_wakeup()
#define __sanitizer_syscall_pre__lwp_getprivate() \
  __sanitizer_syscall_pre_impl__lwp_getprivate()
#define __sanitizer_syscall_post__lwp_getprivate() \
  __sanitizer_syscall_post_impl__lwp_getprivate()
#define __sanitizer_syscall_pre__lwp_setprivate() \
  __sanitizer_syscall_pre_impl__lwp_setprivate()
#define __sanitizer_syscall_post__lwp_setprivate() \
  __sanitizer_syscall_post_impl__lwp_setprivate()
#define __sanitizer_syscall_pre__lwp_kill() \
  __sanitizer_syscall_pre_impl__lwp_kill()
#define __sanitizer_syscall_post__lwp_kill() \
  __sanitizer_syscall_post_impl__lwp_kill()
#define __sanitizer_syscall_pre__lwp_detach() \
  __sanitizer_syscall_pre_impl__lwp_detach()
#define __sanitizer_syscall_post__lwp_detach() \
  __sanitizer_syscall_post_impl__lwp_detach()
#define __sanitizer_syscall_pre_compat_50__lwp_park() \
  __sanitizer_syscall_pre_impl_compat_50__lwp_park()
#define __sanitizer_syscall_post_compat_50__lwp_park() \
  __sanitizer_syscall_post_impl_compat_50__lwp_park()
#define __sanitizer_syscall_pre__lwp_unpark() \
  __sanitizer_syscall_pre_impl__lwp_unpark()
#define __sanitizer_syscall_post__lwp_unpark() \
  __sanitizer_syscall_post_impl__lwp_unpark()
#define __sanitizer_syscall_pre__lwp_unpark_all() \
  __sanitizer_syscall_pre_impl__lwp_unpark_all()
#define __sanitizer_syscall_post__lwp_unpark_all() \
  __sanitizer_syscall_post_impl__lwp_unpark_all()
#define __sanitizer_syscall_pre__lwp_setname() \
  __sanitizer_syscall_pre_impl__lwp_setname()
#define __sanitizer_syscall_post__lwp_setname() \
  __sanitizer_syscall_post_impl__lwp_setname()
#define __sanitizer_syscall_pre__lwp_getname() \
  __sanitizer_syscall_pre_impl__lwp_getname()
#define __sanitizer_syscall_post__lwp_getname() \
  __sanitizer_syscall_post_impl__lwp_getname()
#define __sanitizer_syscall_pre__lwp_ctl() \
  __sanitizer_syscall_pre_impl__lwp_ctl()
#define __sanitizer_syscall_post__lwp_ctl() \
  __sanitizer_syscall_post_impl__lwp_ctl()
/* syscall 326 has been skipped */
/* syscall 327 has been skipped */
/* syscall 328 has been skipped */
/* syscall 329 has been skipped */
#define __sanitizer_syscall_pre_compat_60_sa_register() \
  __sanitizer_syscall_pre_impl_compat_60_sa_register()
#define __sanitizer_syscall_post_compat_60_sa_register() \
  __sanitizer_syscall_post_impl_compat_60_sa_register()
#define __sanitizer_syscall_pre_compat_60_sa_stacks() \
  __sanitizer_syscall_pre_impl_compat_60_sa_stacks()
#define __sanitizer_syscall_post_compat_60_sa_stacks() \
  __sanitizer_syscall_post_impl_compat_60_sa_stacks()
#define __sanitizer_syscall_pre_compat_60_sa_enable() \
  __sanitizer_syscall_pre_impl_compat_60_sa_enable()
#define __sanitizer_syscall_post_compat_60_sa_enable() \
  __sanitizer_syscall_post_impl_compat_60_sa_enable()
#define __sanitizer_syscall_pre_compat_60_sa_setconcurrency() \
  __sanitizer_syscall_pre_impl_compat_60_sa_setconcurrency()
#define __sanitizer_syscall_post_compat_60_sa_setconcurrency() \
  __sanitizer_syscall_post_impl_compat_60_sa_setconcurrency()
#define __sanitizer_syscall_pre_compat_60_sa_yield() \
  __sanitizer_syscall_pre_impl_compat_60_sa_yield()
#define __sanitizer_syscall_post_compat_60_sa_yield() \
  __sanitizer_syscall_post_impl_compat_60_sa_yield()
#define __sanitizer_syscall_pre_compat_60_sa_preempt() \
  __sanitizer_syscall_pre_impl_compat_60_sa_preempt()
#define __sanitizer_syscall_post_compat_60_sa_preempt() \
  __sanitizer_syscall_post_impl_compat_60_sa_preempt()
/* syscall 336 has been skipped */
/* syscall 337 has been skipped */
/* syscall 338 has been skipped */
/* syscall 339 has been skipped */
#define __sanitizer_syscall_pre___sigaction_sigtramp() \
  __sanitizer_syscall_pre_impl___sigaction_sigtramp()
#define __sanitizer_syscall_post___sigaction_sigtramp() \
  __sanitizer_syscall_post_impl___sigaction_sigtramp()
#define __sanitizer_syscall_pre_pmc_get_info() \
  __sanitizer_syscall_pre_impl_pmc_get_info()
#define __sanitizer_syscall_post_pmc_get_info() \
  __sanitizer_syscall_post_impl_pmc_get_info()
#define __sanitizer_syscall_pre_pmc_control() \
  __sanitizer_syscall_pre_impl_pmc_control()
#define __sanitizer_syscall_post_pmc_control() \
  __sanitizer_syscall_post_impl_pmc_control()
#define __sanitizer_syscall_pre_rasctl() \
  __sanitizer_syscall_pre_impl_rasctl()
#define __sanitizer_syscall_post_rasctl() \
  __sanitizer_syscall_post_impl_rasctl()
#define __sanitizer_syscall_pre_kqueue() \
  __sanitizer_syscall_pre_impl_kqueue()
#define __sanitizer_syscall_post_kqueue() \
  __sanitizer_syscall_post_impl_kqueue()
#define __sanitizer_syscall_pre_compat_50_kevent() \
  __sanitizer_syscall_pre_impl_compat_50_kevent()
#define __sanitizer_syscall_post_compat_50_kevent() \
  __sanitizer_syscall_post_impl_compat_50_kevent()
#define __sanitizer_syscall_pre__sched_setparam() \
  __sanitizer_syscall_pre_impl__sched_setparam()
#define __sanitizer_syscall_post__sched_setparam() \
  __sanitizer_syscall_post_impl__sched_setparam()
#define __sanitizer_syscall_pre__sched_getparam() \
  __sanitizer_syscall_pre_impl__sched_getparam()
#define __sanitizer_syscall_post__sched_getparam() \
  __sanitizer_syscall_post_impl__sched_getparam()
#define __sanitizer_syscall_pre__sched_setaffinity() \
  __sanitizer_syscall_pre_impl__sched_setaffinity()
#define __sanitizer_syscall_post__sched_setaffinity() \
  __sanitizer_syscall_post_impl__sched_setaffinity()
#define __sanitizer_syscall_pre__sched_getaffinity() \
  __sanitizer_syscall_pre_impl__sched_getaffinity()
#define __sanitizer_syscall_post__sched_getaffinity() \
  __sanitizer_syscall_post_impl__sched_getaffinity()
#define __sanitizer_syscall_pre_sched_yield() \
  __sanitizer_syscall_pre_impl_sched_yield()
#define __sanitizer_syscall_post_sched_yield() \
  __sanitizer_syscall_post_impl_sched_yield()
#define __sanitizer_syscall_pre__sched_protect() \
  __sanitizer_syscall_pre_impl__sched_protect()
#define __sanitizer_syscall_post__sched_protect() \
  __sanitizer_syscall_post_impl__sched_protect()
/* syscall 352 has been skipped */
/* syscall 353 has been skipped */
#define __sanitizer_syscall_pre_fsync_range() \
  __sanitizer_syscall_pre_impl_fsync_range()
#define __sanitizer_syscall_post_fsync_range() \
  __sanitizer_syscall_post_impl_fsync_range()
#define __sanitizer_syscall_pre_uuidgen() \
  __sanitizer_syscall_pre_impl_uuidgen()
#define __sanitizer_syscall_post_uuidgen() \
  __sanitizer_syscall_post_impl_uuidgen()
#define __sanitizer_syscall_pre_getvfsstat() \
  __sanitizer_syscall_pre_impl_getvfsstat()
#define __sanitizer_syscall_post_getvfsstat() \
  __sanitizer_syscall_post_impl_getvfsstat()
#define __sanitizer_syscall_pre_statvfs1() \
  __sanitizer_syscall_pre_impl_statvfs1()
#define __sanitizer_syscall_post_statvfs1() \
  __sanitizer_syscall_post_impl_statvfs1()
#define __sanitizer_syscall_pre_fstatvfs1() \
  __sanitizer_syscall_pre_impl_fstatvfs1()
#define __sanitizer_syscall_post_fstatvfs1() \
  __sanitizer_syscall_post_impl_fstatvfs1()
#define __sanitizer_syscall_pre_compat_30_fhstatvfs1() \
  __sanitizer_syscall_pre_impl_compat_30_fhstatvfs1()
#define __sanitizer_syscall_post_compat_30_fhstatvfs1() \
  __sanitizer_syscall_post_impl_compat_30_fhstatvfs1()
#define __sanitizer_syscall_pre_extattrctl() \
  __sanitizer_syscall_pre_impl_extattrctl()
#define __sanitizer_syscall_post_extattrctl() \
  __sanitizer_syscall_post_impl_extattrctl()
#define __sanitizer_syscall_pre_extattr_set_file() \
  __sanitizer_syscall_pre_impl_extattr_set_file()
#define __sanitizer_syscall_post_extattr_set_file() \
  __sanitizer_syscall_post_impl_extattr_set_file()
#define __sanitizer_syscall_pre_extattr_get_file() \
  __sanitizer_syscall_pre_impl_extattr_get_file()
#define __sanitizer_syscall_post_extattr_get_file() \
  __sanitizer_syscall_post_impl_extattr_get_file()
#define __sanitizer_syscall_pre_extattr_delete_file() \
  __sanitizer_syscall_pre_impl_extattr_delete_file()
#define __sanitizer_syscall_post_extattr_delete_file() \
  __sanitizer_syscall_post_impl_extattr_delete_file()
#define __sanitizer_syscall_pre_extattr_set_fd() \
  __sanitizer_syscall_pre_impl_extattr_set_fd()
#define __sanitizer_syscall_post_extattr_set_fd() \
  __sanitizer_syscall_post_impl_extattr_set_fd()
#define __sanitizer_syscall_pre_extattr_get_fd() \
  __sanitizer_syscall_pre_impl_extattr_get_fd()
#define __sanitizer_syscall_post_extattr_get_fd() \
  __sanitizer_syscall_post_impl_extattr_get_fd()
#define __sanitizer_syscall_pre_extattr_delete_fd() \
  __sanitizer_syscall_pre_impl_extattr_delete_fd()
#define __sanitizer_syscall_post_extattr_delete_fd() \
  __sanitizer_syscall_post_impl_extattr_delete_fd()
#define __sanitizer_syscall_pre_extattr_set_link() \
  __sanitizer_syscall_pre_impl_extattr_set_link()
#define __sanitizer_syscall_post_extattr_set_link() \
  __sanitizer_syscall_post_impl_extattr_set_link()
#define __sanitizer_syscall_pre_extattr_get_link() \
  __sanitizer_syscall_pre_impl_extattr_get_link()
#define __sanitizer_syscall_post_extattr_get_link() \
  __sanitizer_syscall_post_impl_extattr_get_link()
#define __sanitizer_syscall_pre_extattr_delete_link() \
  __sanitizer_syscall_pre_impl_extattr_delete_link()
#define __sanitizer_syscall_post_extattr_delete_link() \
  __sanitizer_syscall_post_impl_extattr_delete_link()
#define __sanitizer_syscall_pre_extattr_list_fd() \
  __sanitizer_syscall_pre_impl_extattr_list_fd()
#define __sanitizer_syscall_post_extattr_list_fd() \
  __sanitizer_syscall_post_impl_extattr_list_fd()
#define __sanitizer_syscall_pre_extattr_list_file() \
  __sanitizer_syscall_pre_impl_extattr_list_file()
#define __sanitizer_syscall_post_extattr_list_file() \
  __sanitizer_syscall_post_impl_extattr_list_file()
#define __sanitizer_syscall_pre_extattr_list_link() \
  __sanitizer_syscall_pre_impl_extattr_list_link()
#define __sanitizer_syscall_post_extattr_list_link() \
  __sanitizer_syscall_post_impl_extattr_list_link()
#define __sanitizer_syscall_pre_compat_50_pselect() \
  __sanitizer_syscall_pre_impl_compat_50_pselect()
#define __sanitizer_syscall_post_compat_50_pselect() \
  __sanitizer_syscall_post_impl_compat_50_pselect()
#define __sanitizer_syscall_pre_compat_50_pollts() \
  __sanitizer_syscall_pre_impl_compat_50_pollts()
#define __sanitizer_syscall_post_compat_50_pollts() \
  __sanitizer_syscall_post_impl_compat_50_pollts()
#define __sanitizer_syscall_pre_setxattr() \
  __sanitizer_syscall_pre_impl_setxattr()
#define __sanitizer_syscall_post_setxattr() \
  __sanitizer_syscall_post_impl_setxattr()
#define __sanitizer_syscall_pre_lsetxattr() \
  __sanitizer_syscall_pre_impl_lsetxattr()
#define __sanitizer_syscall_post_lsetxattr() \
  __sanitizer_syscall_post_impl_lsetxattr()
#define __sanitizer_syscall_pre_fsetxattr() \
  __sanitizer_syscall_pre_impl_fsetxattr()
#define __sanitizer_syscall_post_fsetxattr() \
  __sanitizer_syscall_post_impl_fsetxattr()
#define __sanitizer_syscall_pre_getxattr() \
  __sanitizer_syscall_pre_impl_getxattr()
#define __sanitizer_syscall_post_getxattr() \
  __sanitizer_syscall_post_impl_getxattr()
#define __sanitizer_syscall_pre_lgetxattr() \
  __sanitizer_syscall_pre_impl_lgetxattr()
#define __sanitizer_syscall_post_lgetxattr() \
  __sanitizer_syscall_post_impl_lgetxattr()
#define __sanitizer_syscall_pre_fgetxattr() \
  __sanitizer_syscall_pre_impl_fgetxattr()
#define __sanitizer_syscall_post_fgetxattr() \
  __sanitizer_syscall_post_impl_fgetxattr()
#define __sanitizer_syscall_pre_listxattr() \
  __sanitizer_syscall_pre_impl_listxattr()
#define __sanitizer_syscall_post_listxattr() \
  __sanitizer_syscall_post_impl_listxattr()
#define __sanitizer_syscall_pre_llistxattr() \
  __sanitizer_syscall_pre_impl_llistxattr()
#define __sanitizer_syscall_post_llistxattr() \
  __sanitizer_syscall_post_impl_llistxattr()
#define __sanitizer_syscall_pre_flistxattr() \
  __sanitizer_syscall_pre_impl_flistxattr()
#define __sanitizer_syscall_post_flistxattr() \
  __sanitizer_syscall_post_impl_flistxattr()
#define __sanitizer_syscall_pre_removexattr() \
  __sanitizer_syscall_pre_impl_removexattr()
#define __sanitizer_syscall_post_removexattr() \
  __sanitizer_syscall_post_impl_removexattr()
#define __sanitizer_syscall_pre_lremovexattr() \
  __sanitizer_syscall_pre_impl_lremovexattr()
#define __sanitizer_syscall_post_lremovexattr() \
  __sanitizer_syscall_post_impl_lremovexattr()
#define __sanitizer_syscall_pre_fremovexattr() \
  __sanitizer_syscall_pre_impl_fremovexattr()
#define __sanitizer_syscall_post_fremovexattr() \
  __sanitizer_syscall_post_impl_fremovexattr()
#define __sanitizer_syscall_pre_compat_50___stat30() \
  __sanitizer_syscall_pre_impl_compat_50___stat30()
#define __sanitizer_syscall_post_compat_50___stat30() \
  __sanitizer_syscall_post_impl_compat_50___stat30()
#define __sanitizer_syscall_pre_compat_50___fstat30() \
  __sanitizer_syscall_pre_impl_compat_50___fstat30()
#define __sanitizer_syscall_post_compat_50___fstat30() \
  __sanitizer_syscall_post_impl_compat_50___fstat30()
#define __sanitizer_syscall_pre_compat_50___lstat30() \
  __sanitizer_syscall_pre_impl_compat_50___lstat30()
#define __sanitizer_syscall_post_compat_50___lstat30() \
  __sanitizer_syscall_post_impl_compat_50___lstat30()
#define __sanitizer_syscall_pre___getdents30() \
  __sanitizer_syscall_pre_impl___getdents30()
#define __sanitizer_syscall_post___getdents30() \
  __sanitizer_syscall_post_impl___getdents30()
#define __sanitizer_syscall_pre_posix_fadvise() \
  __sanitizer_syscall_pre_impl_posix_fadvise()
#define __sanitizer_syscall_post_posix_fadvise() \
  __sanitizer_syscall_post_impl_posix_fadvise()
#define __sanitizer_syscall_pre_compat_30___fhstat30() \
  __sanitizer_syscall_pre_impl_compat_30___fhstat30()
#define __sanitizer_syscall_post_compat_30___fhstat30() \
  __sanitizer_syscall_post_impl_compat_30___fhstat30()
#define __sanitizer_syscall_pre_compat_50___ntp_gettime30() \
  __sanitizer_syscall_pre_impl_compat_50___ntp_gettime30()
#define __sanitizer_syscall_post_compat_50___ntp_gettime30() \
  __sanitizer_syscall_post_impl_compat_50___ntp_gettime30()
#define __sanitizer_syscall_pre___socket30() \
  __sanitizer_syscall_pre_impl___socket30()
#define __sanitizer_syscall_post___socket30() \
  __sanitizer_syscall_post_impl___socket30()
#define __sanitizer_syscall_pre___getfh30() \
  __sanitizer_syscall_pre_impl___getfh30()
#define __sanitizer_syscall_post___getfh30() \
  __sanitizer_syscall_post_impl___getfh30()
#define __sanitizer_syscall_pre___fhopen40() \
  __sanitizer_syscall_pre_impl___fhopen40()
#define __sanitizer_syscall_post___fhopen40() \
  __sanitizer_syscall_post_impl___fhopen40()
#define __sanitizer_syscall_pre___fhstatvfs140() \
  __sanitizer_syscall_pre_impl___fhstatvfs140()
#define __sanitizer_syscall_post___fhstatvfs140() \
  __sanitizer_syscall_post_impl___fhstatvfs140()
#define __sanitizer_syscall_pre_compat_50___fhstat40() \
  __sanitizer_syscall_pre_impl_compat_50___fhstat40()
#define __sanitizer_syscall_post_compat_50___fhstat40() \
  __sanitizer_syscall_post_impl_compat_50___fhstat40()
#define __sanitizer_syscall_pre_aio_cancel() \
  __sanitizer_syscall_pre_impl_aio_cancel()
#define __sanitizer_syscall_post_aio_cancel() \
  __sanitizer_syscall_post_impl_aio_cancel()
#define __sanitizer_syscall_pre_aio_error() \
  __sanitizer_syscall_pre_impl_aio_error()
#define __sanitizer_syscall_post_aio_error() \
  __sanitizer_syscall_post_impl_aio_error()
#define __sanitizer_syscall_pre_aio_fsync() \
  __sanitizer_syscall_pre_impl_aio_fsync()
#define __sanitizer_syscall_post_aio_fsync() \
  __sanitizer_syscall_post_impl_aio_fsync()
#define __sanitizer_syscall_pre_aio_read() \
  __sanitizer_syscall_pre_impl_aio_read()
#define __sanitizer_syscall_post_aio_read() \
  __sanitizer_syscall_post_impl_aio_read()
#define __sanitizer_syscall_pre_aio_return() \
  __sanitizer_syscall_pre_impl_aio_return()
#define __sanitizer_syscall_post_aio_return() \
  __sanitizer_syscall_post_impl_aio_return()
#define __sanitizer_syscall_pre_compat_50_aio_suspend() \
  __sanitizer_syscall_pre_impl_compat_50_aio_suspend()
#define __sanitizer_syscall_post_compat_50_aio_suspend() \
  __sanitizer_syscall_post_impl_compat_50_aio_suspend()
#define __sanitizer_syscall_pre_aio_write() \
  __sanitizer_syscall_pre_impl_aio_write()
#define __sanitizer_syscall_post_aio_write() \
  __sanitizer_syscall_post_impl_aio_write()
#define __sanitizer_syscall_pre_lio_listio() \
  __sanitizer_syscall_pre_impl_lio_listio()
#define __sanitizer_syscall_post_lio_listio() \
  __sanitizer_syscall_post_impl_lio_listio()
/* syscall 407 has been skipped */
/* syscall 408 has been skipped */
/* syscall 409 has been skipped */
#define __sanitizer_syscall_pre___mount50() \
  __sanitizer_syscall_pre_impl___mount50()
#define __sanitizer_syscall_post___mount50() \
  __sanitizer_syscall_post_impl___mount50()
#define __sanitizer_syscall_pre_mremap() \
  __sanitizer_syscall_pre_impl_mremap()
#define __sanitizer_syscall_post_mremap() \
  __sanitizer_syscall_post_impl_mremap()
#define __sanitizer_syscall_pre_pset_create() \
  __sanitizer_syscall_pre_impl_pset_create()
#define __sanitizer_syscall_post_pset_create() \
  __sanitizer_syscall_post_impl_pset_create()
#define __sanitizer_syscall_pre_pset_destroy() \
  __sanitizer_syscall_pre_impl_pset_destroy()
#define __sanitizer_syscall_post_pset_destroy() \
  __sanitizer_syscall_post_impl_pset_destroy()
#define __sanitizer_syscall_pre_pset_assign() \
  __sanitizer_syscall_pre_impl_pset_assign()
#define __sanitizer_syscall_post_pset_assign() \
  __sanitizer_syscall_post_impl_pset_assign()
#define __sanitizer_syscall_pre__pset_bind() \
  __sanitizer_syscall_pre_impl__pset_bind()
#define __sanitizer_syscall_post__pset_bind() \
  __sanitizer_syscall_post_impl__pset_bind()
#define __sanitizer_syscall_pre___posix_fadvise50() \
  __sanitizer_syscall_pre_impl___posix_fadvise50()
#define __sanitizer_syscall_post___posix_fadvise50() \
  __sanitizer_syscall_post_impl___posix_fadvise50()
#define __sanitizer_syscall_pre___select50() \
  __sanitizer_syscall_pre_impl___select50()
#define __sanitizer_syscall_post___select50() \
  __sanitizer_syscall_post_impl___select50()
#define __sanitizer_syscall_pre___gettimeofday50() \
  __sanitizer_syscall_pre_impl___gettimeofday50()
#define __sanitizer_syscall_post___gettimeofday50() \
  __sanitizer_syscall_post_impl___gettimeofday50()
#define __sanitizer_syscall_pre___settimeofday50() \
  __sanitizer_syscall_pre_impl___settimeofday50()
#define __sanitizer_syscall_post___settimeofday50() \
  __sanitizer_syscall_post_impl___settimeofday50()
#define __sanitizer_syscall_pre___utimes50() \
  __sanitizer_syscall_pre_impl___utimes50()
#define __sanitizer_syscall_post___utimes50() \
  __sanitizer_syscall_post_impl___utimes50()
#define __sanitizer_syscall_pre___adjtime50() \
  __sanitizer_syscall_pre_impl___adjtime50()
#define __sanitizer_syscall_post___adjtime50() \
  __sanitizer_syscall_post_impl___adjtime50()
#define __sanitizer_syscall_pre___lfs_segwait50() \
  __sanitizer_syscall_pre_impl___lfs_segwait50()
#define __sanitizer_syscall_post___lfs_segwait50() \
  __sanitizer_syscall_post_impl___lfs_segwait50()
#define __sanitizer_syscall_pre___futimes50() \
  __sanitizer_syscall_pre_impl___futimes50()
#define __sanitizer_syscall_post___futimes50() \
  __sanitizer_syscall_post_impl___futimes50()
#define __sanitizer_syscall_pre___lutimes50() \
  __sanitizer_syscall_pre_impl___lutimes50()
#define __sanitizer_syscall_post___lutimes50() \
  __sanitizer_syscall_post_impl___lutimes50()
#define __sanitizer_syscall_pre___setitimer50() \
  __sanitizer_syscall_pre_impl___setitimer50()
#define __sanitizer_syscall_post___setitimer50() \
  __sanitizer_syscall_post_impl___setitimer50()
#define __sanitizer_syscall_pre___getitimer50() \
  __sanitizer_syscall_pre_impl___getitimer50()
#define __sanitizer_syscall_post___getitimer50() \
  __sanitizer_syscall_post_impl___getitimer50()
#define __sanitizer_syscall_pre___clock_gettime50() \
  __sanitizer_syscall_pre_impl___clock_gettime50()
#define __sanitizer_syscall_post___clock_gettime50() \
  __sanitizer_syscall_post_impl___clock_gettime50()
#define __sanitizer_syscall_pre___clock_settime50() \
  __sanitizer_syscall_pre_impl___clock_settime50()
#define __sanitizer_syscall_post___clock_settime50() \
  __sanitizer_syscall_post_impl___clock_settime50()
#define __sanitizer_syscall_pre___clock_getres50() \
  __sanitizer_syscall_pre_impl___clock_getres50()
#define __sanitizer_syscall_post___clock_getres50() \
  __sanitizer_syscall_post_impl___clock_getres50()
#define __sanitizer_syscall_pre___nanosleep50() \
  __sanitizer_syscall_pre_impl___nanosleep50()
#define __sanitizer_syscall_post___nanosleep50() \
  __sanitizer_syscall_post_impl___nanosleep50()
#define __sanitizer_syscall_pre_____sigtimedwait50() \
  __sanitizer_syscall_pre_impl_____sigtimedwait50()
#define __sanitizer_syscall_post_____sigtimedwait50() \
  __sanitizer_syscall_post_impl_____sigtimedwait50()
#define __sanitizer_syscall_pre___mq_timedsend50() \
  __sanitizer_syscall_pre_impl___mq_timedsend50()
#define __sanitizer_syscall_post___mq_timedsend50() \
  __sanitizer_syscall_post_impl___mq_timedsend50()
#define __sanitizer_syscall_pre___mq_timedreceive50() \
  __sanitizer_syscall_pre_impl___mq_timedreceive50()
#define __sanitizer_syscall_post___mq_timedreceive50() \
  __sanitizer_syscall_post_impl___mq_timedreceive50()
#define __sanitizer_syscall_pre_compat_60__lwp_park() \
  __sanitizer_syscall_pre_impl_compat_60__lwp_park()
#define __sanitizer_syscall_post_compat_60__lwp_park() \
  __sanitizer_syscall_post_impl_compat_60__lwp_park()
#define __sanitizer_syscall_pre___kevent50() \
  __sanitizer_syscall_pre_impl___kevent50()
#define __sanitizer_syscall_post___kevent50() \
  __sanitizer_syscall_post_impl___kevent50()
#define __sanitizer_syscall_pre___pselect50() \
  __sanitizer_syscall_pre_impl___pselect50()
#define __sanitizer_syscall_post___pselect50() \
  __sanitizer_syscall_post_impl___pselect50()
#define __sanitizer_syscall_pre___pollts50() \
  __sanitizer_syscall_pre_impl___pollts50()
#define __sanitizer_syscall_post___pollts50() \
  __sanitizer_syscall_post_impl___pollts50()
#define __sanitizer_syscall_pre___aio_suspend50() \
  __sanitizer_syscall_pre_impl___aio_suspend50()
#define __sanitizer_syscall_post___aio_suspend50() \
  __sanitizer_syscall_post_impl___aio_suspend50()
#define __sanitizer_syscall_pre___stat50() \
  __sanitizer_syscall_pre_impl___stat50()
#define __sanitizer_syscall_post___stat50() \
  __sanitizer_syscall_post_impl___stat50()
#define __sanitizer_syscall_pre___fstat50() \
  __sanitizer_syscall_pre_impl___fstat50()
#define __sanitizer_syscall_post___fstat50() \
  __sanitizer_syscall_post_impl___fstat50()
#define __sanitizer_syscall_pre___lstat50() \
  __sanitizer_syscall_pre_impl___lstat50()
#define __sanitizer_syscall_post___lstat50() \
  __sanitizer_syscall_post_impl___lstat50()
#define __sanitizer_syscall_pre_____semctl50() \
  __sanitizer_syscall_pre_impl_____semctl50()
#define __sanitizer_syscall_post_____semctl50() \
  __sanitizer_syscall_post_impl_____semctl50()
#define __sanitizer_syscall_pre___shmctl50() \
  __sanitizer_syscall_pre_impl___shmctl50()
#define __sanitizer_syscall_post___shmctl50() \
  __sanitizer_syscall_post_impl___shmctl50()
#define __sanitizer_syscall_pre___msgctl50() \
  __sanitizer_syscall_pre_impl___msgctl50()
#define __sanitizer_syscall_post___msgctl50() \
  __sanitizer_syscall_post_impl___msgctl50()
#define __sanitizer_syscall_pre___getrusage50() \
  __sanitizer_syscall_pre_impl___getrusage50()
#define __sanitizer_syscall_post___getrusage50() \
  __sanitizer_syscall_post_impl___getrusage50()
#define __sanitizer_syscall_pre___timer_settime50() \
  __sanitizer_syscall_pre_impl___timer_settime50()
#define __sanitizer_syscall_post___timer_settime50() \
  __sanitizer_syscall_post_impl___timer_settime50()
#define __sanitizer_syscall_pre___timer_gettime50() \
  __sanitizer_syscall_pre_impl___timer_gettime50()
#define __sanitizer_syscall_post___timer_gettime50() \
  __sanitizer_syscall_post_impl___timer_gettime50()
#if defined(NTP) || !defined(_KERNEL_OPT)
#define __sanitizer_syscall_pre___ntp_gettime50() \
  __sanitizer_syscall_pre_impl___ntp_gettime50()
#define __sanitizer_syscall_post___ntp_gettime50() \
  __sanitizer_syscall_post_impl___ntp_gettime50()
#else
/* syscall 448 has been skipped */
#endif
#define __sanitizer_syscall_pre___wait450() \
  __sanitizer_syscall_pre_impl___wait450()
#define __sanitizer_syscall_post___wait450() \
  __sanitizer_syscall_post_impl___wait450()
#define __sanitizer_syscall_pre___mknod50() \
  __sanitizer_syscall_pre_impl___mknod50()
#define __sanitizer_syscall_post___mknod50() \
  __sanitizer_syscall_post_impl___mknod50()
#define __sanitizer_syscall_pre___fhstat50() \
  __sanitizer_syscall_pre_impl___fhstat50()
#define __sanitizer_syscall_post___fhstat50() \
  __sanitizer_syscall_post_impl___fhstat50()
/* syscall 452 has been skipped */
#define __sanitizer_syscall_pre_pipe2() \
  __sanitizer_syscall_pre_impl_pipe2()
#define __sanitizer_syscall_post_pipe2() \
  __sanitizer_syscall_post_impl_pipe2()
#define __sanitizer_syscall_pre_dup3() \
  __sanitizer_syscall_pre_impl_dup3()
#define __sanitizer_syscall_post_dup3() \
  __sanitizer_syscall_post_impl_dup3()
#define __sanitizer_syscall_pre_kqueue1() \
  __sanitizer_syscall_pre_impl_kqueue1()
#define __sanitizer_syscall_post_kqueue1() \
  __sanitizer_syscall_post_impl_kqueue1()
#define __sanitizer_syscall_pre_paccept() \
  __sanitizer_syscall_pre_impl_paccept()
#define __sanitizer_syscall_post_paccept() \
  __sanitizer_syscall_post_impl_paccept()
#define __sanitizer_syscall_pre_linkat() \
  __sanitizer_syscall_pre_impl_linkat()
#define __sanitizer_syscall_post_linkat() \
  __sanitizer_syscall_post_impl_linkat()
#define __sanitizer_syscall_pre_renameat() \
  __sanitizer_syscall_pre_impl_renameat()
#define __sanitizer_syscall_post_renameat() \
  __sanitizer_syscall_post_impl_renameat()
#define __sanitizer_syscall_pre_mkfifoat() \
  __sanitizer_syscall_pre_impl_mkfifoat()
#define __sanitizer_syscall_post_mkfifoat() \
  __sanitizer_syscall_post_impl_mkfifoat()
#define __sanitizer_syscall_pre_mknodat() \
  __sanitizer_syscall_pre_impl_mknodat()
#define __sanitizer_syscall_post_mknodat() \
  __sanitizer_syscall_post_impl_mknodat()
#define __sanitizer_syscall_pre_mkdirat() \
  __sanitizer_syscall_pre_impl_mkdirat()
#define __sanitizer_syscall_post_mkdirat() \
  __sanitizer_syscall_post_impl_mkdirat()
#define __sanitizer_syscall_pre_faccessat() \
  __sanitizer_syscall_pre_impl_faccessat()
#define __sanitizer_syscall_post_faccessat() \
  __sanitizer_syscall_post_impl_faccessat()
#define __sanitizer_syscall_pre_fchmodat() \
  __sanitizer_syscall_pre_impl_fchmodat()
#define __sanitizer_syscall_post_fchmodat() \
  __sanitizer_syscall_post_impl_fchmodat()
#define __sanitizer_syscall_pre_fchownat() \
  __sanitizer_syscall_pre_impl_fchownat()
#define __sanitizer_syscall_post_fchownat() \
  __sanitizer_syscall_post_impl_fchownat()
#define __sanitizer_syscall_pre_fexecve() \
  __sanitizer_syscall_pre_impl_fexecve()
#define __sanitizer_syscall_post_fexecve() \
  __sanitizer_syscall_post_impl_fexecve()
#define __sanitizer_syscall_pre_fstatat() \
  __sanitizer_syscall_pre_impl_fstatat()
#define __sanitizer_syscall_post_fstatat() \
  __sanitizer_syscall_post_impl_fstatat()
#define __sanitizer_syscall_pre_utimensat() \
  __sanitizer_syscall_pre_impl_utimensat()
#define __sanitizer_syscall_post_utimensat() \
  __sanitizer_syscall_post_impl_utimensat()
#define __sanitizer_syscall_pre_openat() \
  __sanitizer_syscall_pre_impl_openat()
#define __sanitizer_syscall_post_openat() \
  __sanitizer_syscall_post_impl_openat()
#define __sanitizer_syscall_pre_readlinkat() \
  __sanitizer_syscall_pre_impl_readlinkat()
#define __sanitizer_syscall_post_readlinkat() \
  __sanitizer_syscall_post_impl_readlinkat()
#define __sanitizer_syscall_pre_symlinkat() \
  __sanitizer_syscall_pre_impl_symlinkat()
#define __sanitizer_syscall_post_symlinkat() \
  __sanitizer_syscall_post_impl_symlinkat()
#define __sanitizer_syscall_pre_unlinkat() \
  __sanitizer_syscall_pre_impl_unlinkat()
#define __sanitizer_syscall_post_unlinkat() \
  __sanitizer_syscall_post_impl_unlinkat()
#define __sanitizer_syscall_pre_futimens() \
  __sanitizer_syscall_pre_impl_futimens()
#define __sanitizer_syscall_post_futimens() \
  __sanitizer_syscall_post_impl_futimens()
#define __sanitizer_syscall_pre___quotactl() \
  __sanitizer_syscall_pre_impl___quotactl()
#define __sanitizer_syscall_post___quotactl() \
  __sanitizer_syscall_post_impl___quotactl()
#define __sanitizer_syscall_pre_posix_spawn() \
  __sanitizer_syscall_pre_impl_posix_spawn()
#define __sanitizer_syscall_post_posix_spawn() \
  __sanitizer_syscall_post_impl_posix_spawn()
#define __sanitizer_syscall_pre_recvmmsg() \
  __sanitizer_syscall_pre_impl_recvmmsg()
#define __sanitizer_syscall_post_recvmmsg() \
  __sanitizer_syscall_post_impl_recvmmsg()
#define __sanitizer_syscall_pre_sendmmsg() \
  __sanitizer_syscall_pre_impl_sendmmsg()
#define __sanitizer_syscall_post_sendmmsg() \
  __sanitizer_syscall_post_impl_sendmmsg()
#define __sanitizer_syscall_pre_clock_nanosleep() \
  __sanitizer_syscall_pre_impl_clock_nanosleep()
#define __sanitizer_syscall_post_clock_nanosleep() \
  __sanitizer_syscall_post_impl_clock_nanosleep()
#define __sanitizer_syscall_pre____lwp_park60() \
  __sanitizer_syscall_pre_impl____lwp_park60()
#define __sanitizer_syscall_post____lwp_park60() \
  __sanitizer_syscall_post_impl____lwp_park60()
#define __sanitizer_syscall_pre_posix_fallocate() \
  __sanitizer_syscall_pre_impl_posix_fallocate()
#define __sanitizer_syscall_post_posix_fallocate() \
  __sanitizer_syscall_post_impl_posix_fallocate()
#define __sanitizer_syscall_pre_fdiscard() \
  __sanitizer_syscall_pre_impl_fdiscard()
#define __sanitizer_syscall_post_fdiscard() \
  __sanitizer_syscall_post_impl_fdiscard()
#define __sanitizer_syscall_pre_wait6() \
  __sanitizer_syscall_pre_impl_wait6()
#define __sanitizer_syscall_post_wait6() \
  __sanitizer_syscall_post_impl_wait6()
#define __sanitizer_syscall_pre_clock_getcpuclockid2() \
  __sanitizer_syscall_pre_impl_clock_getcpuclockid2()
#define __sanitizer_syscall_post_clock_getcpuclockid2() \
  __sanitizer_syscall_post_impl_clock_getcpuclockid2()

#ifdef __cplusplus
extern "C" {
#endif

// Private declarations. Do not call directly from user code. Use macros above.
void __sanitizer_syscall_pre_impl_syscall();
void __sanitizer_syscall_post_impl_syscall();
void __sanitizer_syscall_pre_impl_exit();
void __sanitizer_syscall_post_impl_exit();
void __sanitizer_syscall_pre_impl_fork();
void __sanitizer_syscall_post_impl_fork();
void __sanitizer_syscall_pre_impl_read();
void __sanitizer_syscall_post_impl_read();
void __sanitizer_syscall_pre_impl_write();
void __sanitizer_syscall_post_impl_write();
void __sanitizer_syscall_pre_impl_open();
void __sanitizer_syscall_post_impl_open();
void __sanitizer_syscall_pre_impl_close();
void __sanitizer_syscall_post_impl_close();
void __sanitizer_syscall_pre_impl_compat_50_wait4();
void __sanitizer_syscall_post_impl_compat_50_wait4();
void __sanitizer_syscall_pre_impl_compat_43_ocreat();
void __sanitizer_syscall_post_impl_compat_43_ocreat();
void __sanitizer_syscall_pre_impl_link();
void __sanitizer_syscall_post_impl_link();
void __sanitizer_syscall_pre_impl_unlink();
void __sanitizer_syscall_post_impl_unlink();
/* syscall 11 has been skipped */
void __sanitizer_syscall_pre_impl_chdir();
void __sanitizer_syscall_post_impl_chdir();
void __sanitizer_syscall_pre_impl_fchdir();
void __sanitizer_syscall_post_impl_fchdir();
void __sanitizer_syscall_pre_impl_compat_50_mknod();
void __sanitizer_syscall_post_impl_compat_50_mknod();
void __sanitizer_syscall_pre_impl_chmod();
void __sanitizer_syscall_post_impl_chmod();
void __sanitizer_syscall_pre_impl_chown();
void __sanitizer_syscall_post_impl_chown();
void __sanitizer_syscall_pre_impl_break();
void __sanitizer_syscall_post_impl_break();
void __sanitizer_syscall_pre_impl_compat_20_getfsstat();
void __sanitizer_syscall_post_impl_compat_20_getfsstat();
void __sanitizer_syscall_pre_impl_compat_43_olseek();
void __sanitizer_syscall_post_impl_compat_43_olseek();
void __sanitizer_syscall_pre_impl_getpid();
void __sanitizer_syscall_post_impl_getpid();
void __sanitizer_syscall_pre_impl_compat_40_mount();
void __sanitizer_syscall_post_impl_compat_40_mount();
void __sanitizer_syscall_pre_impl_unmount();
void __sanitizer_syscall_post_impl_unmount();
void __sanitizer_syscall_pre_impl_setuid();
void __sanitizer_syscall_post_impl_setuid();
void __sanitizer_syscall_pre_impl_getuid();
void __sanitizer_syscall_post_impl_getuid();
void __sanitizer_syscall_pre_impl_geteuid();
void __sanitizer_syscall_post_impl_geteuid();
void __sanitizer_syscall_pre_impl_ptrace();
void __sanitizer_syscall_post_impl_ptrace();
void __sanitizer_syscall_pre_impl_recvmsg();
void __sanitizer_syscall_post_impl_recvmsg();
void __sanitizer_syscall_pre_impl_sendmsg();
void __sanitizer_syscall_post_impl_sendmsg();
void __sanitizer_syscall_pre_impl_recvfrom();
void __sanitizer_syscall_post_impl_recvfrom();
void __sanitizer_syscall_pre_impl_accept();
void __sanitizer_syscall_post_impl_accept();
void __sanitizer_syscall_pre_impl_getpeername();
void __sanitizer_syscall_post_impl_getpeername();
void __sanitizer_syscall_pre_impl_getsockname();
void __sanitizer_syscall_post_impl_getsockname();
void __sanitizer_syscall_pre_impl_access();
void __sanitizer_syscall_post_impl_access();
void __sanitizer_syscall_pre_impl_chflags();
void __sanitizer_syscall_post_impl_chflags();
void __sanitizer_syscall_pre_impl_fchflags();
void __sanitizer_syscall_post_impl_fchflags();
void __sanitizer_syscall_pre_impl_sync();
void __sanitizer_syscall_post_impl_sync();
void __sanitizer_syscall_pre_impl_kill();
void __sanitizer_syscall_post_impl_kill();
void __sanitizer_syscall_pre_impl_compat_43_stat43();
void __sanitizer_syscall_post_impl_compat_43_stat43();
void __sanitizer_syscall_pre_impl_getppid();
void __sanitizer_syscall_post_impl_getppid();
void __sanitizer_syscall_pre_impl_compat_43_lstat43();
void __sanitizer_syscall_post_impl_compat_43_lstat43();
void __sanitizer_syscall_pre_impl_dup();
void __sanitizer_syscall_post_impl_dup();
void __sanitizer_syscall_pre_impl_pipe();
void __sanitizer_syscall_post_impl_pipe();
void __sanitizer_syscall_pre_impl_getegid();
void __sanitizer_syscall_post_impl_getegid();
void __sanitizer_syscall_pre_impl_profil();
void __sanitizer_syscall_post_impl_profil();
void __sanitizer_syscall_pre_impl_ktrace();
void __sanitizer_syscall_post_impl_ktrace();
void __sanitizer_syscall_pre_impl_compat_13_sigaction13();
void __sanitizer_syscall_post_impl_compat_13_sigaction13();
void __sanitizer_syscall_pre_impl_getgid();
void __sanitizer_syscall_post_impl_getgid();
void __sanitizer_syscall_pre_impl_compat_13_sigprocmask13();
void __sanitizer_syscall_post_impl_compat_13_sigprocmask13();
void __sanitizer_syscall_pre_impl___getlogin();
void __sanitizer_syscall_post_impl___getlogin();
void __sanitizer_syscall_pre_impl___setlogin();
void __sanitizer_syscall_post_impl___setlogin();
void __sanitizer_syscall_pre_impl_acct();
void __sanitizer_syscall_post_impl_acct();
void __sanitizer_syscall_pre_impl_compat_13_sigpending13();
void __sanitizer_syscall_post_impl_compat_13_sigpending13();
void __sanitizer_syscall_pre_impl_compat_13_sigaltstack13();
void __sanitizer_syscall_post_impl_compat_13_sigaltstack13();
void __sanitizer_syscall_pre_impl_ioctl();
void __sanitizer_syscall_post_impl_ioctl();
void __sanitizer_syscall_pre_impl_compat_12_oreboot();
void __sanitizer_syscall_post_impl_compat_12_oreboot();
void __sanitizer_syscall_pre_impl_revoke();
void __sanitizer_syscall_post_impl_revoke();
void __sanitizer_syscall_pre_impl_symlink();
void __sanitizer_syscall_post_impl_symlink();
void __sanitizer_syscall_pre_impl_readlink();
void __sanitizer_syscall_post_impl_readlink();
void __sanitizer_syscall_pre_impl_execve();
void __sanitizer_syscall_post_impl_execve();
void __sanitizer_syscall_pre_impl_umask();
void __sanitizer_syscall_post_impl_umask();
void __sanitizer_syscall_pre_impl_chroot();
void __sanitizer_syscall_post_impl_chroot();
void __sanitizer_syscall_pre_impl_compat_43_fstat43();
void __sanitizer_syscall_post_impl_compat_43_fstat43();
void __sanitizer_syscall_pre_impl_compat_43_ogetkerninfo();
void __sanitizer_syscall_post_impl_compat_43_ogetkerninfo();
void __sanitizer_syscall_pre_impl_compat_43_ogetpagesize();
void __sanitizer_syscall_post_impl_compat_43_ogetpagesize();
void __sanitizer_syscall_pre_impl_compat_12_msync();
void __sanitizer_syscall_post_impl_compat_12_msync();
void __sanitizer_syscall_pre_impl_vfork();
void __sanitizer_syscall_post_impl_vfork();
/* syscall 67 has been skipped */
/* syscall 68 has been skipped */
void __sanitizer_syscall_pre_impl_sbrk();
void __sanitizer_syscall_post_impl_sbrk();
void __sanitizer_syscall_pre_impl_sstk();
void __sanitizer_syscall_post_impl_sstk();
void __sanitizer_syscall_pre_impl_compat_43_ommap();
void __sanitizer_syscall_post_impl_compat_43_ommap();
void __sanitizer_syscall_pre_impl_vadvise();
void __sanitizer_syscall_post_impl_vadvise();
void __sanitizer_syscall_pre_impl_munmap();
void __sanitizer_syscall_post_impl_munmap();
void __sanitizer_syscall_pre_impl_mprotect();
void __sanitizer_syscall_post_impl_mprotect();
void __sanitizer_syscall_pre_impl_madvise();
void __sanitizer_syscall_post_impl_madvise();
/* syscall 76 has been skipped */
/* syscall 77 has been skipped */
void __sanitizer_syscall_pre_impl_mincore();
void __sanitizer_syscall_post_impl_mincore();
void __sanitizer_syscall_pre_impl_getgroups();
void __sanitizer_syscall_post_impl_getgroups();
void __sanitizer_syscall_pre_impl_setgroups();
void __sanitizer_syscall_post_impl_setgroups();
void __sanitizer_syscall_pre_impl_getpgrp();
void __sanitizer_syscall_post_impl_getpgrp();
void __sanitizer_syscall_pre_impl_setpgid();
void __sanitizer_syscall_post_impl_setpgid();
void __sanitizer_syscall_pre_impl_compat_50_setitimer();
void __sanitizer_syscall_post_impl_compat_50_setitimer();
void __sanitizer_syscall_pre_impl_compat_43_owait();
void __sanitizer_syscall_post_impl_compat_43_owait();
void __sanitizer_syscall_pre_impl_compat_12_oswapon();
void __sanitizer_syscall_post_impl_compat_12_oswapon();
void __sanitizer_syscall_pre_impl_compat_50_getitimer();
void __sanitizer_syscall_post_impl_compat_50_getitimer();
void __sanitizer_syscall_pre_impl_compat_43_ogethostname();
void __sanitizer_syscall_post_impl_compat_43_ogethostname();
void __sanitizer_syscall_pre_impl_compat_43_osethostname();
void __sanitizer_syscall_post_impl_compat_43_osethostname();
void __sanitizer_syscall_pre_impl_compat_43_ogetdtablesize();
void __sanitizer_syscall_post_impl_compat_43_ogetdtablesize();
void __sanitizer_syscall_pre_impl_dup2();
void __sanitizer_syscall_post_impl_dup2();
/* syscall 91 has been skipped */
void __sanitizer_syscall_pre_impl_fcntl();
void __sanitizer_syscall_post_impl_fcntl();
void __sanitizer_syscall_pre_impl_compat_50_select();
void __sanitizer_syscall_post_impl_compat_50_select();
/* syscall 94 has been skipped */
void __sanitizer_syscall_pre_impl_fsync();
void __sanitizer_syscall_post_impl_fsync();
void __sanitizer_syscall_pre_impl_setpriority();
void __sanitizer_syscall_post_impl_setpriority();
void __sanitizer_syscall_pre_impl_compat_30_socket();
void __sanitizer_syscall_post_impl_compat_30_socket();
void __sanitizer_syscall_pre_impl_connect();
void __sanitizer_syscall_post_impl_connect();
void __sanitizer_syscall_pre_impl_compat_43_oaccept();
void __sanitizer_syscall_post_impl_compat_43_oaccept();
void __sanitizer_syscall_pre_impl_getpriority();
void __sanitizer_syscall_post_impl_getpriority();
void __sanitizer_syscall_pre_impl_compat_43_osend();
void __sanitizer_syscall_post_impl_compat_43_osend();
void __sanitizer_syscall_pre_impl_compat_43_orecv();
void __sanitizer_syscall_post_impl_compat_43_orecv();
void __sanitizer_syscall_pre_impl_compat_13_sigreturn13();
void __sanitizer_syscall_post_impl_compat_13_sigreturn13();
void __sanitizer_syscall_pre_impl_bind();
void __sanitizer_syscall_post_impl_bind();
void __sanitizer_syscall_pre_impl_setsockopt();
void __sanitizer_syscall_post_impl_setsockopt();
void __sanitizer_syscall_pre_impl_listen();
void __sanitizer_syscall_post_impl_listen();
/* syscall 107 has been skipped */
void __sanitizer_syscall_pre_impl_compat_43_osigvec();
void __sanitizer_syscall_post_impl_compat_43_osigvec();
void __sanitizer_syscall_pre_impl_compat_43_osigblock();
void __sanitizer_syscall_post_impl_compat_43_osigblock();
void __sanitizer_syscall_pre_impl_compat_43_osigsetmask();
void __sanitizer_syscall_post_impl_compat_43_osigsetmask();
void __sanitizer_syscall_pre_impl_compat_13_sigsuspend13();
void __sanitizer_syscall_post_impl_compat_13_sigsuspend13();
void __sanitizer_syscall_pre_impl_compat_43_osigstack();
void __sanitizer_syscall_post_impl_compat_43_osigstack();
void __sanitizer_syscall_pre_impl_compat_43_orecvmsg();
void __sanitizer_syscall_post_impl_compat_43_orecvmsg();
void __sanitizer_syscall_pre_impl_compat_43_osendmsg();
void __sanitizer_syscall_post_impl_compat_43_osendmsg();
/* syscall 115 has been skipped */
void __sanitizer_syscall_pre_impl_compat_50_gettimeofday();
void __sanitizer_syscall_post_impl_compat_50_gettimeofday();
void __sanitizer_syscall_pre_impl_compat_50_getrusage();
void __sanitizer_syscall_post_impl_compat_50_getrusage();
void __sanitizer_syscall_pre_impl_getsockopt();
void __sanitizer_syscall_post_impl_getsockopt();
/* syscall 119 has been skipped */
void __sanitizer_syscall_pre_impl_readv();
void __sanitizer_syscall_post_impl_readv();
void __sanitizer_syscall_pre_impl_writev();
void __sanitizer_syscall_post_impl_writev();
void __sanitizer_syscall_pre_impl_compat_50_settimeofday();
void __sanitizer_syscall_post_impl_compat_50_settimeofday();
void __sanitizer_syscall_pre_impl_fchown();
void __sanitizer_syscall_post_impl_fchown();
void __sanitizer_syscall_pre_impl_fchmod();
void __sanitizer_syscall_post_impl_fchmod();
void __sanitizer_syscall_pre_impl_compat_43_orecvfrom();
void __sanitizer_syscall_post_impl_compat_43_orecvfrom();
void __sanitizer_syscall_pre_impl_setreuid();
void __sanitizer_syscall_post_impl_setreuid();
void __sanitizer_syscall_pre_impl_setregid();
void __sanitizer_syscall_post_impl_setregid();
void __sanitizer_syscall_pre_impl_rename();
void __sanitizer_syscall_post_impl_rename();
void __sanitizer_syscall_pre_impl_compat_43_otruncate();
void __sanitizer_syscall_post_impl_compat_43_otruncate();
void __sanitizer_syscall_pre_impl_compat_43_oftruncate();
void __sanitizer_syscall_post_impl_compat_43_oftruncate();
void __sanitizer_syscall_pre_impl_flock();
void __sanitizer_syscall_post_impl_flock();
void __sanitizer_syscall_pre_impl_mkfifo();
void __sanitizer_syscall_post_impl_mkfifo();
void __sanitizer_syscall_pre_impl_sendto();
void __sanitizer_syscall_post_impl_sendto();
void __sanitizer_syscall_pre_impl_shutdown();
void __sanitizer_syscall_post_impl_shutdown();
void __sanitizer_syscall_pre_impl_socketpair();
void __sanitizer_syscall_post_impl_socketpair();
void __sanitizer_syscall_pre_impl_mkdir();
void __sanitizer_syscall_post_impl_mkdir();
void __sanitizer_syscall_pre_impl_rmdir();
void __sanitizer_syscall_post_impl_rmdir();
void __sanitizer_syscall_pre_impl_compat_50_utimes();
void __sanitizer_syscall_post_impl_compat_50_utimes();
/* syscall 139 has been skipped */
void __sanitizer_syscall_pre_impl_compat_50_adjtime();
void __sanitizer_syscall_post_impl_compat_50_adjtime();
void __sanitizer_syscall_pre_impl_compat_43_ogetpeername();
void __sanitizer_syscall_post_impl_compat_43_ogetpeername();
void __sanitizer_syscall_pre_impl_compat_43_ogethostid();
void __sanitizer_syscall_post_impl_compat_43_ogethostid();
void __sanitizer_syscall_pre_impl_compat_43_osethostid();
void __sanitizer_syscall_post_impl_compat_43_osethostid();
void __sanitizer_syscall_pre_impl_compat_43_ogetrlimit();
void __sanitizer_syscall_post_impl_compat_43_ogetrlimit();
void __sanitizer_syscall_pre_impl_compat_43_osetrlimit();
void __sanitizer_syscall_post_impl_compat_43_osetrlimit();
void __sanitizer_syscall_pre_impl_compat_43_okillpg();
void __sanitizer_syscall_post_impl_compat_43_okillpg();
void __sanitizer_syscall_pre_impl_setsid();
void __sanitizer_syscall_post_impl_setsid();
void __sanitizer_syscall_pre_impl_compat_50_quotactl();
void __sanitizer_syscall_post_impl_compat_50_quotactl();
void __sanitizer_syscall_pre_impl_compat_43_oquota();
void __sanitizer_syscall_post_impl_compat_43_oquota();
void __sanitizer_syscall_pre_impl_compat_43_ogetsockname();
void __sanitizer_syscall_post_impl_compat_43_ogetsockname();
/* syscall 151 has been skipped */
/* syscall 152 has been skipped */
/* syscall 153 has been skipped */
/* syscall 154 has been skipped */
void __sanitizer_syscall_pre_impl_nfssvc();
void __sanitizer_syscall_post_impl_nfssvc();
void __sanitizer_syscall_pre_impl_compat_43_ogetdirentries();
void __sanitizer_syscall_post_impl_compat_43_ogetdirentries();
void __sanitizer_syscall_pre_impl_compat_20_statfs();
void __sanitizer_syscall_post_impl_compat_20_statfs();
void __sanitizer_syscall_pre_impl_compat_20_fstatfs();
void __sanitizer_syscall_post_impl_compat_20_fstatfs();
/* syscall 159 has been skipped */
/* syscall 160 has been skipped */
void __sanitizer_syscall_pre_impl_compat_30_getfh();
void __sanitizer_syscall_post_impl_compat_30_getfh();
void __sanitizer_syscall_pre_impl_compat_09_ogetdomainname();
void __sanitizer_syscall_post_impl_compat_09_ogetdomainname();
void __sanitizer_syscall_pre_impl_compat_09_osetdomainname();
void __sanitizer_syscall_post_impl_compat_09_osetdomainname();
void __sanitizer_syscall_pre_impl_compat_09_ouname();
void __sanitizer_syscall_post_impl_compat_09_ouname();
void __sanitizer_syscall_pre_impl_sysarch();
void __sanitizer_syscall_post_impl_sysarch();
/* syscall 166 has been skipped */
/* syscall 167 has been skipped */
/* syscall 168 has been skipped */
void __sanitizer_syscall_pre_impl_compat_10_osemsys();
void __sanitizer_syscall_post_impl_compat_10_osemsys();
/* syscall 169 has been skipped */
void __sanitizer_syscall_pre_impl_compat_10_omsgsys();
void __sanitizer_syscall_post_impl_compat_10_omsgsys();
/* syscall 170 has been skipped */
void __sanitizer_syscall_pre_impl_compat_10_oshmsys();
void __sanitizer_syscall_post_impl_compat_10_oshmsys();
/* syscall 171 has been skipped */
/* syscall 172 has been skipped */
void __sanitizer_syscall_pre_impl_pread();
void __sanitizer_syscall_post_impl_pread();
void __sanitizer_syscall_pre_impl_pwrite();
void __sanitizer_syscall_post_impl_pwrite();
void __sanitizer_syscall_pre_impl_compat_30_ntp_gettime();
void __sanitizer_syscall_post_impl_compat_30_ntp_gettime();
void __sanitizer_syscall_pre_impl_ntp_adjtime();
void __sanitizer_syscall_post_impl_ntp_adjtime();
/* syscall 176 has been skipped */
/* syscall 177 has been skipped */
/* syscall 178 has been skipped */
/* syscall 179 has been skipped */
/* syscall 180 has been skipped */
void __sanitizer_syscall_pre_impl_setgid();
void __sanitizer_syscall_post_impl_setgid();
void __sanitizer_syscall_pre_impl_setegid();
void __sanitizer_syscall_post_impl_setegid();
void __sanitizer_syscall_pre_impl_seteuid();
void __sanitizer_syscall_post_impl_seteuid();
void __sanitizer_syscall_pre_impl_lfs_bmapv();
void __sanitizer_syscall_post_impl_lfs_bmapv();
void __sanitizer_syscall_pre_impl_lfs_markv();
void __sanitizer_syscall_post_impl_lfs_markv();
void __sanitizer_syscall_pre_impl_lfs_segclean();
void __sanitizer_syscall_post_impl_lfs_segclean();
void __sanitizer_syscall_pre_impl_compat_50_lfs_segwait();
void __sanitizer_syscall_post_impl_compat_50_lfs_segwait();
void __sanitizer_syscall_pre_impl_compat_12_stat12();
void __sanitizer_syscall_post_impl_compat_12_stat12();
void __sanitizer_syscall_pre_impl_compat_12_fstat12();
void __sanitizer_syscall_post_impl_compat_12_fstat12();
void __sanitizer_syscall_pre_impl_compat_12_lstat12();
void __sanitizer_syscall_post_impl_compat_12_lstat12();
void __sanitizer_syscall_pre_impl_pathconf();
void __sanitizer_syscall_post_impl_pathconf();
void __sanitizer_syscall_pre_impl_fpathconf();
void __sanitizer_syscall_post_impl_fpathconf();
/* syscall 193 has been skipped */
void __sanitizer_syscall_pre_impl_getrlimit();
void __sanitizer_syscall_post_impl_getrlimit();
void __sanitizer_syscall_pre_impl_setrlimit();
void __sanitizer_syscall_post_impl_setrlimit();
void __sanitizer_syscall_pre_impl_compat_12_getdirentries();
void __sanitizer_syscall_post_impl_compat_12_getdirentries();
void __sanitizer_syscall_pre_impl_mmap();
void __sanitizer_syscall_post_impl_mmap();
void __sanitizer_syscall_pre_impl___syscall();
void __sanitizer_syscall_post_impl___syscall();
void __sanitizer_syscall_pre_impl_lseek();
void __sanitizer_syscall_post_impl_lseek();
void __sanitizer_syscall_pre_impl_truncate();
void __sanitizer_syscall_post_impl_truncate();
void __sanitizer_syscall_pre_impl_ftruncate();
void __sanitizer_syscall_post_impl_ftruncate();
void __sanitizer_syscall_pre_impl___sysctl();
void __sanitizer_syscall_post_impl___sysctl();
void __sanitizer_syscall_pre_impl_mlock();
void __sanitizer_syscall_post_impl_mlock();
void __sanitizer_syscall_pre_impl_munlock();
void __sanitizer_syscall_post_impl_munlock();
void __sanitizer_syscall_pre_impl_undelete();
void __sanitizer_syscall_post_impl_undelete();
void __sanitizer_syscall_pre_impl_compat_50_futimes();
void __sanitizer_syscall_post_impl_compat_50_futimes();
void __sanitizer_syscall_pre_impl_getpgid();
void __sanitizer_syscall_post_impl_getpgid();
void __sanitizer_syscall_pre_impl_reboot();
void __sanitizer_syscall_post_impl_reboot();
void __sanitizer_syscall_pre_impl_poll();
void __sanitizer_syscall_post_impl_poll();
void __sanitizer_syscall_pre_impl_afssys();
void __sanitizer_syscall_post_impl_afssys();
/* syscall 211 has been skipped */
/* syscall 212 has been skipped */
/* syscall 213 has been skipped */
/* syscall 214 has been skipped */
/* syscall 215 has been skipped */
/* syscall 216 has been skipped */
/* syscall 217 has been skipped */
/* syscall 218 has been skipped */
/* syscall 219 has been skipped */
void __sanitizer_syscall_pre_impl_compat_14___semctl();
void __sanitizer_syscall_post_impl_compat_14___semctl();
void __sanitizer_syscall_pre_impl_semget();
void __sanitizer_syscall_post_impl_semget();
void __sanitizer_syscall_pre_impl_semop();
void __sanitizer_syscall_post_impl_semop();
void __sanitizer_syscall_pre_impl_semconfig();
void __sanitizer_syscall_post_impl_semconfig();
void __sanitizer_syscall_pre_impl_compat_14_msgctl();
void __sanitizer_syscall_post_impl_compat_14_msgctl();
void __sanitizer_syscall_pre_impl_msgget();
void __sanitizer_syscall_post_impl_msgget();
void __sanitizer_syscall_pre_impl_msgsnd();
void __sanitizer_syscall_post_impl_msgsnd();
void __sanitizer_syscall_pre_impl_msgrcv();
void __sanitizer_syscall_post_impl_msgrcv();
void __sanitizer_syscall_pre_impl_shmat();
void __sanitizer_syscall_post_impl_shmat();
void __sanitizer_syscall_pre_impl_compat_14_shmctl();
void __sanitizer_syscall_post_impl_compat_14_shmctl();
void __sanitizer_syscall_pre_impl_shmdt();
void __sanitizer_syscall_post_impl_shmdt();
void __sanitizer_syscall_pre_impl_shmget();
void __sanitizer_syscall_post_impl_shmget();
void __sanitizer_syscall_pre_impl_compat_50_clock_gettime();
void __sanitizer_syscall_post_impl_compat_50_clock_gettime();
void __sanitizer_syscall_pre_impl_compat_50_clock_settime();
void __sanitizer_syscall_post_impl_compat_50_clock_settime();
void __sanitizer_syscall_pre_impl_compat_50_clock_getres();
void __sanitizer_syscall_post_impl_compat_50_clock_getres();
void __sanitizer_syscall_pre_impl_timer_create();
void __sanitizer_syscall_post_impl_timer_create();
void __sanitizer_syscall_pre_impl_timer_delete();
void __sanitizer_syscall_post_impl_timer_delete();
void __sanitizer_syscall_pre_impl_compat_50_timer_settime();
void __sanitizer_syscall_post_impl_compat_50_timer_settime();
void __sanitizer_syscall_pre_impl_compat_50_timer_gettime();
void __sanitizer_syscall_post_impl_compat_50_timer_gettime();
void __sanitizer_syscall_pre_impl_timer_getoverrun();
void __sanitizer_syscall_post_impl_timer_getoverrun();
void __sanitizer_syscall_pre_impl_compat_50_nanosleep();
void __sanitizer_syscall_post_impl_compat_50_nanosleep();
void __sanitizer_syscall_pre_impl_fdatasync();
void __sanitizer_syscall_post_impl_fdatasync();
void __sanitizer_syscall_pre_impl_mlockall();
void __sanitizer_syscall_post_impl_mlockall();
void __sanitizer_syscall_pre_impl_munlockall();
void __sanitizer_syscall_post_impl_munlockall();
void __sanitizer_syscall_pre_impl_compat_50___sigtimedwait();
void __sanitizer_syscall_post_impl_compat_50___sigtimedwait();
void __sanitizer_syscall_pre_impl_sigqueueinfo();
void __sanitizer_syscall_post_impl_sigqueueinfo();
void __sanitizer_syscall_pre_impl_modctl();
void __sanitizer_syscall_post_impl_modctl();
void __sanitizer_syscall_pre_impl__ksem_init();
void __sanitizer_syscall_post_impl__ksem_init();
void __sanitizer_syscall_pre_impl__ksem_open();
void __sanitizer_syscall_post_impl__ksem_open();
void __sanitizer_syscall_pre_impl__ksem_unlink();
void __sanitizer_syscall_post_impl__ksem_unlink();
void __sanitizer_syscall_pre_impl__ksem_close();
void __sanitizer_syscall_post_impl__ksem_close();
void __sanitizer_syscall_pre_impl__ksem_post();
void __sanitizer_syscall_post_impl__ksem_post();
void __sanitizer_syscall_pre_impl__ksem_wait();
void __sanitizer_syscall_post_impl__ksem_wait();
void __sanitizer_syscall_pre_impl__ksem_trywait();
void __sanitizer_syscall_post_impl__ksem_trywait();
void __sanitizer_syscall_pre_impl__ksem_getvalue();
void __sanitizer_syscall_post_impl__ksem_getvalue();
void __sanitizer_syscall_pre_impl__ksem_destroy();
void __sanitizer_syscall_post_impl__ksem_destroy();
void __sanitizer_syscall_pre_impl__ksem_timedwait();
void __sanitizer_syscall_post_impl__ksem_timedwait();
void __sanitizer_syscall_pre_impl_mq_open();
void __sanitizer_syscall_post_impl_mq_open();
void __sanitizer_syscall_pre_impl_mq_close();
void __sanitizer_syscall_post_impl_mq_close();
void __sanitizer_syscall_pre_impl_mq_unlink();
void __sanitizer_syscall_post_impl_mq_unlink();
void __sanitizer_syscall_pre_impl_mq_getattr();
void __sanitizer_syscall_post_impl_mq_getattr();
void __sanitizer_syscall_pre_impl_mq_setattr();
void __sanitizer_syscall_post_impl_mq_setattr();
void __sanitizer_syscall_pre_impl_mq_notify();
void __sanitizer_syscall_post_impl_mq_notify();
void __sanitizer_syscall_pre_impl_mq_send();
void __sanitizer_syscall_post_impl_mq_send();
void __sanitizer_syscall_pre_impl_mq_receive();
void __sanitizer_syscall_post_impl_mq_receive();
void __sanitizer_syscall_pre_impl_compat_50_mq_timedsend();
void __sanitizer_syscall_post_impl_compat_50_mq_timedsend();
void __sanitizer_syscall_pre_impl_compat_50_mq_timedreceive();
void __sanitizer_syscall_post_impl_compat_50_mq_timedreceive();
/* syscall 267 has been skipped */
/* syscall 268 has been skipped */
/* syscall 269 has been skipped */
void __sanitizer_syscall_pre_impl___posix_rename();
void __sanitizer_syscall_post_impl___posix_rename();
void __sanitizer_syscall_pre_impl_swapctl();
void __sanitizer_syscall_post_impl_swapctl();
void __sanitizer_syscall_pre_impl_compat_30_getdents();
void __sanitizer_syscall_post_impl_compat_30_getdents();
void __sanitizer_syscall_pre_impl_minherit();
void __sanitizer_syscall_post_impl_minherit();
void __sanitizer_syscall_pre_impl_lchmod();
void __sanitizer_syscall_post_impl_lchmod();
void __sanitizer_syscall_pre_impl_lchown();
void __sanitizer_syscall_post_impl_lchown();
void __sanitizer_syscall_pre_impl_compat_50_lutimes();
void __sanitizer_syscall_post_impl_compat_50_lutimes();
void __sanitizer_syscall_pre_impl___msync13();
void __sanitizer_syscall_post_impl___msync13();
void __sanitizer_syscall_pre_impl_compat_30___stat13();
void __sanitizer_syscall_post_impl_compat_30___stat13();
void __sanitizer_syscall_pre_impl_compat_30___fstat13();
void __sanitizer_syscall_post_impl_compat_30___fstat13();
void __sanitizer_syscall_pre_impl_compat_30___lstat13();
void __sanitizer_syscall_post_impl_compat_30___lstat13();
void __sanitizer_syscall_pre_impl___sigaltstack14();
void __sanitizer_syscall_post_impl___sigaltstack14();
void __sanitizer_syscall_pre_impl___vfork14();
void __sanitizer_syscall_post_impl___vfork14();
void __sanitizer_syscall_pre_impl___posix_chown();
void __sanitizer_syscall_post_impl___posix_chown();
void __sanitizer_syscall_pre_impl___posix_fchown();
void __sanitizer_syscall_post_impl___posix_fchown();
void __sanitizer_syscall_pre_impl___posix_lchown();
void __sanitizer_syscall_post_impl___posix_lchown();
void __sanitizer_syscall_pre_impl_getsid();
void __sanitizer_syscall_post_impl_getsid();
void __sanitizer_syscall_pre_impl___clone();
void __sanitizer_syscall_post_impl___clone();
void __sanitizer_syscall_pre_impl_fktrace();
void __sanitizer_syscall_post_impl_fktrace();
void __sanitizer_syscall_pre_impl_preadv();
void __sanitizer_syscall_post_impl_preadv();
void __sanitizer_syscall_pre_impl_pwritev();
void __sanitizer_syscall_post_impl_pwritev();
void __sanitizer_syscall_pre_impl_compat_16___sigaction14();
void __sanitizer_syscall_post_impl_compat_16___sigaction14();
void __sanitizer_syscall_pre_impl___sigpending14();
void __sanitizer_syscall_post_impl___sigpending14();
void __sanitizer_syscall_pre_impl___sigprocmask14();
void __sanitizer_syscall_post_impl___sigprocmask14();
void __sanitizer_syscall_pre_impl___sigsuspend14();
void __sanitizer_syscall_post_impl___sigsuspend14();
void __sanitizer_syscall_pre_impl_compat_16___sigreturn14();
void __sanitizer_syscall_post_impl_compat_16___sigreturn14();
void __sanitizer_syscall_pre_impl___getcwd();
void __sanitizer_syscall_post_impl___getcwd();
void __sanitizer_syscall_pre_impl_fchroot();
void __sanitizer_syscall_post_impl_fchroot();
void __sanitizer_syscall_pre_impl_compat_30_fhopen();
void __sanitizer_syscall_post_impl_compat_30_fhopen();
void __sanitizer_syscall_pre_impl_compat_30_fhstat();
void __sanitizer_syscall_post_impl_compat_30_fhstat();
void __sanitizer_syscall_pre_impl_compat_20_fhstatfs();
void __sanitizer_syscall_post_impl_compat_20_fhstatfs();
void __sanitizer_syscall_pre_impl_compat_50_____semctl13();
void __sanitizer_syscall_post_impl_compat_50_____semctl13();
void __sanitizer_syscall_pre_impl_compat_50___msgctl13();
void __sanitizer_syscall_post_impl_compat_50___msgctl13();
void __sanitizer_syscall_pre_impl_compat_50___shmctl13();
void __sanitizer_syscall_post_impl_compat_50___shmctl13();
void __sanitizer_syscall_pre_impl_lchflags();
void __sanitizer_syscall_post_impl_lchflags();
void __sanitizer_syscall_pre_impl_issetugid();
void __sanitizer_syscall_post_impl_issetugid();
void __sanitizer_syscall_pre_impl_utrace();
void __sanitizer_syscall_post_impl_utrace();
void __sanitizer_syscall_pre_impl_getcontext();
void __sanitizer_syscall_post_impl_getcontext();
void __sanitizer_syscall_pre_impl_setcontext();
void __sanitizer_syscall_post_impl_setcontext();
void __sanitizer_syscall_pre_impl__lwp_create();
void __sanitizer_syscall_post_impl__lwp_create();
void __sanitizer_syscall_pre_impl__lwp_exit();
void __sanitizer_syscall_post_impl__lwp_exit();
void __sanitizer_syscall_pre_impl__lwp_self();
void __sanitizer_syscall_post_impl__lwp_self();
void __sanitizer_syscall_pre_impl__lwp_wait();
void __sanitizer_syscall_post_impl__lwp_wait();
void __sanitizer_syscall_pre_impl__lwp_suspend();
void __sanitizer_syscall_post_impl__lwp_suspend();
void __sanitizer_syscall_pre_impl__lwp_continue();
void __sanitizer_syscall_post_impl__lwp_continue();
void __sanitizer_syscall_pre_impl__lwp_wakeup();
void __sanitizer_syscall_post_impl__lwp_wakeup();
void __sanitizer_syscall_pre_impl__lwp_getprivate();
void __sanitizer_syscall_post_impl__lwp_getprivate();
void __sanitizer_syscall_pre_impl__lwp_setprivate();
void __sanitizer_syscall_post_impl__lwp_setprivate();
void __sanitizer_syscall_pre_impl__lwp_kill();
void __sanitizer_syscall_post_impl__lwp_kill();
void __sanitizer_syscall_pre_impl__lwp_detach();
void __sanitizer_syscall_post_impl__lwp_detach();
void __sanitizer_syscall_pre_impl_compat_50__lwp_park();
void __sanitizer_syscall_post_impl_compat_50__lwp_park();
void __sanitizer_syscall_pre_impl__lwp_unpark();
void __sanitizer_syscall_post_impl__lwp_unpark();
void __sanitizer_syscall_pre_impl__lwp_unpark_all();
void __sanitizer_syscall_post_impl__lwp_unpark_all();
void __sanitizer_syscall_pre_impl__lwp_setname();
void __sanitizer_syscall_post_impl__lwp_setname();
void __sanitizer_syscall_pre_impl__lwp_getname();
void __sanitizer_syscall_post_impl__lwp_getname();
void __sanitizer_syscall_pre_impl__lwp_ctl();
void __sanitizer_syscall_post_impl__lwp_ctl();
/* syscall 326 has been skipped */
/* syscall 327 has been skipped */
/* syscall 328 has been skipped */
/* syscall 329 has been skipped */
void __sanitizer_syscall_pre_impl_compat_60_sa_register();
void __sanitizer_syscall_post_impl_compat_60_sa_register();
void __sanitizer_syscall_pre_impl_compat_60_sa_stacks();
void __sanitizer_syscall_post_impl_compat_60_sa_stacks();
void __sanitizer_syscall_pre_impl_compat_60_sa_enable();
void __sanitizer_syscall_post_impl_compat_60_sa_enable();
void __sanitizer_syscall_pre_impl_compat_60_sa_setconcurrency();
void __sanitizer_syscall_post_impl_compat_60_sa_setconcurrency();
void __sanitizer_syscall_pre_impl_compat_60_sa_yield();
void __sanitizer_syscall_post_impl_compat_60_sa_yield();
void __sanitizer_syscall_pre_impl_compat_60_sa_preempt();
void __sanitizer_syscall_post_impl_compat_60_sa_preempt();
/* syscall 336 has been skipped */
/* syscall 337 has been skipped */
/* syscall 338 has been skipped */
/* syscall 339 has been skipped */
void __sanitizer_syscall_pre_impl___sigaction_sigtramp();
void __sanitizer_syscall_post_impl___sigaction_sigtramp();
void __sanitizer_syscall_pre_impl_pmc_get_info();
void __sanitizer_syscall_post_impl_pmc_get_info();
void __sanitizer_syscall_pre_impl_pmc_control();
void __sanitizer_syscall_post_impl_pmc_control();
void __sanitizer_syscall_pre_impl_rasctl();
void __sanitizer_syscall_post_impl_rasctl();
void __sanitizer_syscall_pre_impl_kqueue();
void __sanitizer_syscall_post_impl_kqueue();
void __sanitizer_syscall_pre_impl_compat_50_kevent();
void __sanitizer_syscall_post_impl_compat_50_kevent();
void __sanitizer_syscall_pre_impl__sched_setparam();
void __sanitizer_syscall_post_impl__sched_setparam();
void __sanitizer_syscall_pre_impl__sched_getparam();
void __sanitizer_syscall_post_impl__sched_getparam();
void __sanitizer_syscall_pre_impl__sched_setaffinity();
void __sanitizer_syscall_post_impl__sched_setaffinity();
void __sanitizer_syscall_pre_impl__sched_getaffinity();
void __sanitizer_syscall_post_impl__sched_getaffinity();
void __sanitizer_syscall_pre_impl_sched_yield();
void __sanitizer_syscall_post_impl_sched_yield();
void __sanitizer_syscall_pre_impl__sched_protect();
void __sanitizer_syscall_post_impl__sched_protect();
/* syscall 352 has been skipped */
/* syscall 353 has been skipped */
void __sanitizer_syscall_pre_impl_fsync_range();
void __sanitizer_syscall_post_impl_fsync_range();
void __sanitizer_syscall_pre_impl_uuidgen();
void __sanitizer_syscall_post_impl_uuidgen();
void __sanitizer_syscall_pre_impl_getvfsstat();
void __sanitizer_syscall_post_impl_getvfsstat();
void __sanitizer_syscall_pre_impl_statvfs1();
void __sanitizer_syscall_post_impl_statvfs1();
void __sanitizer_syscall_pre_impl_fstatvfs1();
void __sanitizer_syscall_post_impl_fstatvfs1();
void __sanitizer_syscall_pre_impl_compat_30_fhstatvfs1();
void __sanitizer_syscall_post_impl_compat_30_fhstatvfs1();
void __sanitizer_syscall_pre_impl_extattrctl();
void __sanitizer_syscall_post_impl_extattrctl();
void __sanitizer_syscall_pre_impl_extattr_set_file();
void __sanitizer_syscall_post_impl_extattr_set_file();
void __sanitizer_syscall_pre_impl_extattr_get_file();
void __sanitizer_syscall_post_impl_extattr_get_file();
void __sanitizer_syscall_pre_impl_extattr_delete_file();
void __sanitizer_syscall_post_impl_extattr_delete_file();
void __sanitizer_syscall_pre_impl_extattr_set_fd();
void __sanitizer_syscall_post_impl_extattr_set_fd();
void __sanitizer_syscall_pre_impl_extattr_get_fd();
void __sanitizer_syscall_post_impl_extattr_get_fd();
void __sanitizer_syscall_pre_impl_extattr_delete_fd();
void __sanitizer_syscall_post_impl_extattr_delete_fd();
void __sanitizer_syscall_pre_impl_extattr_set_link();
void __sanitizer_syscall_post_impl_extattr_set_link();
void __sanitizer_syscall_pre_impl_extattr_get_link();
void __sanitizer_syscall_post_impl_extattr_get_link();
void __sanitizer_syscall_pre_impl_extattr_delete_link();
void __sanitizer_syscall_post_impl_extattr_delete_link();
void __sanitizer_syscall_pre_impl_extattr_list_fd();
void __sanitizer_syscall_post_impl_extattr_list_fd();
void __sanitizer_syscall_pre_impl_extattr_list_file();
void __sanitizer_syscall_post_impl_extattr_list_file();
void __sanitizer_syscall_pre_impl_extattr_list_link();
void __sanitizer_syscall_post_impl_extattr_list_link();
void __sanitizer_syscall_pre_impl_compat_50_pselect();
void __sanitizer_syscall_post_impl_compat_50_pselect();
void __sanitizer_syscall_pre_impl_compat_50_pollts();
void __sanitizer_syscall_post_impl_compat_50_pollts();
void __sanitizer_syscall_pre_impl_setxattr();
void __sanitizer_syscall_post_impl_setxattr();
void __sanitizer_syscall_pre_impl_lsetxattr();
void __sanitizer_syscall_post_impl_lsetxattr();
void __sanitizer_syscall_pre_impl_fsetxattr();
void __sanitizer_syscall_post_impl_fsetxattr();
void __sanitizer_syscall_pre_impl_getxattr();
void __sanitizer_syscall_post_impl_getxattr();
void __sanitizer_syscall_pre_impl_lgetxattr();
void __sanitizer_syscall_post_impl_lgetxattr();
void __sanitizer_syscall_pre_impl_fgetxattr();
void __sanitizer_syscall_post_impl_fgetxattr();
void __sanitizer_syscall_pre_impl_listxattr();
void __sanitizer_syscall_post_impl_listxattr();
void __sanitizer_syscall_pre_impl_llistxattr();
void __sanitizer_syscall_post_impl_llistxattr();
void __sanitizer_syscall_pre_impl_flistxattr();
void __sanitizer_syscall_post_impl_flistxattr();
void __sanitizer_syscall_pre_impl_removexattr();
void __sanitizer_syscall_post_impl_removexattr();
void __sanitizer_syscall_pre_impl_lremovexattr();
void __sanitizer_syscall_post_impl_lremovexattr();
void __sanitizer_syscall_pre_impl_fremovexattr();
void __sanitizer_syscall_post_impl_fremovexattr();
void __sanitizer_syscall_pre_impl_compat_50___stat30();
void __sanitizer_syscall_post_impl_compat_50___stat30();
void __sanitizer_syscall_pre_impl_compat_50___fstat30();
void __sanitizer_syscall_post_impl_compat_50___fstat30();
void __sanitizer_syscall_pre_impl_compat_50___lstat30();
void __sanitizer_syscall_post_impl_compat_50___lstat30();
void __sanitizer_syscall_pre_impl___getdents30();
void __sanitizer_syscall_post_impl___getdents30();
void __sanitizer_syscall_pre_impl_posix_fadvise();
void __sanitizer_syscall_post_impl_posix_fadvise();
void __sanitizer_syscall_pre_impl_compat_30___fhstat30();
void __sanitizer_syscall_post_impl_compat_30___fhstat30();
void __sanitizer_syscall_pre_impl_compat_50___ntp_gettime30();
void __sanitizer_syscall_post_impl_compat_50___ntp_gettime30();
void __sanitizer_syscall_pre_impl___socket30();
void __sanitizer_syscall_post_impl___socket30();
void __sanitizer_syscall_pre_impl___getfh30();
void __sanitizer_syscall_post_impl___getfh30();
void __sanitizer_syscall_pre_impl___fhopen40();
void __sanitizer_syscall_post_impl___fhopen40();
void __sanitizer_syscall_pre_impl___fhstatvfs140();
void __sanitizer_syscall_post_impl___fhstatvfs140();
void __sanitizer_syscall_pre_impl_compat_50___fhstat40();
void __sanitizer_syscall_post_impl_compat_50___fhstat40();
void __sanitizer_syscall_pre_impl_aio_cancel();
void __sanitizer_syscall_post_impl_aio_cancel();
void __sanitizer_syscall_pre_impl_aio_error();
void __sanitizer_syscall_post_impl_aio_error();
void __sanitizer_syscall_pre_impl_aio_fsync();
void __sanitizer_syscall_post_impl_aio_fsync();
void __sanitizer_syscall_pre_impl_aio_read();
void __sanitizer_syscall_post_impl_aio_read();
void __sanitizer_syscall_pre_impl_aio_return();
void __sanitizer_syscall_post_impl_aio_return();
void __sanitizer_syscall_pre_impl_compat_50_aio_suspend();
void __sanitizer_syscall_post_impl_compat_50_aio_suspend();
void __sanitizer_syscall_pre_impl_aio_write();
void __sanitizer_syscall_post_impl_aio_write();
void __sanitizer_syscall_pre_impl_lio_listio();
void __sanitizer_syscall_post_impl_lio_listio();
/* syscall 407 has been skipped */
/* syscall 408 has been skipped */
/* syscall 409 has been skipped */
void __sanitizer_syscall_pre_impl___mount50();
void __sanitizer_syscall_post_impl___mount50();
void __sanitizer_syscall_pre_impl_mremap();
void __sanitizer_syscall_post_impl_mremap();
void __sanitizer_syscall_pre_impl_pset_create();
void __sanitizer_syscall_post_impl_pset_create();
void __sanitizer_syscall_pre_impl_pset_destroy();
void __sanitizer_syscall_post_impl_pset_destroy();
void __sanitizer_syscall_pre_impl_pset_assign();
void __sanitizer_syscall_post_impl_pset_assign();
void __sanitizer_syscall_pre_impl__pset_bind();
void __sanitizer_syscall_post_impl__pset_bind();
void __sanitizer_syscall_pre_impl___posix_fadvise50();
void __sanitizer_syscall_post_impl___posix_fadvise50();
void __sanitizer_syscall_pre_impl___select50();
void __sanitizer_syscall_post_impl___select50();
void __sanitizer_syscall_pre_impl___gettimeofday50();
void __sanitizer_syscall_post_impl___gettimeofday50();
void __sanitizer_syscall_pre_impl___settimeofday50();
void __sanitizer_syscall_post_impl___settimeofday50();
void __sanitizer_syscall_pre_impl___utimes50();
void __sanitizer_syscall_post_impl___utimes50();
void __sanitizer_syscall_pre_impl___adjtime50();
void __sanitizer_syscall_post_impl___adjtime50();
void __sanitizer_syscall_pre_impl___lfs_segwait50();
void __sanitizer_syscall_post_impl___lfs_segwait50();
void __sanitizer_syscall_pre_impl___futimes50();
void __sanitizer_syscall_post_impl___futimes50();
void __sanitizer_syscall_pre_impl___lutimes50();
void __sanitizer_syscall_post_impl___lutimes50();
void __sanitizer_syscall_pre_impl___setitimer50();
void __sanitizer_syscall_post_impl___setitimer50();
void __sanitizer_syscall_pre_impl___getitimer50();
void __sanitizer_syscall_post_impl___getitimer50();
void __sanitizer_syscall_pre_impl___clock_gettime50();
void __sanitizer_syscall_post_impl___clock_gettime50();
void __sanitizer_syscall_pre_impl___clock_settime50();
void __sanitizer_syscall_post_impl___clock_settime50();
void __sanitizer_syscall_pre_impl___clock_getres50();
void __sanitizer_syscall_post_impl___clock_getres50();
void __sanitizer_syscall_pre_impl___nanosleep50();
void __sanitizer_syscall_post_impl___nanosleep50();
void __sanitizer_syscall_pre_impl_____sigtimedwait50();
void __sanitizer_syscall_post_impl_____sigtimedwait50();
void __sanitizer_syscall_pre_impl___mq_timedsend50();
void __sanitizer_syscall_post_impl___mq_timedsend50();
void __sanitizer_syscall_pre_impl___mq_timedreceive50();
void __sanitizer_syscall_post_impl___mq_timedreceive50();
void __sanitizer_syscall_pre_impl_compat_60__lwp_park();
void __sanitizer_syscall_post_impl_compat_60__lwp_park();
void __sanitizer_syscall_pre_impl___kevent50();
void __sanitizer_syscall_post_impl___kevent50();
void __sanitizer_syscall_pre_impl___pselect50();
void __sanitizer_syscall_post_impl___pselect50();
void __sanitizer_syscall_pre_impl___pollts50();
void __sanitizer_syscall_post_impl___pollts50();
void __sanitizer_syscall_pre_impl___aio_suspend50();
void __sanitizer_syscall_post_impl___aio_suspend50();
void __sanitizer_syscall_pre_impl___stat50();
void __sanitizer_syscall_post_impl___stat50();
void __sanitizer_syscall_pre_impl___fstat50();
void __sanitizer_syscall_post_impl___fstat50();
void __sanitizer_syscall_pre_impl___lstat50();
void __sanitizer_syscall_post_impl___lstat50();
void __sanitizer_syscall_pre_impl_____semctl50();
void __sanitizer_syscall_post_impl_____semctl50();
void __sanitizer_syscall_pre_impl___shmctl50();
void __sanitizer_syscall_post_impl___shmctl50();
void __sanitizer_syscall_pre_impl___msgctl50();
void __sanitizer_syscall_post_impl___msgctl50();
void __sanitizer_syscall_pre_impl___getrusage50();
void __sanitizer_syscall_post_impl___getrusage50();
void __sanitizer_syscall_pre_impl___timer_settime50();
void __sanitizer_syscall_post_impl___timer_settime50();
void __sanitizer_syscall_pre_impl___timer_gettime50();
void __sanitizer_syscall_post_impl___timer_gettime50();
void __sanitizer_syscall_pre_impl___ntp_gettime50();
void __sanitizer_syscall_post_impl___ntp_gettime50();
/* syscall 448 has been skipped */
void __sanitizer_syscall_pre_impl___wait450();
void __sanitizer_syscall_post_impl___wait450();
void __sanitizer_syscall_pre_impl___mknod50();
void __sanitizer_syscall_post_impl___mknod50();
void __sanitizer_syscall_pre_impl___fhstat50();
void __sanitizer_syscall_post_impl___fhstat50();
/* syscall 452 has been skipped */
void __sanitizer_syscall_pre_impl_pipe2();
void __sanitizer_syscall_post_impl_pipe2();
void __sanitizer_syscall_pre_impl_dup3();
void __sanitizer_syscall_post_impl_dup3();
void __sanitizer_syscall_pre_impl_kqueue1();
void __sanitizer_syscall_post_impl_kqueue1();
void __sanitizer_syscall_pre_impl_paccept();
void __sanitizer_syscall_post_impl_paccept();
void __sanitizer_syscall_pre_impl_linkat();
void __sanitizer_syscall_post_impl_linkat();
void __sanitizer_syscall_pre_impl_renameat();
void __sanitizer_syscall_post_impl_renameat();
void __sanitizer_syscall_pre_impl_mkfifoat();
void __sanitizer_syscall_post_impl_mkfifoat();
void __sanitizer_syscall_pre_impl_mknodat();
void __sanitizer_syscall_post_impl_mknodat();
void __sanitizer_syscall_pre_impl_mkdirat();
void __sanitizer_syscall_post_impl_mkdirat();
void __sanitizer_syscall_pre_impl_faccessat();
void __sanitizer_syscall_post_impl_faccessat();
void __sanitizer_syscall_pre_impl_fchmodat();
void __sanitizer_syscall_post_impl_fchmodat();
void __sanitizer_syscall_pre_impl_fchownat();
void __sanitizer_syscall_post_impl_fchownat();
void __sanitizer_syscall_pre_impl_fexecve();
void __sanitizer_syscall_post_impl_fexecve();
void __sanitizer_syscall_pre_impl_fstatat();
void __sanitizer_syscall_post_impl_fstatat();
void __sanitizer_syscall_pre_impl_utimensat();
void __sanitizer_syscall_post_impl_utimensat();
void __sanitizer_syscall_pre_impl_openat();
void __sanitizer_syscall_post_impl_openat();
void __sanitizer_syscall_pre_impl_readlinkat();
void __sanitizer_syscall_post_impl_readlinkat();
void __sanitizer_syscall_pre_impl_symlinkat();
void __sanitizer_syscall_post_impl_symlinkat();
void __sanitizer_syscall_pre_impl_unlinkat();
void __sanitizer_syscall_post_impl_unlinkat();
void __sanitizer_syscall_pre_impl_futimens();
void __sanitizer_syscall_post_impl_futimens();
void __sanitizer_syscall_pre_impl___quotactl();
void __sanitizer_syscall_post_impl___quotactl();
void __sanitizer_syscall_pre_impl_posix_spawn();
void __sanitizer_syscall_post_impl_posix_spawn();
void __sanitizer_syscall_pre_impl_recvmmsg();
void __sanitizer_syscall_post_impl_recvmmsg();
void __sanitizer_syscall_pre_impl_sendmmsg();
void __sanitizer_syscall_post_impl_sendmmsg();
void __sanitizer_syscall_pre_impl_clock_nanosleep();
void __sanitizer_syscall_post_impl_clock_nanosleep();
void __sanitizer_syscall_pre_impl____lwp_park60();
void __sanitizer_syscall_post_impl____lwp_park60();
void __sanitizer_syscall_pre_impl_posix_fallocate();
void __sanitizer_syscall_post_impl_posix_fallocate();
void __sanitizer_syscall_pre_impl_fdiscard();
void __sanitizer_syscall_post_impl_fdiscard();
void __sanitizer_syscall_pre_impl_wait6();
void __sanitizer_syscall_post_impl_wait6();
void __sanitizer_syscall_pre_impl_clock_getcpuclockid2();
void __sanitizer_syscall_post_impl_clock_getcpuclockid2();

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // SANITIZER_NETBSD_SYSCALL_HOOKS_H
