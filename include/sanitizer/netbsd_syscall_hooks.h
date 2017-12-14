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
// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!
//
// Generated with: make_netbsd_syscalls_header.awk
// Generated date: 2017-12-14
// Generated from: syscalls.master,v 1.287 2017/12/08 01:19:29 christos Exp
//
//===----------------------------------------------------------------------===//
#ifndef SANITIZER_NETBSD_SYSCALL_HOOKS_H
#define SANITIZER_NETBSD_SYSCALL_HOOKS_H

#define __sanitizer_syscall_pre_syscall(code, args[SYS_MAXSYSARGS])            \
  __sanitizer_syscall_pre_impl_syscall((long)(code),                           \
                                       (long)(args[SYS_MAXSYSARGS]))
#define __sanitizer_syscall_post_syscall(res, code, args[SYS_MAXSYSARGS])      \
  __sanitizer_syscall_post_impl_syscall(res, (long)(code),                     \
                                        (long)(args[SYS_MAXSYSARGS]))
#define __sanitizer_syscall_pre_exit(rval)                                     \
  __sanitizer_syscall_pre_impl_exit((long)(rval))
#define __sanitizer_syscall_post_exit(res, rval)                               \
  __sanitizer_syscall_post_impl_exit(res, (long)(rval))
#define __sanitizer_syscall_pre_fork() __sanitizer_syscall_pre_impl_fork()
#define __sanitizer_syscall_post_fork(res)                                     \
  __sanitizer_syscall_post_impl_fork(res)
#define __sanitizer_syscall_pre_read(fd, buf, nbyte)                           \
  __sanitizer_syscall_pre_impl_read((long)(fd), (long)(buf), (long)(nbyte))
#define __sanitizer_syscall_post_read(res, fd, buf, nbyte)                     \
  __sanitizer_syscall_post_impl_read(res, (long)(fd), (long)(buf),             \
                                     (long)(nbyte))
#define __sanitizer_syscall_pre_write(fd, buf, nbyte)                          \
  __sanitizer_syscall_pre_impl_write((long)(fd), (long)(buf), (long)(nbyte))
#define __sanitizer_syscall_post_write(res, fd, buf, nbyte)                    \
  __sanitizer_syscall_post_impl_write(res, (long)(fd), (long)(buf),            \
                                      (long)(nbyte))
#define __sanitizer_syscall_pre_open(path, flags, mode)                        \
  __sanitizer_syscall_pre_impl_open((long)(path), (long)(flags), (long)(mode))
#define __sanitizer_syscall_post_open(res, path, flags, mode)                  \
  __sanitizer_syscall_post_impl_open(res, (long)(path), (long)(flags),         \
                                     (long)(mode))
#define __sanitizer_syscall_pre_close(fd)                                      \
  __sanitizer_syscall_pre_impl_close((long)(fd))
#define __sanitizer_syscall_post_close(res, fd)                                \
  __sanitizer_syscall_post_impl_close(res, (long)(fd))
#define __sanitizer_syscall_pre_compat_50_wait4(pid, status, options, rusage)  \
  __sanitizer_syscall_pre_impl_compat_50_wait4(                                \
      (long)(pid), (long)(status), (long)(options), (long)(rusage))
#define __sanitizer_syscall_post_compat_50_wait4(res, pid, status, options,    \
                                                 rusage)                       \
  __sanitizer_syscall_post_impl_compat_50_wait4(                               \
      res, (long)(pid), (long)(status), (long)(options), (long)(rusage))
#define __sanitizer_syscall_pre_compat_43_ocreat(path, mode)                   \
  __sanitizer_syscall_pre_impl_compat_43_ocreat((long)(path), (long)(mode))
#define __sanitizer_syscall_post_compat_43_ocreat(res, path, mode)             \
  __sanitizer_syscall_post_impl_compat_43_ocreat(res, (long)(path),            \
                                                 (long)(mode))
#define __sanitizer_syscall_pre_link(path, link)                               \
  __sanitizer_syscall_pre_impl_link((long)(path), (long)(link))
#define __sanitizer_syscall_post_link(res, path, link)                         \
  __sanitizer_syscall_post_impl_link(res, (long)(path), (long)(link))
#define __sanitizer_syscall_pre_unlink(path)                                   \
  __sanitizer_syscall_pre_impl_unlink((long)(path))
#define __sanitizer_syscall_post_unlink(res, path)                             \
  __sanitizer_syscall_post_impl_unlink(res, (long)(path))
/* syscall 11 has been skipped */
#define __sanitizer_syscall_pre_chdir(path)                                    \
  __sanitizer_syscall_pre_impl_chdir((long)(path))
#define __sanitizer_syscall_post_chdir(res, path)                              \
  __sanitizer_syscall_post_impl_chdir(res, (long)(path))
#define __sanitizer_syscall_pre_fchdir(fd)                                     \
  __sanitizer_syscall_pre_impl_fchdir((long)(fd))
#define __sanitizer_syscall_post_fchdir(res, fd)                               \
  __sanitizer_syscall_post_impl_fchdir(res, (long)(fd))
#define __sanitizer_syscall_pre_compat_50_mknod(path, mode, dev)               \
  __sanitizer_syscall_pre_impl_compat_50_mknod((long)(path), (long)(mode),     \
                                               (long)(dev))
#define __sanitizer_syscall_post_compat_50_mknod(res, path, mode, dev)         \
  __sanitizer_syscall_post_impl_compat_50_mknod(res, (long)(path),             \
                                                (long)(mode), (long)(dev))
#define __sanitizer_syscall_pre_chmod(path, mode)                              \
  __sanitizer_syscall_pre_impl_chmod((long)(path), (long)(mode))
#define __sanitizer_syscall_post_chmod(res, path, mode)                        \
  __sanitizer_syscall_post_impl_chmod(res, (long)(path), (long)(mode))
#define __sanitizer_syscall_pre_chown(path, uid, gid)                          \
  __sanitizer_syscall_pre_impl_chown((long)(path), (long)(uid), (long)(gid))
#define __sanitizer_syscall_post_chown(res, path, uid, gid)                    \
  __sanitizer_syscall_post_impl_chown(res, (long)(path), (long)(uid),          \
                                      (long)(gid))
#define __sanitizer_syscall_pre_break(nsize)                                   \
  __sanitizer_syscall_pre_impl_break((long)(nsize))
#define __sanitizer_syscall_post_break(res, nsize)                             \
  __sanitizer_syscall_post_impl_break(res, (long)(nsize))
#define __sanitizer_syscall_pre_compat_20_getfsstat(buf, bufsize, flags)       \
  __sanitizer_syscall_pre_impl_compat_20_getfsstat(                            \
      (long)(buf), (long)(bufsize), (long)(flags))
#define __sanitizer_syscall_post_compat_20_getfsstat(res, buf, bufsize, flags) \
  __sanitizer_syscall_post_impl_compat_20_getfsstat(                           \
      res, (long)(buf), (long)(bufsize), (long)(flags))
#define __sanitizer_syscall_pre_compat_43_olseek(fd, offset, whence)           \
  __sanitizer_syscall_pre_impl_compat_43_olseek((long)(fd), (long)(offset),    \
                                                (long)(whence))
#define __sanitizer_syscall_post_compat_43_olseek(res, fd, offset, whence)     \
  __sanitizer_syscall_post_impl_compat_43_olseek(                              \
      res, (long)(fd), (long)(offset), (long)(whence))
#define __sanitizer_syscall_pre_getpid() __sanitizer_syscall_pre_impl_getpid()
#define __sanitizer_syscall_post_getpid(res)                                   \
  __sanitizer_syscall_post_impl_getpid(res)
#define __sanitizer_syscall_pre_compat_40_mount(type, path, flags, data)       \
  __sanitizer_syscall_pre_impl_compat_40_mount((long)(type), (long)(path),     \
                                               (long)(flags), (long)(data))
#define __sanitizer_syscall_post_compat_40_mount(res, type, path, flags, data) \
  __sanitizer_syscall_post_impl_compat_40_mount(                               \
      res, (long)(type), (long)(path), (long)(flags), (long)(data))
#define __sanitizer_syscall_pre_unmount(path, flags)                           \
  __sanitizer_syscall_pre_impl_unmount((long)(path), (long)(flags))
#define __sanitizer_syscall_post_unmount(res, path, flags)                     \
  __sanitizer_syscall_post_impl_unmount(res, (long)(path), (long)(flags))
#define __sanitizer_syscall_pre_setuid(uid)                                    \
  __sanitizer_syscall_pre_impl_setuid((long)(uid))
#define __sanitizer_syscall_post_setuid(res, uid)                              \
  __sanitizer_syscall_post_impl_setuid(res, (long)(uid))
#define __sanitizer_syscall_pre_getuid() __sanitizer_syscall_pre_impl_getuid()
#define __sanitizer_syscall_post_getuid(res)                                   \
  __sanitizer_syscall_post_impl_getuid(res)
#define __sanitizer_syscall_pre_geteuid() __sanitizer_syscall_pre_impl_geteuid()
#define __sanitizer_syscall_post_geteuid(res)                                  \
  __sanitizer_syscall_post_impl_geteuid(res)
#define __sanitizer_syscall_pre_ptrace(req, pid, addr, data)                   \
  __sanitizer_syscall_pre_impl_ptrace((long)(req), (long)(pid), (long)(addr),  \
                                      (long)(data))
#define __sanitizer_syscall_post_ptrace(res, req, pid, addr, data)             \
  __sanitizer_syscall_post_impl_ptrace(res, (long)(req), (long)(pid),          \
                                       (long)(addr), (long)(data))
#define __sanitizer_syscall_pre_recvmsg(s, msg, flags)                         \
  __sanitizer_syscall_pre_impl_recvmsg((long)(s), (long)(msg), (long)(flags))
#define __sanitizer_syscall_post_recvmsg(res, s, msg, flags)                   \
  __sanitizer_syscall_post_impl_recvmsg(res, (long)(s), (long)(msg),           \
                                        (long)(flags))
#define __sanitizer_syscall_pre_sendmsg(s, msg, flags)                         \
  __sanitizer_syscall_pre_impl_sendmsg((long)(s), (long)(msg), (long)(flags))
#define __sanitizer_syscall_post_sendmsg(res, s, msg, flags)                   \
  __sanitizer_syscall_post_impl_sendmsg(res, (long)(s), (long)(msg),           \
                                        (long)(flags))
#define __sanitizer_syscall_pre_recvfrom(s, buf, len, flags, from,             \
                                         fromlenaddr)                          \
  __sanitizer_syscall_pre_impl_recvfrom((long)(s), (long)(buf), (long)(len),   \
                                        (long)(flags), (long)(from),           \
                                        (long)(fromlenaddr))
#define __sanitizer_syscall_post_recvfrom(res, s, buf, len, flags, from,       \
                                          fromlenaddr)                         \
  __sanitizer_syscall_post_impl_recvfrom(res, (long)(s), (long)(buf),          \
                                         (long)(len), (long)(flags),           \
                                         (long)(from), (long)(fromlenaddr))
#define __sanitizer_syscall_pre_accept(s, name, anamelen)                      \
  __sanitizer_syscall_pre_impl_accept((long)(s), (long)(name), (long)(anamelen))
#define __sanitizer_syscall_post_accept(res, s, name, anamelen)                \
  __sanitizer_syscall_post_impl_accept(res, (long)(s), (long)(name),           \
                                       (long)(anamelen))
#define __sanitizer_syscall_pre_getpeername(fdes, asa, alen)                   \
  __sanitizer_syscall_pre_impl_getpeername((long)(fdes), (long)(asa),          \
                                           (long)(alen))
#define __sanitizer_syscall_post_getpeername(res, fdes, asa, alen)             \
  __sanitizer_syscall_post_impl_getpeername(res, (long)(fdes), (long)(asa),    \
                                            (long)(alen))
#define __sanitizer_syscall_pre_getsockname(fdes, asa, alen)                   \
  __sanitizer_syscall_pre_impl_getsockname((long)(fdes), (long)(asa),          \
                                           (long)(alen))
#define __sanitizer_syscall_post_getsockname(res, fdes, asa, alen)             \
  __sanitizer_syscall_post_impl_getsockname(res, (long)(fdes), (long)(asa),    \
                                            (long)(alen))
#define __sanitizer_syscall_pre_access(path, flags)                            \
  __sanitizer_syscall_pre_impl_access((long)(path), (long)(flags))
#define __sanitizer_syscall_post_access(res, path, flags)                      \
  __sanitizer_syscall_post_impl_access(res, (long)(path), (long)(flags))
#define __sanitizer_syscall_pre_chflags(path, flags)                           \
  __sanitizer_syscall_pre_impl_chflags((long)(path), (long)(flags))
#define __sanitizer_syscall_post_chflags(res, path, flags)                     \
  __sanitizer_syscall_post_impl_chflags(res, (long)(path), (long)(flags))
#define __sanitizer_syscall_pre_fchflags(fd, flags)                            \
  __sanitizer_syscall_pre_impl_fchflags((long)(fd), (long)(flags))
#define __sanitizer_syscall_post_fchflags(res, fd, flags)                      \
  __sanitizer_syscall_post_impl_fchflags(res, (long)(fd), (long)(flags))
#define __sanitizer_syscall_pre_sync() __sanitizer_syscall_pre_impl_sync()
#define __sanitizer_syscall_post_sync(res)                                     \
  __sanitizer_syscall_post_impl_sync(res)
#define __sanitizer_syscall_pre_kill(pid, signum)                              \
  __sanitizer_syscall_pre_impl_kill((long)(pid), (long)(signum))
#define __sanitizer_syscall_post_kill(res, pid, signum)                        \
  __sanitizer_syscall_post_impl_kill(res, (long)(pid), (long)(signum))
#define __sanitizer_syscall_pre_compat_43_stat43(path, ub)                     \
  __sanitizer_syscall_pre_impl_compat_43_stat43((long)(path), (long)(ub))
#define __sanitizer_syscall_post_compat_43_stat43(res, path, ub)               \
  __sanitizer_syscall_post_impl_compat_43_stat43(res, (long)(path), (long)(ub))
#define __sanitizer_syscall_pre_getppid() __sanitizer_syscall_pre_impl_getppid()
#define __sanitizer_syscall_post_getppid(res)                                  \
  __sanitizer_syscall_post_impl_getppid(res)
#define __sanitizer_syscall_pre_compat_43_lstat43(path, ub)                    \
  __sanitizer_syscall_pre_impl_compat_43_lstat43((long)(path), (long)(ub))
#define __sanitizer_syscall_post_compat_43_lstat43(res, path, ub)              \
  __sanitizer_syscall_post_impl_compat_43_lstat43(res, (long)(path), (long)(ub))
#define __sanitizer_syscall_pre_dup(fd)                                        \
  __sanitizer_syscall_pre_impl_dup((long)(fd))
#define __sanitizer_syscall_post_dup(res, fd)                                  \
  __sanitizer_syscall_post_impl_dup(res, (long)(fd))
#define __sanitizer_syscall_pre_pipe() __sanitizer_syscall_pre_impl_pipe()
#define __sanitizer_syscall_post_pipe(res)                                     \
  __sanitizer_syscall_post_impl_pipe(res)
#define __sanitizer_syscall_pre_getegid() __sanitizer_syscall_pre_impl_getegid()
#define __sanitizer_syscall_post_getegid(res)                                  \
  __sanitizer_syscall_post_impl_getegid(res)
#define __sanitizer_syscall_pre_profil(samples, size, offset, scale)           \
  __sanitizer_syscall_pre_impl_profil((long)(samples), (long)(size),           \
                                      (long)(offset), (long)(scale))
#define __sanitizer_syscall_post_profil(res, samples, size, offset, scale)     \
  __sanitizer_syscall_post_impl_profil(res, (long)(samples), (long)(size),     \
                                       (long)(offset), (long)(scale))
#define __sanitizer_syscall_pre_ktrace(fname, ops, facs, pid)                  \
  __sanitizer_syscall_pre_impl_ktrace((long)(fname), (long)(ops),              \
                                      (long)(facs), (long)(pid))
#define __sanitizer_syscall_post_ktrace(res, fname, ops, facs, pid)            \
  __sanitizer_syscall_post_impl_ktrace(res, (long)(fname), (long)(ops),        \
                                       (long)(facs), (long)(pid))
#define __sanitizer_syscall_pre_compat_13_sigaction13(signum, nsa, osa)        \
  __sanitizer_syscall_pre_impl_compat_13_sigaction13((long)(signum),           \
                                                     (long)(nsa), (long)(osa))
#define __sanitizer_syscall_post_compat_13_sigaction13(res, signum, nsa, osa)  \
  __sanitizer_syscall_post_impl_compat_13_sigaction13(                         \
      res, (long)(signum), (long)(nsa), (long)(osa))
#define __sanitizer_syscall_pre_getgid() __sanitizer_syscall_pre_impl_getgid()
#define __sanitizer_syscall_post_getgid(res)                                   \
  __sanitizer_syscall_post_impl_getgid(res)
#define __sanitizer_syscall_pre_compat_13_sigprocmask13(how, mask)             \
  __sanitizer_syscall_pre_impl_compat_13_sigprocmask13((long)(how),            \
                                                       (long)(mask))
#define __sanitizer_syscall_post_compat_13_sigprocmask13(res, how, mask)       \
  __sanitizer_syscall_post_impl_compat_13_sigprocmask13(res, (long)(how),      \
                                                        (long)(mask))
#define __sanitizer_syscall_pre___getlogin(namebuf, namelen)                   \
  __sanitizer_syscall_pre_impl___getlogin((long)(namebuf), (long)(namelen))
#define __sanitizer_syscall_post___getlogin(res, namebuf, namelen)             \
  __sanitizer_syscall_post_impl___getlogin(res, (long)(namebuf),               \
                                           (long)(namelen))
#define __sanitizer_syscall_pre___setlogin(namebuf)                            \
  __sanitizer_syscall_pre_impl___setlogin((long)(namebuf))
#define __sanitizer_syscall_post___setlogin(res, namebuf)                      \
  __sanitizer_syscall_post_impl___setlogin(res, (long)(namebuf))
#define __sanitizer_syscall_pre_acct(path)                                     \
  __sanitizer_syscall_pre_impl_acct((long)(path))
#define __sanitizer_syscall_post_acct(res, path)                               \
  __sanitizer_syscall_post_impl_acct(res, (long)(path))
#define __sanitizer_syscall_pre_compat_13_sigpending13()                       \
  __sanitizer_syscall_pre_impl_compat_13_sigpending13()
#define __sanitizer_syscall_post_compat_13_sigpending13(res)                   \
  __sanitizer_syscall_post_impl_compat_13_sigpending13(res)
#define __sanitizer_syscall_pre_compat_13_sigaltstack13(nss, oss)              \
  __sanitizer_syscall_pre_impl_compat_13_sigaltstack13((long)(nss), (long)(oss))
#define __sanitizer_syscall_post_compat_13_sigaltstack13(res, nss, oss)        \
  __sanitizer_syscall_post_impl_compat_13_sigaltstack13(res, (long)(nss),      \
                                                        (long)(oss))
#define __sanitizer_syscall_pre_ioctl(fd, com, data)                           \
  __sanitizer_syscall_pre_impl_ioctl((long)(fd), (long)(com), (long)(data))
#define __sanitizer_syscall_post_ioctl(res, fd, com, data)                     \
  __sanitizer_syscall_post_impl_ioctl(res, (long)(fd), (long)(com),            \
                                      (long)(data))
#define __sanitizer_syscall_pre_compat_12_oreboot(opt)                         \
  __sanitizer_syscall_pre_impl_compat_12_oreboot((long)(opt))
#define __sanitizer_syscall_post_compat_12_oreboot(res, opt)                   \
  __sanitizer_syscall_post_impl_compat_12_oreboot(res, (long)(opt))
#define __sanitizer_syscall_pre_revoke(path)                                   \
  __sanitizer_syscall_pre_impl_revoke((long)(path))
#define __sanitizer_syscall_post_revoke(res, path)                             \
  __sanitizer_syscall_post_impl_revoke(res, (long)(path))
#define __sanitizer_syscall_pre_symlink(path, link)                            \
  __sanitizer_syscall_pre_impl_symlink((long)(path), (long)(link))
#define __sanitizer_syscall_post_symlink(res, path, link)                      \
  __sanitizer_syscall_post_impl_symlink(res, (long)(path), (long)(link))
#define __sanitizer_syscall_pre_readlink(path, buf, count)                     \
  __sanitizer_syscall_pre_impl_readlink((long)(path), (long)(buf),             \
                                        (long)(count))
#define __sanitizer_syscall_post_readlink(res, path, buf, count)               \
  __sanitizer_syscall_post_impl_readlink(res, (long)(path), (long)(buf),       \
                                         (long)(count))
#define __sanitizer_syscall_pre_execve(path, argp, envp)                       \
  __sanitizer_syscall_pre_impl_execve((long)(path), (long)(argp), (long)(envp))
#define __sanitizer_syscall_post_execve(res, path, argp, envp)                 \
  __sanitizer_syscall_post_impl_execve(res, (long)(path), (long)(argp),        \
                                       (long)(envp))
#define __sanitizer_syscall_pre_umask(newmask)                                 \
  __sanitizer_syscall_pre_impl_umask((long)(newmask))
#define __sanitizer_syscall_post_umask(res, newmask)                           \
  __sanitizer_syscall_post_impl_umask(res, (long)(newmask))
#define __sanitizer_syscall_pre_chroot(path)                                   \
  __sanitizer_syscall_pre_impl_chroot((long)(path))
#define __sanitizer_syscall_post_chroot(res, path)                             \
  __sanitizer_syscall_post_impl_chroot(res, (long)(path))
#define __sanitizer_syscall_pre_compat_43_fstat43(fd, sb)                      \
  __sanitizer_syscall_pre_impl_compat_43_fstat43((long)(fd), (long)(sb))
#define __sanitizer_syscall_post_compat_43_fstat43(res, fd, sb)                \
  __sanitizer_syscall_post_impl_compat_43_fstat43(res, (long)(fd), (long)(sb))
#define __sanitizer_syscall_pre_compat_43_ogetkerninfo(op, where, size, arg)   \
  __sanitizer_syscall_pre_impl_compat_43_ogetkerninfo(                         \
      (long)(op), (long)(where), (long)(size), (long)(arg))
#define __sanitizer_syscall_post_compat_43_ogetkerninfo(res, op, where, size,  \
                                                        arg)                   \
  __sanitizer_syscall_post_impl_compat_43_ogetkerninfo(                        \
      res, (long)(op), (long)(where), (long)(size), (long)(arg))
#define __sanitizer_syscall_pre_compat_43_ogetpagesize()                       \
  __sanitizer_syscall_pre_impl_compat_43_ogetpagesize()
#define __sanitizer_syscall_post_compat_43_ogetpagesize(res)                   \
  __sanitizer_syscall_post_impl_compat_43_ogetpagesize(res)
#define __sanitizer_syscall_pre_compat_12_msync(addr, len)                     \
  __sanitizer_syscall_pre_impl_compat_12_msync((long)(addr), (long)(len))
#define __sanitizer_syscall_post_compat_12_msync(res, addr, len)               \
  __sanitizer_syscall_post_impl_compat_12_msync(res, (long)(addr), (long)(len))
#define __sanitizer_syscall_pre_vfork() __sanitizer_syscall_pre_impl_vfork()
#define __sanitizer_syscall_post_vfork(res)                                    \
  __sanitizer_syscall_post_impl_vfork(res)
/* syscall 67 has been skipped */
/* syscall 68 has been skipped */
#define __sanitizer_syscall_pre_sbrk(incr)                                     \
  __sanitizer_syscall_pre_impl_sbrk((long)(incr))
#define __sanitizer_syscall_post_sbrk(res, incr)                               \
  __sanitizer_syscall_post_impl_sbrk(res, (long)(incr))
#define __sanitizer_syscall_pre_sstk(incr)                                     \
  __sanitizer_syscall_pre_impl_sstk((long)(incr))
#define __sanitizer_syscall_post_sstk(res, incr)                               \
  __sanitizer_syscall_post_impl_sstk(res, (long)(incr))
#define __sanitizer_syscall_pre_compat_43_ommap(addr, len, prot, flags, fd,    \
                                                pos)                           \
  __sanitizer_syscall_pre_impl_compat_43_ommap((long)(addr), (long)(len),      \
                                               (long)(prot), (long)(flags),    \
                                               (long)(fd), (long)(pos))
#define __sanitizer_syscall_post_compat_43_ommap(res, addr, len, prot, flags,  \
                                                 fd, pos)                      \
  __sanitizer_syscall_post_impl_compat_43_ommap(                               \
      res, (long)(addr), (long)(len), (long)(prot), (long)(flags), (long)(fd), \
      (long)(pos))
#define __sanitizer_syscall_pre_vadvise(anom)                                  \
  __sanitizer_syscall_pre_impl_vadvise((long)(anom))
#define __sanitizer_syscall_post_vadvise(res, anom)                            \
  __sanitizer_syscall_post_impl_vadvise(res, (long)(anom))
#define __sanitizer_syscall_pre_munmap(addr, len)                              \
  __sanitizer_syscall_pre_impl_munmap((long)(addr), (long)(len))
#define __sanitizer_syscall_post_munmap(res, addr, len)                        \
  __sanitizer_syscall_post_impl_munmap(res, (long)(addr), (long)(len))
#define __sanitizer_syscall_pre_mprotect(addr, len, prot)                      \
  __sanitizer_syscall_pre_impl_mprotect((long)(addr), (long)(len), (long)(prot))
#define __sanitizer_syscall_post_mprotect(res, addr, len, prot)                \
  __sanitizer_syscall_post_impl_mprotect(res, (long)(addr), (long)(len),       \
                                         (long)(prot))
#define __sanitizer_syscall_pre_madvise(addr, len, behav)                      \
  __sanitizer_syscall_pre_impl_madvise((long)(addr), (long)(len), (long)(behav))
#define __sanitizer_syscall_post_madvise(res, addr, len, behav)                \
  __sanitizer_syscall_post_impl_madvise(res, (long)(addr), (long)(len),        \
                                        (long)(behav))
/* syscall 76 has been skipped */
/* syscall 77 has been skipped */
#define __sanitizer_syscall_pre_mincore(addr, len, vec)                        \
  __sanitizer_syscall_pre_impl_mincore((long)(addr), (long)(len), (long)(vec))
#define __sanitizer_syscall_post_mincore(res, addr, len, vec)                  \
  __sanitizer_syscall_post_impl_mincore(res, (long)(addr), (long)(len),        \
                                        (long)(vec))
#define __sanitizer_syscall_pre_getgroups(gidsetsize, gidset)                  \
  __sanitizer_syscall_pre_impl_getgroups((long)(gidsetsize), (long)(gidset))
#define __sanitizer_syscall_post_getgroups(res, gidsetsize, gidset)            \
  __sanitizer_syscall_post_impl_getgroups(res, (long)(gidsetsize),             \
                                          (long)(gidset))
#define __sanitizer_syscall_pre_setgroups(gidsetsize, gidset)                  \
  __sanitizer_syscall_pre_impl_setgroups((long)(gidsetsize), (long)(gidset))
#define __sanitizer_syscall_post_setgroups(res, gidsetsize, gidset)            \
  __sanitizer_syscall_post_impl_setgroups(res, (long)(gidsetsize),             \
                                          (long)(gidset))
#define __sanitizer_syscall_pre_getpgrp() __sanitizer_syscall_pre_impl_getpgrp()
#define __sanitizer_syscall_post_getpgrp(res)                                  \
  __sanitizer_syscall_post_impl_getpgrp(res)
#define __sanitizer_syscall_pre_setpgid(pid, pgid)                             \
  __sanitizer_syscall_pre_impl_setpgid((long)(pid), (long)(pgid))
#define __sanitizer_syscall_post_setpgid(res, pid, pgid)                       \
  __sanitizer_syscall_post_impl_setpgid(res, (long)(pid), (long)(pgid))
#define __sanitizer_syscall_pre_compat_50_setitimer(which, itv, oitv)          \
  __sanitizer_syscall_pre_impl_compat_50_setitimer((long)(which), (long)(itv), \
                                                   (long)(oitv))
#define __sanitizer_syscall_post_compat_50_setitimer(res, which, itv, oitv)    \
  __sanitizer_syscall_post_impl_compat_50_setitimer(res, (long)(which),        \
                                                    (long)(itv), (long)(oitv))
#define __sanitizer_syscall_pre_compat_43_owait()                              \
  __sanitizer_syscall_pre_impl_compat_43_owait()
#define __sanitizer_syscall_post_compat_43_owait(res)                          \
  __sanitizer_syscall_post_impl_compat_43_owait(res)
#define __sanitizer_syscall_pre_compat_12_oswapon(name)                        \
  __sanitizer_syscall_pre_impl_compat_12_oswapon((long)(name))
#define __sanitizer_syscall_post_compat_12_oswapon(res, name)                  \
  __sanitizer_syscall_post_impl_compat_12_oswapon(res, (long)(name))
#define __sanitizer_syscall_pre_compat_50_getitimer(which, itv)                \
  __sanitizer_syscall_pre_impl_compat_50_getitimer((long)(which), (long)(itv))
#define __sanitizer_syscall_post_compat_50_getitimer(res, which, itv)          \
  __sanitizer_syscall_post_impl_compat_50_getitimer(res, (long)(which),        \
                                                    (long)(itv))
#define __sanitizer_syscall_pre_compat_43_ogethostname(hostname, len)          \
  __sanitizer_syscall_pre_impl_compat_43_ogethostname((long)(hostname),        \
                                                      (long)(len))
#define __sanitizer_syscall_post_compat_43_ogethostname(res, hostname, len)    \
  __sanitizer_syscall_post_impl_compat_43_ogethostname(res, (long)(hostname),  \
                                                       (long)(len))
#define __sanitizer_syscall_pre_compat_43_osethostname(hostname, len)          \
  __sanitizer_syscall_pre_impl_compat_43_osethostname((long)(hostname),        \
                                                      (long)(len))
#define __sanitizer_syscall_post_compat_43_osethostname(res, hostname, len)    \
  __sanitizer_syscall_post_impl_compat_43_osethostname(res, (long)(hostname),  \
                                                       (long)(len))
#define __sanitizer_syscall_pre_compat_43_ogetdtablesize()                     \
  __sanitizer_syscall_pre_impl_compat_43_ogetdtablesize()
#define __sanitizer_syscall_post_compat_43_ogetdtablesize(res)                 \
  __sanitizer_syscall_post_impl_compat_43_ogetdtablesize(res)
#define __sanitizer_syscall_pre_dup2(from, to)                                 \
  __sanitizer_syscall_pre_impl_dup2((long)(from), (long)(to))
#define __sanitizer_syscall_post_dup2(res, from, to)                           \
  __sanitizer_syscall_post_impl_dup2(res, (long)(from), (long)(to))
/* syscall 91 has been skipped */
#define __sanitizer_syscall_pre_fcntl(fd, cmd, arg)                            \
  __sanitizer_syscall_pre_impl_fcntl((long)(fd), (long)(cmd), (long)(arg))
#define __sanitizer_syscall_post_fcntl(res, fd, cmd, arg)                      \
  __sanitizer_syscall_post_impl_fcntl(res, (long)(fd), (long)(cmd), (long)(arg))
#define __sanitizer_syscall_pre_compat_50_select(nd, in, ou, ex, tv)           \
  __sanitizer_syscall_pre_impl_compat_50_select(                               \
      (long)(nd), (long)(in), (long)(ou), (long)(ex), (long)(tv))
#define __sanitizer_syscall_post_compat_50_select(res, nd, in, ou, ex, tv)     \
  __sanitizer_syscall_post_impl_compat_50_select(                              \
      res, (long)(nd), (long)(in), (long)(ou), (long)(ex), (long)(tv))
/* syscall 94 has been skipped */
#define __sanitizer_syscall_pre_fsync(fd)                                      \
  __sanitizer_syscall_pre_impl_fsync((long)(fd))
#define __sanitizer_syscall_post_fsync(res, fd)                                \
  __sanitizer_syscall_post_impl_fsync(res, (long)(fd))
#define __sanitizer_syscall_pre_setpriority(which, who, prio)                  \
  __sanitizer_syscall_pre_impl_setpriority((long)(which), (long)(who),         \
                                           (long)(prio))
#define __sanitizer_syscall_post_setpriority(res, which, who, prio)            \
  __sanitizer_syscall_post_impl_setpriority(res, (long)(which), (long)(who),   \
                                            (long)(prio))
#define __sanitizer_syscall_pre_compat_30_socket(domain, type, protocol)       \
  __sanitizer_syscall_pre_impl_compat_30_socket((long)(domain), (long)(type),  \
                                                (long)(protocol))
#define __sanitizer_syscall_post_compat_30_socket(res, domain, type, protocol) \
  __sanitizer_syscall_post_impl_compat_30_socket(                              \
      res, (long)(domain), (long)(type), (long)(protocol))
#define __sanitizer_syscall_pre_connect(s, name, namelen)                      \
  __sanitizer_syscall_pre_impl_connect((long)(s), (long)(name), (long)(namelen))
#define __sanitizer_syscall_post_connect(res, s, name, namelen)                \
  __sanitizer_syscall_post_impl_connect(res, (long)(s), (long)(name),          \
                                        (long)(namelen))
#define __sanitizer_syscall_pre_compat_43_oaccept(s, name, anamelen)           \
  __sanitizer_syscall_pre_impl_compat_43_oaccept((long)(s), (long)(name),      \
                                                 (long)(anamelen))
#define __sanitizer_syscall_post_compat_43_oaccept(res, s, name, anamelen)     \
  __sanitizer_syscall_post_impl_compat_43_oaccept(                             \
      res, (long)(s), (long)(name), (long)(anamelen))
#define __sanitizer_syscall_pre_getpriority(which, who)                        \
  __sanitizer_syscall_pre_impl_getpriority((long)(which), (long)(who))
#define __sanitizer_syscall_post_getpriority(res, which, who)                  \
  __sanitizer_syscall_post_impl_getpriority(res, (long)(which), (long)(who))
#define __sanitizer_syscall_pre_compat_43_osend(s, buf, len, flags)            \
  __sanitizer_syscall_pre_impl_compat_43_osend((long)(s), (long)(buf),         \
                                               (long)(len), (long)(flags))
#define __sanitizer_syscall_post_compat_43_osend(res, s, buf, len, flags)      \
  __sanitizer_syscall_post_impl_compat_43_osend(res, (long)(s), (long)(buf),   \
                                                (long)(len), (long)(flags))
#define __sanitizer_syscall_pre_compat_43_orecv(s, buf, len, flags)            \
  __sanitizer_syscall_pre_impl_compat_43_orecv((long)(s), (long)(buf),         \
                                               (long)(len), (long)(flags))
#define __sanitizer_syscall_post_compat_43_orecv(res, s, buf, len, flags)      \
  __sanitizer_syscall_post_impl_compat_43_orecv(res, (long)(s), (long)(buf),   \
                                                (long)(len), (long)(flags))
#define __sanitizer_syscall_pre_compat_13_sigreturn13(sigcntxp)                \
  __sanitizer_syscall_pre_impl_compat_13_sigreturn13((long)(sigcntxp))
#define __sanitizer_syscall_post_compat_13_sigreturn13(res, sigcntxp)          \
  __sanitizer_syscall_post_impl_compat_13_sigreturn13(res, (long)(sigcntxp))
#define __sanitizer_syscall_pre_bind(s, name, namelen)                         \
  __sanitizer_syscall_pre_impl_bind((long)(s), (long)(name), (long)(namelen))
#define __sanitizer_syscall_post_bind(res, s, name, namelen)                   \
  __sanitizer_syscall_post_impl_bind(res, (long)(s), (long)(name),             \
                                     (long)(namelen))
#define __sanitizer_syscall_pre_setsockopt(s, level, name, val, valsize)       \
  __sanitizer_syscall_pre_impl_setsockopt(                                     \
      (long)(s), (long)(level), (long)(name), (long)(val), (long)(valsize))
#define __sanitizer_syscall_post_setsockopt(res, s, level, name, val, valsize) \
  __sanitizer_syscall_post_impl_setsockopt(res, (long)(s), (long)(level),      \
                                           (long)(name), (long)(val),          \
                                           (long)(valsize))
#define __sanitizer_syscall_pre_listen(s, backlog)                             \
  __sanitizer_syscall_pre_impl_listen((long)(s), (long)(backlog))
#define __sanitizer_syscall_post_listen(res, s, backlog)                       \
  __sanitizer_syscall_post_impl_listen(res, (long)(s), (long)(backlog))
/* syscall 107 has been skipped */
#define __sanitizer_syscall_pre_compat_43_osigvec(signum, nsv, osv)            \
  __sanitizer_syscall_pre_impl_compat_43_osigvec((long)(signum), (long)(nsv),  \
                                                 (long)(osv))
#define __sanitizer_syscall_post_compat_43_osigvec(res, signum, nsv, osv)      \
  __sanitizer_syscall_post_impl_compat_43_osigvec(res, (long)(signum),         \
                                                  (long)(nsv), (long)(osv))
#define __sanitizer_syscall_pre_compat_43_osigblock(mask)                      \
  __sanitizer_syscall_pre_impl_compat_43_osigblock((long)(mask))
#define __sanitizer_syscall_post_compat_43_osigblock(res, mask)                \
  __sanitizer_syscall_post_impl_compat_43_osigblock(res, (long)(mask))
#define __sanitizer_syscall_pre_compat_43_osigsetmask(mask)                    \
  __sanitizer_syscall_pre_impl_compat_43_osigsetmask((long)(mask))
#define __sanitizer_syscall_post_compat_43_osigsetmask(res, mask)              \
  __sanitizer_syscall_post_impl_compat_43_osigsetmask(res, (long)(mask))
#define __sanitizer_syscall_pre_compat_13_sigsuspend13(mask)                   \
  __sanitizer_syscall_pre_impl_compat_13_sigsuspend13((long)(mask))
#define __sanitizer_syscall_post_compat_13_sigsuspend13(res, mask)             \
  __sanitizer_syscall_post_impl_compat_13_sigsuspend13(res, (long)(mask))
#define __sanitizer_syscall_pre_compat_43_osigstack(nss, oss)                  \
  __sanitizer_syscall_pre_impl_compat_43_osigstack((long)(nss), (long)(oss))
#define __sanitizer_syscall_post_compat_43_osigstack(res, nss, oss)            \
  __sanitizer_syscall_post_impl_compat_43_osigstack(res, (long)(nss),          \
                                                    (long)(oss))
#define __sanitizer_syscall_pre_compat_43_orecvmsg(s, msg, flags)              \
  __sanitizer_syscall_pre_impl_compat_43_orecvmsg((long)(s), (long)(msg),      \
                                                  (long)(flags))
#define __sanitizer_syscall_post_compat_43_orecvmsg(res, s, msg, flags)        \
  __sanitizer_syscall_post_impl_compat_43_orecvmsg(res, (long)(s),             \
                                                   (long)(msg), (long)(flags))
#define __sanitizer_syscall_pre_compat_43_osendmsg(s, msg, flags)              \
  __sanitizer_syscall_pre_impl_compat_43_osendmsg((long)(s), (long)(msg),      \
                                                  (long)(flags))
#define __sanitizer_syscall_post_compat_43_osendmsg(res, s, msg, flags)        \
  __sanitizer_syscall_post_impl_compat_43_osendmsg(res, (long)(s),             \
                                                   (long)(msg), (long)(flags))
/* syscall 115 has been skipped */
#define __sanitizer_syscall_pre_compat_50_gettimeofday(tp, tzp)                \
  __sanitizer_syscall_pre_impl_compat_50_gettimeofday((long)(tp), (long)(tzp))
#define __sanitizer_syscall_post_compat_50_gettimeofday(res, tp, tzp)          \
  __sanitizer_syscall_post_impl_compat_50_gettimeofday(res, (long)(tp),        \
                                                       (long)(tzp))
#define __sanitizer_syscall_pre_compat_50_getrusage(who, rusage)               \
  __sanitizer_syscall_pre_impl_compat_50_getrusage((long)(who), (long)(rusage))
#define __sanitizer_syscall_post_compat_50_getrusage(res, who, rusage)         \
  __sanitizer_syscall_post_impl_compat_50_getrusage(res, (long)(who),          \
                                                    (long)(rusage))
#define __sanitizer_syscall_pre_getsockopt(s, level, name, val, avalsize)      \
  __sanitizer_syscall_pre_impl_getsockopt(                                     \
      (long)(s), (long)(level), (long)(name), (long)(val), (long)(avalsize))
#define __sanitizer_syscall_post_getsockopt(res, s, level, name, val,          \
                                            avalsize)                          \
  __sanitizer_syscall_post_impl_getsockopt(res, (long)(s), (long)(level),      \
                                           (long)(name), (long)(val),          \
                                           (long)(avalsize))
/* syscall 119 has been skipped */
#define __sanitizer_syscall_pre_readv(fd, iovp, iovcnt)                        \
  __sanitizer_syscall_pre_impl_readv((long)(fd), (long)(iovp), (long)(iovcnt))
#define __sanitizer_syscall_post_readv(res, fd, iovp, iovcnt)                  \
  __sanitizer_syscall_post_impl_readv(res, (long)(fd), (long)(iovp),           \
                                      (long)(iovcnt))
#define __sanitizer_syscall_pre_writev(fd, iovp, iovcnt)                       \
  __sanitizer_syscall_pre_impl_writev((long)(fd), (long)(iovp), (long)(iovcnt))
#define __sanitizer_syscall_post_writev(res, fd, iovp, iovcnt)                 \
  __sanitizer_syscall_post_impl_writev(res, (long)(fd), (long)(iovp),          \
                                       (long)(iovcnt))
#define __sanitizer_syscall_pre_compat_50_settimeofday(tv, tzp)                \
  __sanitizer_syscall_pre_impl_compat_50_settimeofday((long)(tv), (long)(tzp))
#define __sanitizer_syscall_post_compat_50_settimeofday(res, tv, tzp)          \
  __sanitizer_syscall_post_impl_compat_50_settimeofday(res, (long)(tv),        \
                                                       (long)(tzp))
#define __sanitizer_syscall_pre_fchown(fd, uid, gid)                           \
  __sanitizer_syscall_pre_impl_fchown((long)(fd), (long)(uid), (long)(gid))
#define __sanitizer_syscall_post_fchown(res, fd, uid, gid)                     \
  __sanitizer_syscall_post_impl_fchown(res, (long)(fd), (long)(uid),           \
                                       (long)(gid))
#define __sanitizer_syscall_pre_fchmod(fd, mode)                               \
  __sanitizer_syscall_pre_impl_fchmod((long)(fd), (long)(mode))
#define __sanitizer_syscall_post_fchmod(res, fd, mode)                         \
  __sanitizer_syscall_post_impl_fchmod(res, (long)(fd), (long)(mode))
#define __sanitizer_syscall_pre_compat_43_orecvfrom(s, buf, len, flags, from,  \
                                                    fromlenaddr)               \
  __sanitizer_syscall_pre_impl_compat_43_orecvfrom(                            \
      (long)(s), (long)(buf), (long)(len), (long)(flags), (long)(from),        \
      (long)(fromlenaddr))
#define __sanitizer_syscall_post_compat_43_orecvfrom(res, s, buf, len, flags,  \
                                                     from, fromlenaddr)        \
  __sanitizer_syscall_post_impl_compat_43_orecvfrom(                           \
      res, (long)(s), (long)(buf), (long)(len), (long)(flags), (long)(from),   \
      (long)(fromlenaddr))
#define __sanitizer_syscall_pre_setreuid(ruid, euid)                           \
  __sanitizer_syscall_pre_impl_setreuid((long)(ruid), (long)(euid))
#define __sanitizer_syscall_post_setreuid(res, ruid, euid)                     \
  __sanitizer_syscall_post_impl_setreuid(res, (long)(ruid), (long)(euid))
#define __sanitizer_syscall_pre_setregid(rgid, egid)                           \
  __sanitizer_syscall_pre_impl_setregid((long)(rgid), (long)(egid))
#define __sanitizer_syscall_post_setregid(res, rgid, egid)                     \
  __sanitizer_syscall_post_impl_setregid(res, (long)(rgid), (long)(egid))
#define __sanitizer_syscall_pre_rename(from, to)                               \
  __sanitizer_syscall_pre_impl_rename((long)(from), (long)(to))
#define __sanitizer_syscall_post_rename(res, from, to)                         \
  __sanitizer_syscall_post_impl_rename(res, (long)(from), (long)(to))
#define __sanitizer_syscall_pre_compat_43_otruncate(path, length)              \
  __sanitizer_syscall_pre_impl_compat_43_otruncate((long)(path), (long)(length))
#define __sanitizer_syscall_post_compat_43_otruncate(res, path, length)        \
  __sanitizer_syscall_post_impl_compat_43_otruncate(res, (long)(path),         \
                                                    (long)(length))
#define __sanitizer_syscall_pre_compat_43_oftruncate(fd, length)               \
  __sanitizer_syscall_pre_impl_compat_43_oftruncate((long)(fd), (long)(length))
#define __sanitizer_syscall_post_compat_43_oftruncate(res, fd, length)         \
  __sanitizer_syscall_post_impl_compat_43_oftruncate(res, (long)(fd),          \
                                                     (long)(length))
#define __sanitizer_syscall_pre_flock(fd, how)                                 \
  __sanitizer_syscall_pre_impl_flock((long)(fd), (long)(how))
#define __sanitizer_syscall_post_flock(res, fd, how)                           \
  __sanitizer_syscall_post_impl_flock(res, (long)(fd), (long)(how))
#define __sanitizer_syscall_pre_mkfifo(path, mode)                             \
  __sanitizer_syscall_pre_impl_mkfifo((long)(path), (long)(mode))
#define __sanitizer_syscall_post_mkfifo(res, path, mode)                       \
  __sanitizer_syscall_post_impl_mkfifo(res, (long)(path), (long)(mode))
#define __sanitizer_syscall_pre_sendto(s, buf, len, flags, to, tolen)          \
  __sanitizer_syscall_pre_impl_sendto((long)(s), (long)(buf), (long)(len),     \
                                      (long)(flags), (long)(to),               \
                                      (long)(tolen))
#define __sanitizer_syscall_post_sendto(res, s, buf, len, flags, to, tolen)    \
  __sanitizer_syscall_post_impl_sendto(res, (long)(s), (long)(buf),            \
                                       (long)(len), (long)(flags), (long)(to), \
                                       (long)(tolen))
#define __sanitizer_syscall_pre_shutdown(s, how)                               \
  __sanitizer_syscall_pre_impl_shutdown((long)(s), (long)(how))
#define __sanitizer_syscall_post_shutdown(res, s, how)                         \
  __sanitizer_syscall_post_impl_shutdown(res, (long)(s), (long)(how))
#define __sanitizer_syscall_pre_socketpair(domain, type, protocol, rsv)        \
  __sanitizer_syscall_pre_impl_socketpair((long)(domain), (long)(type),        \
                                          (long)(protocol), (long)(rsv))
#define __sanitizer_syscall_post_socketpair(res, domain, type, protocol, rsv)  \
  __sanitizer_syscall_post_impl_socketpair(res, (long)(domain), (long)(type),  \
                                           (long)(protocol), (long)(rsv))
#define __sanitizer_syscall_pre_mkdir(path, mode)                              \
  __sanitizer_syscall_pre_impl_mkdir((long)(path), (long)(mode))
#define __sanitizer_syscall_post_mkdir(res, path, mode)                        \
  __sanitizer_syscall_post_impl_mkdir(res, (long)(path), (long)(mode))
#define __sanitizer_syscall_pre_rmdir(path)                                    \
  __sanitizer_syscall_pre_impl_rmdir((long)(path))
#define __sanitizer_syscall_post_rmdir(res, path)                              \
  __sanitizer_syscall_post_impl_rmdir(res, (long)(path))
#define __sanitizer_syscall_pre_compat_50_utimes(path, tptr)                   \
  __sanitizer_syscall_pre_impl_compat_50_utimes((long)(path), (long)(tptr))
#define __sanitizer_syscall_post_compat_50_utimes(res, path, tptr)             \
  __sanitizer_syscall_post_impl_compat_50_utimes(res, (long)(path),            \
                                                 (long)(tptr))
/* syscall 139 has been skipped */
#define __sanitizer_syscall_pre_compat_50_adjtime(delta, olddelta)             \
  __sanitizer_syscall_pre_impl_compat_50_adjtime((long)(delta),                \
                                                 (long)(olddelta))
#define __sanitizer_syscall_post_compat_50_adjtime(res, delta, olddelta)       \
  __sanitizer_syscall_post_impl_compat_50_adjtime(res, (long)(delta),          \
                                                  (long)(olddelta))
#define __sanitizer_syscall_pre_compat_43_ogetpeername(fdes, asa, alen)        \
  __sanitizer_syscall_pre_impl_compat_43_ogetpeername(                         \
      (long)(fdes), (long)(asa), (long)(alen))
#define __sanitizer_syscall_post_compat_43_ogetpeername(res, fdes, asa, alen)  \
  __sanitizer_syscall_post_impl_compat_43_ogetpeername(                        \
      res, (long)(fdes), (long)(asa), (long)(alen))
#define __sanitizer_syscall_pre_compat_43_ogethostid()                         \
  __sanitizer_syscall_pre_impl_compat_43_ogethostid()
#define __sanitizer_syscall_post_compat_43_ogethostid(res)                     \
  __sanitizer_syscall_post_impl_compat_43_ogethostid(res)
#define __sanitizer_syscall_pre_compat_43_osethostid(hostid)                   \
  __sanitizer_syscall_pre_impl_compat_43_osethostid((long)(hostid))
#define __sanitizer_syscall_post_compat_43_osethostid(res, hostid)             \
  __sanitizer_syscall_post_impl_compat_43_osethostid(res, (long)(hostid))
#define __sanitizer_syscall_pre_compat_43_ogetrlimit(which, rlp)               \
  __sanitizer_syscall_pre_impl_compat_43_ogetrlimit((long)(which), (long)(rlp))
#define __sanitizer_syscall_post_compat_43_ogetrlimit(res, which, rlp)         \
  __sanitizer_syscall_post_impl_compat_43_ogetrlimit(res, (long)(which),       \
                                                     (long)(rlp))
#define __sanitizer_syscall_pre_compat_43_osetrlimit(which, rlp)               \
  __sanitizer_syscall_pre_impl_compat_43_osetrlimit((long)(which), (long)(rlp))
#define __sanitizer_syscall_post_compat_43_osetrlimit(res, which, rlp)         \
  __sanitizer_syscall_post_impl_compat_43_osetrlimit(res, (long)(which),       \
                                                     (long)(rlp))
#define __sanitizer_syscall_pre_compat_43_okillpg(pgid, signum)                \
  __sanitizer_syscall_pre_impl_compat_43_okillpg((long)(pgid), (long)(signum))
#define __sanitizer_syscall_post_compat_43_okillpg(res, pgid, signum)          \
  __sanitizer_syscall_post_impl_compat_43_okillpg(res, (long)(pgid),           \
                                                  (long)(signum))
#define __sanitizer_syscall_pre_setsid() __sanitizer_syscall_pre_impl_setsid()
#define __sanitizer_syscall_post_setsid(res)                                   \
  __sanitizer_syscall_post_impl_setsid(res)
#define __sanitizer_syscall_pre_compat_50_quotactl(path, cmd, uid, arg)        \
  __sanitizer_syscall_pre_impl_compat_50_quotactl((long)(path), (long)(cmd),   \
                                                  (long)(uid), (long)(arg))
#define __sanitizer_syscall_post_compat_50_quotactl(res, path, cmd, uid, arg)  \
  __sanitizer_syscall_post_impl_compat_50_quotactl(                            \
      res, (long)(path), (long)(cmd), (long)(uid), (long)(arg))
#define __sanitizer_syscall_pre_compat_43_oquota()                             \
  __sanitizer_syscall_pre_impl_compat_43_oquota()
#define __sanitizer_syscall_post_compat_43_oquota(res)                         \
  __sanitizer_syscall_post_impl_compat_43_oquota(res)
#define __sanitizer_syscall_pre_compat_43_ogetsockname(fdec, asa, alen)        \
  __sanitizer_syscall_pre_impl_compat_43_ogetsockname(                         \
      (long)(fdec), (long)(asa), (long)(alen))
#define __sanitizer_syscall_post_compat_43_ogetsockname(res, fdec, asa, alen)  \
  __sanitizer_syscall_post_impl_compat_43_ogetsockname(                        \
      res, (long)(fdec), (long)(asa), (long)(alen))
/* syscall 151 has been skipped */
/* syscall 152 has been skipped */
/* syscall 153 has been skipped */
/* syscall 154 has been skipped */
#define __sanitizer_syscall_pre_nfssvc(flag, argp)                             \
  __sanitizer_syscall_pre_impl_nfssvc((long)(flag), (long)(argp))
#define __sanitizer_syscall_post_nfssvc(res, flag, argp)                       \
  __sanitizer_syscall_post_impl_nfssvc(res, (long)(flag), (long)(argp))
#define __sanitizer_syscall_pre_compat_43_ogetdirentries(fd, buf, count,       \
                                                         basep)                \
  __sanitizer_syscall_pre_impl_compat_43_ogetdirentries(                       \
      (long)(fd), (long)(buf), (long)(count), (long)(basep))
#define __sanitizer_syscall_post_compat_43_ogetdirentries(res, fd, buf, count, \
                                                          basep)               \
  __sanitizer_syscall_post_impl_compat_43_ogetdirentries(                      \
      res, (long)(fd), (long)(buf), (long)(count), (long)(basep))
#define __sanitizer_syscall_pre_compat_20_statfs(path, buf)                    \
  __sanitizer_syscall_pre_impl_compat_20_statfs((long)(path), (long)(buf))
#define __sanitizer_syscall_post_compat_20_statfs(res, path, buf)              \
  __sanitizer_syscall_post_impl_compat_20_statfs(res, (long)(path), (long)(buf))
#define __sanitizer_syscall_pre_compat_20_fstatfs(fd, buf)                     \
  __sanitizer_syscall_pre_impl_compat_20_fstatfs((long)(fd), (long)(buf))
#define __sanitizer_syscall_post_compat_20_fstatfs(res, fd, buf)               \
  __sanitizer_syscall_post_impl_compat_20_fstatfs(res, (long)(fd), (long)(buf))
/* syscall 159 has been skipped */
/* syscall 160 has been skipped */
#define __sanitizer_syscall_pre_compat_30_getfh(fname, fhp)                    \
  __sanitizer_syscall_pre_impl_compat_30_getfh((long)(fname), (long)(fhp))
#define __sanitizer_syscall_post_compat_30_getfh(res, fname, fhp)              \
  __sanitizer_syscall_post_impl_compat_30_getfh(res, (long)(fname), (long)(fhp))
#define __sanitizer_syscall_pre_compat_09_ogetdomainname(domainname, len)      \
  __sanitizer_syscall_pre_impl_compat_09_ogetdomainname((long)(domainname),    \
                                                        (long)(len))
#define __sanitizer_syscall_post_compat_09_ogetdomainname(res, domainname,     \
                                                          len)                 \
  __sanitizer_syscall_post_impl_compat_09_ogetdomainname(                      \
      res, (long)(domainname), (long)(len))
#define __sanitizer_syscall_pre_compat_09_osetdomainname(domainname, len)      \
  __sanitizer_syscall_pre_impl_compat_09_osetdomainname((long)(domainname),    \
                                                        (long)(len))
#define __sanitizer_syscall_post_compat_09_osetdomainname(res, domainname,     \
                                                          len)                 \
  __sanitizer_syscall_post_impl_compat_09_osetdomainname(                      \
      res, (long)(domainname), (long)(len))
#define __sanitizer_syscall_pre_compat_09_ouname(name)                         \
  __sanitizer_syscall_pre_impl_compat_09_ouname((long)(name))
#define __sanitizer_syscall_post_compat_09_ouname(res, name)                   \
  __sanitizer_syscall_post_impl_compat_09_ouname(res, (long)(name))
#define __sanitizer_syscall_pre_sysarch(op, parms)                             \
  __sanitizer_syscall_pre_impl_sysarch((long)(op), (long)(parms))
#define __sanitizer_syscall_post_sysarch(res, op, parms)                       \
  __sanitizer_syscall_post_impl_sysarch(res, (long)(op), (long)(parms))
/* syscall 166 has been skipped */
/* syscall 167 has been skipped */
/* syscall 168 has been skipped */
#if !defined(_LP64)
#define __sanitizer_syscall_pre_compat_10_osemsys(which, a2, a3, a4, a5)       \
  __sanitizer_syscall_pre_impl_compat_10_osemsys(                              \
      (long)(which), (long)(a2), (long)(a3), (long)(a4), (long)(a5))
#define __sanitizer_syscall_post_compat_10_osemsys(res, which, a2, a3, a4, a5) \
  __sanitizer_syscall_post_impl_compat_10_osemsys(                             \
      res, (long)(which), (long)(a2), (long)(a3), (long)(a4), (long)(a5))
#else
/* syscall 169 has been skipped */
#if !defined(_LP64)
#define __sanitizer_syscall_pre_compat_10_omsgsys(which, a2, a3, a4, a5, a6)   \
  __sanitizer_syscall_pre_impl_compat_10_omsgsys((long)(which), (long)(a2),    \
                                                 (long)(a3), (long)(a4),       \
                                                 (long)(a5), (long)(a6))
#define __sanitizer_syscall_post_compat_10_omsgsys(res, which, a2, a3, a4, a5, \
                                                   a6)                         \
  __sanitizer_syscall_post_impl_compat_10_omsgsys(                             \
      res, (long)(which), (long)(a2), (long)(a3), (long)(a4), (long)(a5),      \
      (long)(a6))
#else
/* syscall 170 has been skipped */
#if !defined(_LP64)
#define __sanitizer_syscall_pre_compat_10_oshmsys(which, a2, a3, a4)           \
  __sanitizer_syscall_pre_impl_compat_10_oshmsys((long)(which), (long)(a2),    \
                                                 (long)(a3), (long)(a4))
#define __sanitizer_syscall_post_compat_10_oshmsys(res, which, a2, a3, a4)     \
  __sanitizer_syscall_post_impl_compat_10_oshmsys(                             \
      res, (long)(which), (long)(a2), (long)(a3), (long)(a4))
#else
/* syscall 171 has been skipped */
#endif
/* syscall 172 has been skipped */
#define __sanitizer_syscall_pre_pread(fd, buf, nbyte, PAD, offset)             \
  __sanitizer_syscall_pre_impl_pread((long)(fd), (long)(buf), (long)(nbyte),   \
                                     (long)(PAD), (long)(offset))
#define __sanitizer_syscall_post_pread(res, fd, buf, nbyte, PAD, offset)       \
  __sanitizer_syscall_post_impl_pread(res, (long)(fd), (long)(buf),            \
                                      (long)(nbyte), (long)(PAD),              \
                                      (long)(offset))
#define __sanitizer_syscall_pre_pwrite(fd, buf, nbyte, PAD, offset)            \
  __sanitizer_syscall_pre_impl_pwrite((long)(fd), (long)(buf), (long)(nbyte),  \
                                      (long)(PAD), (long)(offset))
#define __sanitizer_syscall_post_pwrite(res, fd, buf, nbyte, PAD, offset)      \
  __sanitizer_syscall_post_impl_pwrite(res, (long)(fd), (long)(buf),           \
                                       (long)(nbyte), (long)(PAD),             \
                                       (long)(offset))
#define __sanitizer_syscall_pre_compat_30_ntp_gettime(ntvp)                    \
  __sanitizer_syscall_pre_impl_compat_30_ntp_gettime((long)(ntvp))
#define __sanitizer_syscall_post_compat_30_ntp_gettime(res, ntvp)              \
  __sanitizer_syscall_post_impl_compat_30_ntp_gettime(res, (long)(ntvp))
#if defined(NTP) || !defined(_KERNEL_OPT)
#define __sanitizer_syscall_pre_ntp_adjtime(tp)                                \
  __sanitizer_syscall_pre_impl_ntp_adjtime((long)(tp))
#define __sanitizer_syscall_post_ntp_adjtime(res, tp)                          \
  __sanitizer_syscall_post_impl_ntp_adjtime(res, (long)(tp))
#else
/* syscall 176 has been skipped */
#endif
/* syscall 177 has been skipped */
/* syscall 178 has been skipped */
/* syscall 179 has been skipped */
/* syscall 180 has been skipped */
#define __sanitizer_syscall_pre_setgid(gid)                                    \
  __sanitizer_syscall_pre_impl_setgid((long)(gid))
#define __sanitizer_syscall_post_setgid(res, gid)                              \
  __sanitizer_syscall_post_impl_setgid(res, (long)(gid))
#define __sanitizer_syscall_pre_setegid(egid)                                  \
  __sanitizer_syscall_pre_impl_setegid((long)(egid))
#define __sanitizer_syscall_post_setegid(res, egid)                            \
  __sanitizer_syscall_post_impl_setegid(res, (long)(egid))
#define __sanitizer_syscall_pre_seteuid(euid)                                  \
  __sanitizer_syscall_pre_impl_seteuid((long)(euid))
#define __sanitizer_syscall_post_seteuid(res, euid)                            \
  __sanitizer_syscall_post_impl_seteuid(res, (long)(euid))
#define __sanitizer_syscall_pre_lfs_bmapv(fsidp, blkiov, blkcnt)               \
  __sanitizer_syscall_pre_impl_lfs_bmapv((long)(fsidp), (long)(blkiov),        \
                                         (long)(blkcnt))
#define __sanitizer_syscall_post_lfs_bmapv(res, fsidp, blkiov, blkcnt)         \
  __sanitizer_syscall_post_impl_lfs_bmapv(res, (long)(fsidp), (long)(blkiov),  \
                                          (long)(blkcnt))
#define __sanitizer_syscall_pre_lfs_markv(fsidp, blkiov, blkcnt)               \
  __sanitizer_syscall_pre_impl_lfs_markv((long)(fsidp), (long)(blkiov),        \
                                         (long)(blkcnt))
#define __sanitizer_syscall_post_lfs_markv(res, fsidp, blkiov, blkcnt)         \
  __sanitizer_syscall_post_impl_lfs_markv(res, (long)(fsidp), (long)(blkiov),  \
                                          (long)(blkcnt))
#define __sanitizer_syscall_pre_lfs_segclean(fsidp, segment)                   \
  __sanitizer_syscall_pre_impl_lfs_segclean((long)(fsidp), (long)(segment))
#define __sanitizer_syscall_post_lfs_segclean(res, fsidp, segment)             \
  __sanitizer_syscall_post_impl_lfs_segclean(res, (long)(fsidp),               \
                                             (long)(segment))
#define __sanitizer_syscall_pre_compat_50_lfs_segwait(fsidp, tv)               \
  __sanitizer_syscall_pre_impl_compat_50_lfs_segwait((long)(fsidp), (long)(tv))
#define __sanitizer_syscall_post_compat_50_lfs_segwait(res, fsidp, tv)         \
  __sanitizer_syscall_post_impl_compat_50_lfs_segwait(res, (long)(fsidp),      \
                                                      (long)(tv))
#define __sanitizer_syscall_pre_compat_12_stat12(path, ub)                     \
  __sanitizer_syscall_pre_impl_compat_12_stat12((long)(path), (long)(ub))
#define __sanitizer_syscall_post_compat_12_stat12(res, path, ub)               \
  __sanitizer_syscall_post_impl_compat_12_stat12(res, (long)(path), (long)(ub))
#define __sanitizer_syscall_pre_compat_12_fstat12(fd, sb)                      \
  __sanitizer_syscall_pre_impl_compat_12_fstat12((long)(fd), (long)(sb))
#define __sanitizer_syscall_post_compat_12_fstat12(res, fd, sb)                \
  __sanitizer_syscall_post_impl_compat_12_fstat12(res, (long)(fd), (long)(sb))
#define __sanitizer_syscall_pre_compat_12_lstat12(path, ub)                    \
  __sanitizer_syscall_pre_impl_compat_12_lstat12((long)(path), (long)(ub))
#define __sanitizer_syscall_post_compat_12_lstat12(res, path, ub)              \
  __sanitizer_syscall_post_impl_compat_12_lstat12(res, (long)(path), (long)(ub))
#define __sanitizer_syscall_pre_pathconf(path, name)                           \
  __sanitizer_syscall_pre_impl_pathconf((long)(path), (long)(name))
#define __sanitizer_syscall_post_pathconf(res, path, name)                     \
  __sanitizer_syscall_post_impl_pathconf(res, (long)(path), (long)(name))
#define __sanitizer_syscall_pre_fpathconf(fd, name)                            \
  __sanitizer_syscall_pre_impl_fpathconf((long)(fd), (long)(name))
#define __sanitizer_syscall_post_fpathconf(res, fd, name)                      \
  __sanitizer_syscall_post_impl_fpathconf(res, (long)(fd), (long)(name))
/* syscall 193 has been skipped */
#define __sanitizer_syscall_pre_getrlimit(which, rlp)                          \
  __sanitizer_syscall_pre_impl_getrlimit((long)(which), (long)(rlp))
#define __sanitizer_syscall_post_getrlimit(res, which, rlp)                    \
  __sanitizer_syscall_post_impl_getrlimit(res, (long)(which), (long)(rlp))
#define __sanitizer_syscall_pre_setrlimit(which, rlp)                          \
  __sanitizer_syscall_pre_impl_setrlimit((long)(which), (long)(rlp))
#define __sanitizer_syscall_post_setrlimit(res, which, rlp)                    \
  __sanitizer_syscall_post_impl_setrlimit(res, (long)(which), (long)(rlp))
#define __sanitizer_syscall_pre_compat_12_getdirentries(fd, buf, count, basep) \
  __sanitizer_syscall_pre_impl_compat_12_getdirentries(                        \
      (long)(fd), (long)(buf), (long)(count), (long)(basep))
#define __sanitizer_syscall_post_compat_12_getdirentries(res, fd, buf, count,  \
                                                         basep)                \
  __sanitizer_syscall_post_impl_compat_12_getdirentries(                       \
      res, (long)(fd), (long)(buf), (long)(count), (long)(basep))
#define __sanitizer_syscall_pre_mmap(addr, len, prot, flags, fd, PAD, pos)     \
  __sanitizer_syscall_pre_impl_mmap((long)(addr), (long)(len), (long)(prot),   \
                                    (long)(flags), (long)(fd), (long)(PAD),    \
                                    (long)(pos))
#define __sanitizer_syscall_post_mmap(res, addr, len, prot, flags, fd, PAD,    \
                                      pos)                                     \
  __sanitizer_syscall_post_impl_mmap(res, (long)(addr), (long)(len),           \
                                     (long)(prot), (long)(flags), (long)(fd),  \
                                     (long)(PAD), (long)(pos))
#define __sanitizer_syscall_pre___syscall(code, args[SYS_MAXSYSARGS])          \
  __sanitizer_syscall_pre_impl___syscall((long)(code),                         \
                                         (long)(args[SYS_MAXSYSARGS]))
#define __sanitizer_syscall_post___syscall(res, code, args[SYS_MAXSYSARGS])    \
  __sanitizer_syscall_post_impl___syscall(res, (long)(code),                   \
                                          (long)(args[SYS_MAXSYSARGS]))
#define __sanitizer_syscall_pre_lseek(fd, PAD, offset, whence)                 \
  __sanitizer_syscall_pre_impl_lseek((long)(fd), (long)(PAD), (long)(offset),  \
                                     (long)(whence))
#define __sanitizer_syscall_post_lseek(res, fd, PAD, offset, whence)           \
  __sanitizer_syscall_post_impl_lseek(res, (long)(fd), (long)(PAD),            \
                                      (long)(offset), (long)(whence))
#define __sanitizer_syscall_pre_truncate(path, PAD, length)                    \
  __sanitizer_syscall_pre_impl_truncate((long)(path), (long)(PAD),             \
                                        (long)(length))
#define __sanitizer_syscall_post_truncate(res, path, PAD, length)              \
  __sanitizer_syscall_post_impl_truncate(res, (long)(path), (long)(PAD),       \
                                         (long)(length))
#define __sanitizer_syscall_pre_ftruncate(fd, PAD, length)                     \
  __sanitizer_syscall_pre_impl_ftruncate((long)(fd), (long)(PAD),              \
                                         (long)(length))
#define __sanitizer_syscall_post_ftruncate(res, fd, PAD, length)               \
  __sanitizer_syscall_post_impl_ftruncate(res, (long)(fd), (long)(PAD),        \
                                          (long)(length))
#define __sanitizer_syscall_pre___sysctl(name, namelen, oldv, oldlenp, newv,   \
                                         newlen)                               \
  __sanitizer_syscall_pre_impl___sysctl((long)(name), (long)(namelen),         \
                                        (long)(oldv), (long)(oldlenp),         \
                                        (long)(newv), (long)(newlen))
#define __sanitizer_syscall_post___sysctl(res, name, namelen, oldv, oldlenp,   \
                                          newv, newlen)                        \
  __sanitizer_syscall_post_impl___sysctl(res, (long)(name), (long)(namelen),   \
                                         (long)(oldv), (long)(oldlenp),        \
                                         (long)(newv), (long)(newlen))
#define __sanitizer_syscall_pre_mlock(addr, len)                               \
  __sanitizer_syscall_pre_impl_mlock((long)(addr), (long)(len))
#define __sanitizer_syscall_post_mlock(res, addr, len)                         \
  __sanitizer_syscall_post_impl_mlock(res, (long)(addr), (long)(len))
#define __sanitizer_syscall_pre_munlock(addr, len)                             \
  __sanitizer_syscall_pre_impl_munlock((long)(addr), (long)(len))
#define __sanitizer_syscall_post_munlock(res, addr, len)                       \
  __sanitizer_syscall_post_impl_munlock(res, (long)(addr), (long)(len))
#define __sanitizer_syscall_pre_undelete(path)                                 \
  __sanitizer_syscall_pre_impl_undelete((long)(path))
#define __sanitizer_syscall_post_undelete(res, path)                           \
  __sanitizer_syscall_post_impl_undelete(res, (long)(path))
#define __sanitizer_syscall_pre_compat_50_futimes(fd, tptr)                    \
  __sanitizer_syscall_pre_impl_compat_50_futimes((long)(fd), (long)(tptr))
#define __sanitizer_syscall_post_compat_50_futimes(res, fd, tptr)              \
  __sanitizer_syscall_post_impl_compat_50_futimes(res, (long)(fd), (long)(tptr))
#define __sanitizer_syscall_pre_getpgid(pid)                                   \
  __sanitizer_syscall_pre_impl_getpgid((long)(pid))
#define __sanitizer_syscall_post_getpgid(res, pid)                             \
  __sanitizer_syscall_post_impl_getpgid(res, (long)(pid))
#define __sanitizer_syscall_pre_reboot(opt, bootstr)                           \
  __sanitizer_syscall_pre_impl_reboot((long)(opt), (long)(bootstr))
#define __sanitizer_syscall_post_reboot(res, opt, bootstr)                     \
  __sanitizer_syscall_post_impl_reboot(res, (long)(opt), (long)(bootstr))
#define __sanitizer_syscall_pre_poll(fds, nfds, timeout)                       \
  __sanitizer_syscall_pre_impl_poll((long)(fds), (long)(nfds), (long)(timeout))
#define __sanitizer_syscall_post_poll(res, fds, nfds, timeout)                 \
  __sanitizer_syscall_post_impl_poll(res, (long)(fds), (long)(nfds),           \
                                     (long)(timeout))
#define __sanitizer_syscall_pre_afssys(id, a1, a2, a3, a4, a5, a6)             \
  __sanitizer_syscall_pre_impl_afssys((long)(id), (long)(a1), (long)(a2),      \
                                      (long)(a3), (long)(a4), (long)(a5),      \
                                      (long)(a6))
#define __sanitizer_syscall_post_afssys(res, id, a1, a2, a3, a4, a5, a6)       \
  __sanitizer_syscall_post_impl_afssys(res, (long)(id), (long)(a1),            \
                                       (long)(a2), (long)(a3), (long)(a4),     \
                                       (long)(a5), (long)(a6))
/* syscall 211 has been skipped */
/* syscall 212 has been skipped */
/* syscall 213 has been skipped */
/* syscall 214 has been skipped */
/* syscall 215 has been skipped */
/* syscall 216 has been skipped */
/* syscall 217 has been skipped */
/* syscall 218 has been skipped */
/* syscall 219 has been skipped */
#define __sanitizer_syscall_pre_compat_14___semctl(semid, semnum, cmd, arg)    \
  __sanitizer_syscall_pre_impl_compat_14___semctl(                             \
      (long)(semid), (long)(semnum), (long)(cmd), (long)(arg))
#define __sanitizer_syscall_post_compat_14___semctl(res, semid, semnum, cmd,   \
                                                    arg)                       \
  __sanitizer_syscall_post_impl_compat_14___semctl(                            \
      res, (long)(semid), (long)(semnum), (long)(cmd), (long)(arg))
#define __sanitizer_syscall_pre_semget(key, nsems, semflg)                     \
  __sanitizer_syscall_pre_impl_semget((long)(key), (long)(nsems),              \
                                      (long)(semflg))
#define __sanitizer_syscall_post_semget(res, key, nsems, semflg)               \
  __sanitizer_syscall_post_impl_semget(res, (long)(key), (long)(nsems),        \
                                       (long)(semflg))
#define __sanitizer_syscall_pre_semop(semid, sops, nsops)                      \
  __sanitizer_syscall_pre_impl_semop((long)(semid), (long)(sops), (long)(nsops))
#define __sanitizer_syscall_post_semop(res, semid, sops, nsops)                \
  __sanitizer_syscall_post_impl_semop(res, (long)(semid), (long)(sops),        \
                                      (long)(nsops))
#define __sanitizer_syscall_pre_semconfig(flag)                                \
  __sanitizer_syscall_pre_impl_semconfig((long)(flag))
#define __sanitizer_syscall_post_semconfig(res, flag)                          \
  __sanitizer_syscall_post_impl_semconfig(res, (long)(flag))
#define __sanitizer_syscall_pre_compat_14_msgctl(msqid, cmd, buf)              \
  __sanitizer_syscall_pre_impl_compat_14_msgctl((long)(msqid), (long)(cmd),    \
                                                (long)(buf))
#define __sanitizer_syscall_post_compat_14_msgctl(res, msqid, cmd, buf)        \
  __sanitizer_syscall_post_impl_compat_14_msgctl(res, (long)(msqid),           \
                                                 (long)(cmd), (long)(buf))
#define __sanitizer_syscall_pre_msgget(key, msgflg)                            \
  __sanitizer_syscall_pre_impl_msgget((long)(key), (long)(msgflg))
#define __sanitizer_syscall_post_msgget(res, key, msgflg)                      \
  __sanitizer_syscall_post_impl_msgget(res, (long)(key), (long)(msgflg))
#define __sanitizer_syscall_pre_msgsnd(msqid, msgp, msgsz, msgflg)             \
  __sanitizer_syscall_pre_impl_msgsnd((long)(msqid), (long)(msgp),             \
                                      (long)(msgsz), (long)(msgflg))
#define __sanitizer_syscall_post_msgsnd(res, msqid, msgp, msgsz, msgflg)       \
  __sanitizer_syscall_post_impl_msgsnd(res, (long)(msqid), (long)(msgp),       \
                                       (long)(msgsz), (long)(msgflg))
#define __sanitizer_syscall_pre_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)     \
  __sanitizer_syscall_pre_impl_msgrcv((long)(msqid), (long)(msgp),             \
                                      (long)(msgsz), (long)(msgtyp),           \
                                      (long)(msgflg))
#define __sanitizer_syscall_post_msgrcv(res, msqid, msgp, msgsz, msgtyp,       \
                                        msgflg)                                \
  __sanitizer_syscall_post_impl_msgrcv(res, (long)(msqid), (long)(msgp),       \
                                       (long)(msgsz), (long)(msgtyp),          \
                                       (long)(msgflg))
#define __sanitizer_syscall_pre_shmat(shmid, shmaddr, shmflg)                  \
  __sanitizer_syscall_pre_impl_shmat((long)(shmid), (long)(shmaddr),           \
                                     (long)(shmflg))
#define __sanitizer_syscall_post_shmat(res, shmid, shmaddr, shmflg)            \
  __sanitizer_syscall_post_impl_shmat(res, (long)(shmid), (long)(shmaddr),     \
                                      (long)(shmflg))
#define __sanitizer_syscall_pre_compat_14_shmctl(shmid, cmd, buf)              \
  __sanitizer_syscall_pre_impl_compat_14_shmctl((long)(shmid), (long)(cmd),    \
                                                (long)(buf))
#define __sanitizer_syscall_post_compat_14_shmctl(res, shmid, cmd, buf)        \
  __sanitizer_syscall_post_impl_compat_14_shmctl(res, (long)(shmid),           \
                                                 (long)(cmd), (long)(buf))
#define __sanitizer_syscall_pre_shmdt(shmaddr)                                 \
  __sanitizer_syscall_pre_impl_shmdt((long)(shmaddr))
#define __sanitizer_syscall_post_shmdt(res, shmaddr)                           \
  __sanitizer_syscall_post_impl_shmdt(res, (long)(shmaddr))
#define __sanitizer_syscall_pre_shmget(key, size, shmflg)                      \
  __sanitizer_syscall_pre_impl_shmget((long)(key), (long)(size), (long)(shmflg))
#define __sanitizer_syscall_post_shmget(res, key, size, shmflg)                \
  __sanitizer_syscall_post_impl_shmget(res, (long)(key), (long)(size),         \
                                       (long)(shmflg))
#define __sanitizer_syscall_pre_compat_50_clock_gettime(clock_id, tp)          \
  __sanitizer_syscall_pre_impl_compat_50_clock_gettime((long)(clock_id),       \
                                                       (long)(tp))
#define __sanitizer_syscall_post_compat_50_clock_gettime(res, clock_id, tp)    \
  __sanitizer_syscall_post_impl_compat_50_clock_gettime(res, (long)(clock_id), \
                                                        (long)(tp))
#define __sanitizer_syscall_pre_compat_50_clock_settime(clock_id, tp)          \
  __sanitizer_syscall_pre_impl_compat_50_clock_settime((long)(clock_id),       \
                                                       (long)(tp))
#define __sanitizer_syscall_post_compat_50_clock_settime(res, clock_id, tp)    \
  __sanitizer_syscall_post_impl_compat_50_clock_settime(res, (long)(clock_id), \
                                                        (long)(tp))
#define __sanitizer_syscall_pre_compat_50_clock_getres(clock_id, tp)           \
  __sanitizer_syscall_pre_impl_compat_50_clock_getres((long)(clock_id),        \
                                                      (long)(tp))
#define __sanitizer_syscall_post_compat_50_clock_getres(res, clock_id, tp)     \
  __sanitizer_syscall_post_impl_compat_50_clock_getres(res, (long)(clock_id),  \
                                                       (long)(tp))
#define __sanitizer_syscall_pre_timer_create(clock_id, evp, timerid)           \
  __sanitizer_syscall_pre_impl_timer_create((long)(clock_id), (long)(evp),     \
                                            (long)(timerid))
#define __sanitizer_syscall_post_timer_create(res, clock_id, evp, timerid)     \
  __sanitizer_syscall_post_impl_timer_create(res, (long)(clock_id),            \
                                             (long)(evp), (long)(timerid))
#define __sanitizer_syscall_pre_timer_delete(timerid)                          \
  __sanitizer_syscall_pre_impl_timer_delete((long)(timerid))
#define __sanitizer_syscall_post_timer_delete(res, timerid)                    \
  __sanitizer_syscall_post_impl_timer_delete(res, (long)(timerid))
#define __sanitizer_syscall_pre_compat_50_timer_settime(timerid, flags, value, \
                                                        ovalue)                \
  __sanitizer_syscall_pre_impl_compat_50_timer_settime(                        \
      (long)(timerid), (long)(flags), (long)(value), (long)(ovalue))
#define __sanitizer_syscall_post_compat_50_timer_settime(res, timerid, flags,  \
                                                         value, ovalue)        \
  __sanitizer_syscall_post_impl_compat_50_timer_settime(                       \
      res, (long)(timerid), (long)(flags), (long)(value), (long)(ovalue))
#define __sanitizer_syscall_pre_compat_50_timer_gettime(timerid, value)        \
  __sanitizer_syscall_pre_impl_compat_50_timer_gettime((long)(timerid),        \
                                                       (long)(value))
#define __sanitizer_syscall_post_compat_50_timer_gettime(res, timerid, value)  \
  __sanitizer_syscall_post_impl_compat_50_timer_gettime(res, (long)(timerid),  \
                                                        (long)(value))
#define __sanitizer_syscall_pre_timer_getoverrun(timerid)                      \
  __sanitizer_syscall_pre_impl_timer_getoverrun((long)(timerid))
#define __sanitizer_syscall_post_timer_getoverrun(res, timerid)                \
  __sanitizer_syscall_post_impl_timer_getoverrun(res, (long)(timerid))
#define __sanitizer_syscall_pre_compat_50_nanosleep(rqtp, rmtp)                \
  __sanitizer_syscall_pre_impl_compat_50_nanosleep((long)(rqtp), (long)(rmtp))
#define __sanitizer_syscall_post_compat_50_nanosleep(res, rqtp, rmtp)          \
  __sanitizer_syscall_post_impl_compat_50_nanosleep(res, (long)(rqtp),         \
                                                    (long)(rmtp))
#define __sanitizer_syscall_pre_fdatasync(fd)                                  \
  __sanitizer_syscall_pre_impl_fdatasync((long)(fd))
#define __sanitizer_syscall_post_fdatasync(res, fd)                            \
  __sanitizer_syscall_post_impl_fdatasync(res, (long)(fd))
#define __sanitizer_syscall_pre_mlockall(flags)                                \
  __sanitizer_syscall_pre_impl_mlockall((long)(flags))
#define __sanitizer_syscall_post_mlockall(res, flags)                          \
  __sanitizer_syscall_post_impl_mlockall(res, (long)(flags))
#define __sanitizer_syscall_pre_munlockall()                                   \
  __sanitizer_syscall_pre_impl_munlockall()
#define __sanitizer_syscall_post_munlockall(res)                               \
  __sanitizer_syscall_post_impl_munlockall(res)
#define __sanitizer_syscall_pre_compat_50___sigtimedwait(set, info, timeout)   \
  __sanitizer_syscall_pre_impl_compat_50___sigtimedwait(                       \
      (long)(set), (long)(info), (long)(timeout))
#define __sanitizer_syscall_post_compat_50___sigtimedwait(res, set, info,      \
                                                          timeout)             \
  __sanitizer_syscall_post_impl_compat_50___sigtimedwait(                      \
      res, (long)(set), (long)(info), (long)(timeout))
#define __sanitizer_syscall_pre_sigqueueinfo(pid, info)                        \
  __sanitizer_syscall_pre_impl_sigqueueinfo((long)(pid), (long)(info))
#define __sanitizer_syscall_post_sigqueueinfo(res, pid, info)                  \
  __sanitizer_syscall_post_impl_sigqueueinfo(res, (long)(pid), (long)(info))
#define __sanitizer_syscall_pre_modctl(cmd, arg)                               \
  __sanitizer_syscall_pre_impl_modctl((long)(cmd), (long)(arg))
#define __sanitizer_syscall_post_modctl(res, cmd, arg)                         \
  __sanitizer_syscall_post_impl_modctl(res, (long)(cmd), (long)(arg))
#define __sanitizer_syscall_pre__ksem_init(value, idp)                         \
  __sanitizer_syscall_pre_impl__ksem_init((long)(value), (long)(idp))
#define __sanitizer_syscall_post__ksem_init(res, value, idp)                   \
  __sanitizer_syscall_post_impl__ksem_init(res, (long)(value), (long)(idp))
#define __sanitizer_syscall_pre__ksem_open(name, oflag, mode, value, idp)      \
  __sanitizer_syscall_pre_impl__ksem_open(                                     \
      (long)(name), (long)(oflag), (long)(mode), (long)(value), (long)(idp))
#define __sanitizer_syscall_post__ksem_open(res, name, oflag, mode, value,     \
                                            idp)                               \
  __sanitizer_syscall_post_impl__ksem_open(res, (long)(name), (long)(oflag),   \
                                           (long)(mode), (long)(value),        \
                                           (long)(idp))
#define __sanitizer_syscall_pre__ksem_unlink(name)                             \
  __sanitizer_syscall_pre_impl__ksem_unlink((long)(name))
#define __sanitizer_syscall_post__ksem_unlink(res, name)                       \
  __sanitizer_syscall_post_impl__ksem_unlink(res, (long)(name))
#define __sanitizer_syscall_pre__ksem_close(id)                                \
  __sanitizer_syscall_pre_impl__ksem_close((long)(id))
#define __sanitizer_syscall_post__ksem_close(res, id)                          \
  __sanitizer_syscall_post_impl__ksem_close(res, (long)(id))
#define __sanitizer_syscall_pre__ksem_post(id)                                 \
  __sanitizer_syscall_pre_impl__ksem_post((long)(id))
#define __sanitizer_syscall_post__ksem_post(res, id)                           \
  __sanitizer_syscall_post_impl__ksem_post(res, (long)(id))
#define __sanitizer_syscall_pre__ksem_wait(id)                                 \
  __sanitizer_syscall_pre_impl__ksem_wait((long)(id))
#define __sanitizer_syscall_post__ksem_wait(res, id)                           \
  __sanitizer_syscall_post_impl__ksem_wait(res, (long)(id))
#define __sanitizer_syscall_pre__ksem_trywait(id)                              \
  __sanitizer_syscall_pre_impl__ksem_trywait((long)(id))
#define __sanitizer_syscall_post__ksem_trywait(res, id)                        \
  __sanitizer_syscall_post_impl__ksem_trywait(res, (long)(id))
#define __sanitizer_syscall_pre__ksem_getvalue(id, value)                      \
  __sanitizer_syscall_pre_impl__ksem_getvalue((long)(id), (long)(value))
#define __sanitizer_syscall_post__ksem_getvalue(res, id, value)                \
  __sanitizer_syscall_post_impl__ksem_getvalue(res, (long)(id), (long)(value))
#define __sanitizer_syscall_pre__ksem_destroy(id)                              \
  __sanitizer_syscall_pre_impl__ksem_destroy((long)(id))
#define __sanitizer_syscall_post__ksem_destroy(res, id)                        \
  __sanitizer_syscall_post_impl__ksem_destroy(res, (long)(id))
#define __sanitizer_syscall_pre__ksem_timedwait(id, abstime)                   \
  __sanitizer_syscall_pre_impl__ksem_timedwait((long)(id), (long)(abstime))
#define __sanitizer_syscall_post__ksem_timedwait(res, id, abstime)             \
  __sanitizer_syscall_post_impl__ksem_timedwait(res, (long)(id),               \
                                                (long)(abstime))
#define __sanitizer_syscall_pre_mq_open(name, oflag, mode, attr)               \
  __sanitizer_syscall_pre_impl_mq_open((long)(name), (long)(oflag),            \
                                       (long)(mode), (long)(attr))
#define __sanitizer_syscall_post_mq_open(res, name, oflag, mode, attr)         \
  __sanitizer_syscall_post_impl_mq_open(res, (long)(name), (long)(oflag),      \
                                        (long)(mode), (long)(attr))
#define __sanitizer_syscall_pre_mq_close(mqdes)                                \
  __sanitizer_syscall_pre_impl_mq_close((long)(mqdes))
#define __sanitizer_syscall_post_mq_close(res, mqdes)                          \
  __sanitizer_syscall_post_impl_mq_close(res, (long)(mqdes))
#define __sanitizer_syscall_pre_mq_unlink(name)                                \
  __sanitizer_syscall_pre_impl_mq_unlink((long)(name))
#define __sanitizer_syscall_post_mq_unlink(res, name)                          \
  __sanitizer_syscall_post_impl_mq_unlink(res, (long)(name))
#define __sanitizer_syscall_pre_mq_getattr(mqdes, mqstat)                      \
  __sanitizer_syscall_pre_impl_mq_getattr((long)(mqdes), (long)(mqstat))
#define __sanitizer_syscall_post_mq_getattr(res, mqdes, mqstat)                \
  __sanitizer_syscall_post_impl_mq_getattr(res, (long)(mqdes), (long)(mqstat))
#define __sanitizer_syscall_pre_mq_setattr(mqdes, mqstat, omqstat)             \
  __sanitizer_syscall_pre_impl_mq_setattr((long)(mqdes), (long)(mqstat),       \
                                          (long)(omqstat))
#define __sanitizer_syscall_post_mq_setattr(res, mqdes, mqstat, omqstat)       \
  __sanitizer_syscall_post_impl_mq_setattr(res, (long)(mqdes), (long)(mqstat), \
                                           (long)(omqstat))
#define __sanitizer_syscall_pre_mq_notify(mqdes, notification)                 \
  __sanitizer_syscall_pre_impl_mq_notify((long)(mqdes), (long)(notification))
#define __sanitizer_syscall_post_mq_notify(res, mqdes, notification)           \
  __sanitizer_syscall_post_impl_mq_notify(res, (long)(mqdes),                  \
                                          (long)(notification))
#define __sanitizer_syscall_pre_mq_send(mqdes, msg_ptr, msg_len, msg_prio)     \
  __sanitizer_syscall_pre_impl_mq_send((long)(mqdes), (long)(msg_ptr),         \
                                       (long)(msg_len), (long)(msg_prio))
#define __sanitizer_syscall_post_mq_send(res, mqdes, msg_ptr, msg_len,         \
                                         msg_prio)                             \
  __sanitizer_syscall_post_impl_mq_send(res, (long)(mqdes), (long)(msg_ptr),   \
                                        (long)(msg_len), (long)(msg_prio))
#define __sanitizer_syscall_pre_mq_receive(mqdes, msg_ptr, msg_len, msg_prio)  \
  __sanitizer_syscall_pre_impl_mq_receive((long)(mqdes), (long)(msg_ptr),      \
                                          (long)(msg_len), (long)(msg_prio))
#define __sanitizer_syscall_post_mq_receive(res, mqdes, msg_ptr, msg_len,      \
                                            msg_prio)                          \
  __sanitizer_syscall_post_impl_mq_receive(                                    \
      res, (long)(mqdes), (long)(msg_ptr), (long)(msg_len), (long)(msg_prio))
#define __sanitizer_syscall_pre_compat_50_mq_timedsend(                        \
    mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)                            \
  __sanitizer_syscall_pre_impl_compat_50_mq_timedsend(                         \
      (long)(mqdes), (long)(msg_ptr), (long)(msg_len), (long)(msg_prio),       \
      (long)(abs_timeout))
#define __sanitizer_syscall_post_compat_50_mq_timedsend(                       \
    res, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)                       \
  __sanitizer_syscall_post_impl_compat_50_mq_timedsend(                        \
      res, (long)(mqdes), (long)(msg_ptr), (long)(msg_len), (long)(msg_prio),  \
      (long)(abs_timeout))
#define __sanitizer_syscall_pre_compat_50_mq_timedreceive(                     \
    mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)                            \
  __sanitizer_syscall_pre_impl_compat_50_mq_timedreceive(                      \
      (long)(mqdes), (long)(msg_ptr), (long)(msg_len), (long)(msg_prio),       \
      (long)(abs_timeout))
#define __sanitizer_syscall_post_compat_50_mq_timedreceive(                    \
    res, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)                       \
  __sanitizer_syscall_post_impl_compat_50_mq_timedreceive(                     \
      res, (long)(mqdes), (long)(msg_ptr), (long)(msg_len), (long)(msg_prio),  \
      (long)(abs_timeout))
/* syscall 267 has been skipped */
/* syscall 268 has been skipped */
/* syscall 269 has been skipped */
#define __sanitizer_syscall_pre___posix_rename(from, to)                       \
  __sanitizer_syscall_pre_impl___posix_rename((long)(from), (long)(to))
#define __sanitizer_syscall_post___posix_rename(res, from, to)                 \
  __sanitizer_syscall_post_impl___posix_rename(res, (long)(from), (long)(to))
#define __sanitizer_syscall_pre_swapctl(cmd, arg, misc)                        \
  __sanitizer_syscall_pre_impl_swapctl((long)(cmd), (long)(arg), (long)(misc))
#define __sanitizer_syscall_post_swapctl(res, cmd, arg, misc)                  \
  __sanitizer_syscall_post_impl_swapctl(res, (long)(cmd), (long)(arg),         \
                                        (long)(misc))
#define __sanitizer_syscall_pre_compat_30_getdents(fd, buf, count)             \
  __sanitizer_syscall_pre_impl_compat_30_getdents((long)(fd), (long)(buf),     \
                                                  (long)(count))
#define __sanitizer_syscall_post_compat_30_getdents(res, fd, buf, count)       \
  __sanitizer_syscall_post_impl_compat_30_getdents(res, (long)(fd),            \
                                                   (long)(buf), (long)(count))
#define __sanitizer_syscall_pre_minherit(addr, len, inherit)                   \
  __sanitizer_syscall_pre_impl_minherit((long)(addr), (long)(len),             \
                                        (long)(inherit))
#define __sanitizer_syscall_post_minherit(res, addr, len, inherit)             \
  __sanitizer_syscall_post_impl_minherit(res, (long)(addr), (long)(len),       \
                                         (long)(inherit))
#define __sanitizer_syscall_pre_lchmod(path, mode)                             \
  __sanitizer_syscall_pre_impl_lchmod((long)(path), (long)(mode))
#define __sanitizer_syscall_post_lchmod(res, path, mode)                       \
  __sanitizer_syscall_post_impl_lchmod(res, (long)(path), (long)(mode))
#define __sanitizer_syscall_pre_lchown(path, uid, gid)                         \
  __sanitizer_syscall_pre_impl_lchown((long)(path), (long)(uid), (long)(gid))
#define __sanitizer_syscall_post_lchown(res, path, uid, gid)                   \
  __sanitizer_syscall_post_impl_lchown(res, (long)(path), (long)(uid),         \
                                       (long)(gid))
#define __sanitizer_syscall_pre_compat_50_lutimes(path, tptr)                  \
  __sanitizer_syscall_pre_impl_compat_50_lutimes((long)(path), (long)(tptr))
#define __sanitizer_syscall_post_compat_50_lutimes(res, path, tptr)            \
  __sanitizer_syscall_post_impl_compat_50_lutimes(res, (long)(path),           \
                                                  (long)(tptr))
#define __sanitizer_syscall_pre___msync13(addr, len, flags)                    \
  __sanitizer_syscall_pre_impl___msync13((long)(addr), (long)(len),            \
                                         (long)(flags))
#define __sanitizer_syscall_post___msync13(res, addr, len, flags)              \
  __sanitizer_syscall_post_impl___msync13(res, (long)(addr), (long)(len),      \
                                          (long)(flags))
#define __sanitizer_syscall_pre_compat_30___stat13(path, ub)                   \
  __sanitizer_syscall_pre_impl_compat_30___stat13((long)(path), (long)(ub))
#define __sanitizer_syscall_post_compat_30___stat13(res, path, ub)             \
  __sanitizer_syscall_post_impl_compat_30___stat13(res, (long)(path),          \
                                                   (long)(ub))
#define __sanitizer_syscall_pre_compat_30___fstat13(fd, sb)                    \
  __sanitizer_syscall_pre_impl_compat_30___fstat13((long)(fd), (long)(sb))
#define __sanitizer_syscall_post_compat_30___fstat13(res, fd, sb)              \
  __sanitizer_syscall_post_impl_compat_30___fstat13(res, (long)(fd), (long)(sb))
#define __sanitizer_syscall_pre_compat_30___lstat13(path, ub)                  \
  __sanitizer_syscall_pre_impl_compat_30___lstat13((long)(path), (long)(ub))
#define __sanitizer_syscall_post_compat_30___lstat13(res, path, ub)            \
  __sanitizer_syscall_post_impl_compat_30___lstat13(res, (long)(path),         \
                                                    (long)(ub))
#define __sanitizer_syscall_pre___sigaltstack14(nss, oss)                      \
  __sanitizer_syscall_pre_impl___sigaltstack14((long)(nss), (long)(oss))
#define __sanitizer_syscall_post___sigaltstack14(res, nss, oss)                \
  __sanitizer_syscall_post_impl___sigaltstack14(res, (long)(nss), (long)(oss))
#define __sanitizer_syscall_pre___vfork14()                                    \
  __sanitizer_syscall_pre_impl___vfork14()
#define __sanitizer_syscall_post___vfork14(res)                                \
  __sanitizer_syscall_post_impl___vfork14(res)
#define __sanitizer_syscall_pre___posix_chown(path, uid, gid)                  \
  __sanitizer_syscall_pre_impl___posix_chown((long)(path), (long)(uid),        \
                                             (long)(gid))
#define __sanitizer_syscall_post___posix_chown(res, path, uid, gid)            \
  __sanitizer_syscall_post_impl___posix_chown(res, (long)(path), (long)(uid),  \
                                              (long)(gid))
#define __sanitizer_syscall_pre___posix_fchown(fd, uid, gid)                   \
  __sanitizer_syscall_pre_impl___posix_fchown((long)(fd), (long)(uid),         \
                                              (long)(gid))
#define __sanitizer_syscall_post___posix_fchown(res, fd, uid, gid)             \
  __sanitizer_syscall_post_impl___posix_fchown(res, (long)(fd), (long)(uid),   \
                                               (long)(gid))
#define __sanitizer_syscall_pre___posix_lchown(path, uid, gid)                 \
  __sanitizer_syscall_pre_impl___posix_lchown((long)(path), (long)(uid),       \
                                              (long)(gid))
#define __sanitizer_syscall_post___posix_lchown(res, path, uid, gid)           \
  __sanitizer_syscall_post_impl___posix_lchown(res, (long)(path), (long)(uid), \
                                               (long)(gid))
#define __sanitizer_syscall_pre_getsid(pid)                                    \
  __sanitizer_syscall_pre_impl_getsid((long)(pid))
#define __sanitizer_syscall_post_getsid(res, pid)                              \
  __sanitizer_syscall_post_impl_getsid(res, (long)(pid))
#define __sanitizer_syscall_pre___clone(flags, stack)                          \
  __sanitizer_syscall_pre_impl___clone((long)(flags), (long)(stack))
#define __sanitizer_syscall_post___clone(res, flags, stack)                    \
  __sanitizer_syscall_post_impl___clone(res, (long)(flags), (long)(stack))
#define __sanitizer_syscall_pre_fktrace(fd, ops, facs, pid)                    \
  __sanitizer_syscall_pre_impl_fktrace((long)(fd), (long)(ops), (long)(facs),  \
                                       (long)(pid))
#define __sanitizer_syscall_post_fktrace(res, fd, ops, facs, pid)              \
  __sanitizer_syscall_post_impl_fktrace(res, (long)(fd), (long)(ops),          \
                                        (long)(facs), (long)(pid))
#define __sanitizer_syscall_pre_preadv(fd, iovp, iovcnt, PAD, offset)          \
  __sanitizer_syscall_pre_impl_preadv(                                         \
      (long)(fd), (long)(iovp), (long)(iovcnt), (long)(PAD), (long)(offset))
#define __sanitizer_syscall_post_preadv(res, fd, iovp, iovcnt, PAD, offset)    \
  __sanitizer_syscall_post_impl_preadv(res, (long)(fd), (long)(iovp),          \
                                       (long)(iovcnt), (long)(PAD),            \
                                       (long)(offset))
#define __sanitizer_syscall_pre_pwritev(fd, iovp, iovcnt, PAD, offset)         \
  __sanitizer_syscall_pre_impl_pwritev(                                        \
      (long)(fd), (long)(iovp), (long)(iovcnt), (long)(PAD), (long)(offset))
#define __sanitizer_syscall_post_pwritev(res, fd, iovp, iovcnt, PAD, offset)   \
  __sanitizer_syscall_post_impl_pwritev(res, (long)(fd), (long)(iovp),         \
                                        (long)(iovcnt), (long)(PAD),           \
                                        (long)(offset))
#define __sanitizer_syscall_pre_compat_16___sigaction14(signum, nsa, osa)      \
  __sanitizer_syscall_pre_impl_compat_16___sigaction14(                        \
      (long)(signum), (long)(nsa), (long)(osa))
#define __sanitizer_syscall_post_compat_16___sigaction14(res, signum, nsa,     \
                                                         osa)                  \
  __sanitizer_syscall_post_impl_compat_16___sigaction14(                       \
      res, (long)(signum), (long)(nsa), (long)(osa))
#define __sanitizer_syscall_pre___sigpending14(set)                            \
  __sanitizer_syscall_pre_impl___sigpending14((long)(set))
#define __sanitizer_syscall_post___sigpending14(res, set)                      \
  __sanitizer_syscall_post_impl___sigpending14(res, (long)(set))
#define __sanitizer_syscall_pre___sigprocmask14(how, set, oset)                \
  __sanitizer_syscall_pre_impl___sigprocmask14((long)(how), (long)(set),       \
                                               (long)(oset))
#define __sanitizer_syscall_post___sigprocmask14(res, how, set, oset)          \
  __sanitizer_syscall_post_impl___sigprocmask14(res, (long)(how), (long)(set), \
                                                (long)(oset))
#define __sanitizer_syscall_pre___sigsuspend14(set)                            \
  __sanitizer_syscall_pre_impl___sigsuspend14((long)(set))
#define __sanitizer_syscall_post___sigsuspend14(res, set)                      \
  __sanitizer_syscall_post_impl___sigsuspend14(res, (long)(set))
#define __sanitizer_syscall_pre_compat_16___sigreturn14(sigcntxp)              \
  __sanitizer_syscall_pre_impl_compat_16___sigreturn14((long)(sigcntxp))
#define __sanitizer_syscall_post_compat_16___sigreturn14(res, sigcntxp)        \
  __sanitizer_syscall_post_impl_compat_16___sigreturn14(res, (long)(sigcntxp))
#define __sanitizer_syscall_pre___getcwd(bufp, length)                         \
  __sanitizer_syscall_pre_impl___getcwd((long)(bufp), (long)(length))
#define __sanitizer_syscall_post___getcwd(res, bufp, length)                   \
  __sanitizer_syscall_post_impl___getcwd(res, (long)(bufp), (long)(length))
#define __sanitizer_syscall_pre_fchroot(fd)                                    \
  __sanitizer_syscall_pre_impl_fchroot((long)(fd))
#define __sanitizer_syscall_post_fchroot(res, fd)                              \
  __sanitizer_syscall_post_impl_fchroot(res, (long)(fd))
#define __sanitizer_syscall_pre_compat_30_fhopen(fhp, flags)                   \
  __sanitizer_syscall_pre_impl_compat_30_fhopen((long)(fhp), (long)(flags))
#define __sanitizer_syscall_post_compat_30_fhopen(res, fhp, flags)             \
  __sanitizer_syscall_post_impl_compat_30_fhopen(res, (long)(fhp),             \
                                                 (long)(flags))
#define __sanitizer_syscall_pre_compat_30_fhstat(fhp, sb)                      \
  __sanitizer_syscall_pre_impl_compat_30_fhstat((long)(fhp), (long)(sb))
#define __sanitizer_syscall_post_compat_30_fhstat(res, fhp, sb)                \
  __sanitizer_syscall_post_impl_compat_30_fhstat(res, (long)(fhp), (long)(sb))
#define __sanitizer_syscall_pre_compat_20_fhstatfs(fhp, buf)                   \
  __sanitizer_syscall_pre_impl_compat_20_fhstatfs((long)(fhp), (long)(buf))
#define __sanitizer_syscall_post_compat_20_fhstatfs(res, fhp, buf)             \
  __sanitizer_syscall_post_impl_compat_20_fhstatfs(res, (long)(fhp),           \
                                                   (long)(buf))
#define __sanitizer_syscall_pre_compat_50_____semctl13(semid, semnum, cmd,     \
                                                       arg)                    \
  __sanitizer_syscall_pre_impl_compat_50_____semctl13(                         \
      (long)(semid), (long)(semnum), (long)(cmd), (long)(arg))
#define __sanitizer_syscall_post_compat_50_____semctl13(res, semid, semnum,    \
                                                        cmd, arg)              \
  __sanitizer_syscall_post_impl_compat_50_____semctl13(                        \
      res, (long)(semid), (long)(semnum), (long)(cmd), (long)(arg))
#define __sanitizer_syscall_pre_compat_50___msgctl13(msqid, cmd, buf)          \
  __sanitizer_syscall_pre_impl_compat_50___msgctl13((long)(msqid),             \
                                                    (long)(cmd), (long)(buf))
#define __sanitizer_syscall_post_compat_50___msgctl13(res, msqid, cmd, buf)    \
  __sanitizer_syscall_post_impl_compat_50___msgctl13(res, (long)(msqid),       \
                                                     (long)(cmd), (long)(buf))
#define __sanitizer_syscall_pre_compat_50___shmctl13(shmid, cmd, buf)          \
  __sanitizer_syscall_pre_impl_compat_50___shmctl13((long)(shmid),             \
                                                    (long)(cmd), (long)(buf))
#define __sanitizer_syscall_post_compat_50___shmctl13(res, shmid, cmd, buf)    \
  __sanitizer_syscall_post_impl_compat_50___shmctl13(res, (long)(shmid),       \
                                                     (long)(cmd), (long)(buf))
#define __sanitizer_syscall_pre_lchflags(path, flags)                          \
  __sanitizer_syscall_pre_impl_lchflags((long)(path), (long)(flags))
#define __sanitizer_syscall_post_lchflags(res, path, flags)                    \
  __sanitizer_syscall_post_impl_lchflags(res, (long)(path), (long)(flags))
#define __sanitizer_syscall_pre_issetugid()                                    \
  __sanitizer_syscall_pre_impl_issetugid()
#define __sanitizer_syscall_post_issetugid(res)                                \
  __sanitizer_syscall_post_impl_issetugid(res)
#define __sanitizer_syscall_pre_utrace(label, addr, len)                       \
  __sanitizer_syscall_pre_impl_utrace((long)(label), (long)(addr), (long)(len))
#define __sanitizer_syscall_post_utrace(res, label, addr, len)                 \
  __sanitizer_syscall_post_impl_utrace(res, (long)(label), (long)(addr),       \
                                       (long)(len))
#define __sanitizer_syscall_pre_getcontext(ucp)                                \
  __sanitizer_syscall_pre_impl_getcontext((long)(ucp))
#define __sanitizer_syscall_post_getcontext(res, ucp)                          \
  __sanitizer_syscall_post_impl_getcontext(res, (long)(ucp))
#define __sanitizer_syscall_pre_setcontext(ucp)                                \
  __sanitizer_syscall_pre_impl_setcontext((long)(ucp))
#define __sanitizer_syscall_post_setcontext(res, ucp)                          \
  __sanitizer_syscall_post_impl_setcontext(res, (long)(ucp))
#define __sanitizer_syscall_pre__lwp_create(ucp, flags, new_lwp)               \
  __sanitizer_syscall_pre_impl__lwp_create((long)(ucp), (long)(flags),         \
                                           (long)(new_lwp))
#define __sanitizer_syscall_post__lwp_create(res, ucp, flags, new_lwp)         \
  __sanitizer_syscall_post_impl__lwp_create(res, (long)(ucp), (long)(flags),   \
                                            (long)(new_lwp))
#define __sanitizer_syscall_pre__lwp_exit()                                    \
  __sanitizer_syscall_pre_impl__lwp_exit()
#define __sanitizer_syscall_post__lwp_exit(res)                                \
  __sanitizer_syscall_post_impl__lwp_exit(res)
#define __sanitizer_syscall_pre__lwp_self()                                    \
  __sanitizer_syscall_pre_impl__lwp_self()
#define __sanitizer_syscall_post__lwp_self(res)                                \
  __sanitizer_syscall_post_impl__lwp_self(res)
#define __sanitizer_syscall_pre__lwp_wait(wait_for, departed)                  \
  __sanitizer_syscall_pre_impl__lwp_wait((long)(wait_for), (long)(departed))
#define __sanitizer_syscall_post__lwp_wait(res, wait_for, departed)            \
  __sanitizer_syscall_post_impl__lwp_wait(res, (long)(wait_for),               \
                                          (long)(departed))
#define __sanitizer_syscall_pre__lwp_suspend(target)                           \
  __sanitizer_syscall_pre_impl__lwp_suspend((long)(target))
#define __sanitizer_syscall_post__lwp_suspend(res, target)                     \
  __sanitizer_syscall_post_impl__lwp_suspend(res, (long)(target))
#define __sanitizer_syscall_pre__lwp_continue(target)                          \
  __sanitizer_syscall_pre_impl__lwp_continue((long)(target))
#define __sanitizer_syscall_post__lwp_continue(res, target)                    \
  __sanitizer_syscall_post_impl__lwp_continue(res, (long)(target))
#define __sanitizer_syscall_pre__lwp_wakeup(target)                            \
  __sanitizer_syscall_pre_impl__lwp_wakeup((long)(target))
#define __sanitizer_syscall_post__lwp_wakeup(res, target)                      \
  __sanitizer_syscall_post_impl__lwp_wakeup(res, (long)(target))
#define __sanitizer_syscall_pre__lwp_getprivate()                              \
  __sanitizer_syscall_pre_impl__lwp_getprivate()
#define __sanitizer_syscall_post__lwp_getprivate(res)                          \
  __sanitizer_syscall_post_impl__lwp_getprivate(res)
#define __sanitizer_syscall_pre__lwp_setprivate(ptr)                           \
  __sanitizer_syscall_pre_impl__lwp_setprivate((long)(ptr))
#define __sanitizer_syscall_post__lwp_setprivate(res, ptr)                     \
  __sanitizer_syscall_post_impl__lwp_setprivate(res, (long)(ptr))
#define __sanitizer_syscall_pre__lwp_kill(target, signo)                       \
  __sanitizer_syscall_pre_impl__lwp_kill((long)(target), (long)(signo))
#define __sanitizer_syscall_post__lwp_kill(res, target, signo)                 \
  __sanitizer_syscall_post_impl__lwp_kill(res, (long)(target), (long)(signo))
#define __sanitizer_syscall_pre__lwp_detach(target)                            \
  __sanitizer_syscall_pre_impl__lwp_detach((long)(target))
#define __sanitizer_syscall_post__lwp_detach(res, target)                      \
  __sanitizer_syscall_post_impl__lwp_detach(res, (long)(target))
#define __sanitizer_syscall_pre_compat_50__lwp_park(ts, unpark, hint,          \
                                                    unparkhint)                \
  __sanitizer_syscall_pre_impl_compat_50__lwp_park(                            \
      (long)(ts), (long)(unpark), (long)(hint), (long)(unparkhint))
#define __sanitizer_syscall_post_compat_50__lwp_park(res, ts, unpark, hint,    \
                                                     unparkhint)               \
  __sanitizer_syscall_post_impl_compat_50__lwp_park(                           \
      res, (long)(ts), (long)(unpark), (long)(hint), (long)(unparkhint))
#define __sanitizer_syscall_pre__lwp_unpark(target, hint)                      \
  __sanitizer_syscall_pre_impl__lwp_unpark((long)(target), (long)(hint))
#define __sanitizer_syscall_post__lwp_unpark(res, target, hint)                \
  __sanitizer_syscall_post_impl__lwp_unpark(res, (long)(target), (long)(hint))
#define __sanitizer_syscall_pre__lwp_unpark_all(targets, ntargets, hint)       \
  __sanitizer_syscall_pre_impl__lwp_unpark_all((long)(targets),                \
                                               (long)(ntargets), (long)(hint))
#define __sanitizer_syscall_post__lwp_unpark_all(res, targets, ntargets, hint) \
  __sanitizer_syscall_post_impl__lwp_unpark_all(                               \
      res, (long)(targets), (long)(ntargets), (long)(hint))
#define __sanitizer_syscall_pre__lwp_setname(target, name)                     \
  __sanitizer_syscall_pre_impl__lwp_setname((long)(target), (long)(name))
#define __sanitizer_syscall_post__lwp_setname(res, target, name)               \
  __sanitizer_syscall_post_impl__lwp_setname(res, (long)(target), (long)(name))
#define __sanitizer_syscall_pre__lwp_getname(target, name, len)                \
  __sanitizer_syscall_pre_impl__lwp_getname((long)(target), (long)(name),      \
                                            (long)(len))
#define __sanitizer_syscall_post__lwp_getname(res, target, name, len)          \
  __sanitizer_syscall_post_impl__lwp_getname(res, (long)(target),              \
                                             (long)(name), (long)(len))
#define __sanitizer_syscall_pre__lwp_ctl(features, address)                    \
  __sanitizer_syscall_pre_impl__lwp_ctl((long)(features), (long)(address))
#define __sanitizer_syscall_post__lwp_ctl(res, features, address)              \
  __sanitizer_syscall_post_impl__lwp_ctl(res, (long)(features), (long)(address))
/* syscall 326 has been skipped */
/* syscall 327 has been skipped */
/* syscall 328 has been skipped */
/* syscall 329 has been skipped */
#define __sanitizer_syscall_pre_compat_60_sa_register(newv, oldv, flags,       \
                                                      stackinfo_offset)        \
  __sanitizer_syscall_pre_impl_compat_60_sa_register(                          \
      (long)(newv), (long)(oldv), (long)(flags), (long)(stackinfo_offset))
#define __sanitizer_syscall_post_compat_60_sa_register(res, newv, oldv, flags, \
                                                       stackinfo_offset)       \
  __sanitizer_syscall_post_impl_compat_60_sa_register(                         \
      res, (long)(newv), (long)(oldv), (long)(flags),                          \
      (long)(stackinfo_offset))
#define __sanitizer_syscall_pre_compat_60_sa_stacks(num, stacks)               \
  __sanitizer_syscall_pre_impl_compat_60_sa_stacks((long)(num), (long)(stacks))
#define __sanitizer_syscall_post_compat_60_sa_stacks(res, num, stacks)         \
  __sanitizer_syscall_post_impl_compat_60_sa_stacks(res, (long)(num),          \
                                                    (long)(stacks))
#define __sanitizer_syscall_pre_compat_60_sa_enable()                          \
  __sanitizer_syscall_pre_impl_compat_60_sa_enable()
#define __sanitizer_syscall_post_compat_60_sa_enable(res)                      \
  __sanitizer_syscall_post_impl_compat_60_sa_enable(res)
#define __sanitizer_syscall_pre_compat_60_sa_setconcurrency(concurrency)       \
  __sanitizer_syscall_pre_impl_compat_60_sa_setconcurrency((long)(concurrency))
#define __sanitizer_syscall_post_compat_60_sa_setconcurrency(res, concurrency) \
  __sanitizer_syscall_post_impl_compat_60_sa_setconcurrency(                   \
      res, (long)(concurrency))
#define __sanitizer_syscall_pre_compat_60_sa_yield()                           \
  __sanitizer_syscall_pre_impl_compat_60_sa_yield()
#define __sanitizer_syscall_post_compat_60_sa_yield(res)                       \
  __sanitizer_syscall_post_impl_compat_60_sa_yield(res)
#define __sanitizer_syscall_pre_compat_60_sa_preempt(sa_id)                    \
  __sanitizer_syscall_pre_impl_compat_60_sa_preempt((long)(sa_id))
#define __sanitizer_syscall_post_compat_60_sa_preempt(res, sa_id)              \
  __sanitizer_syscall_post_impl_compat_60_sa_preempt(res, (long)(sa_id))
/* syscall 336 has been skipped */
/* syscall 337 has been skipped */
/* syscall 338 has been skipped */
/* syscall 339 has been skipped */
#define __sanitizer_syscall_pre___sigaction_sigtramp(signum, nsa, osa, tramp,  \
                                                     vers)                     \
  __sanitizer_syscall_pre_impl___sigaction_sigtramp(                           \
      (long)(signum), (long)(nsa), (long)(osa), (long)(tramp), (long)(vers))
#define __sanitizer_syscall_post___sigaction_sigtramp(res, signum, nsa, osa,   \
                                                      tramp, vers)             \
  __sanitizer_syscall_post_impl___sigaction_sigtramp(                          \
      res, (long)(signum), (long)(nsa), (long)(osa), (long)(tramp),            \
      (long)(vers))
#define __sanitizer_syscall_pre_pmc_get_info(ctr, op, args)                    \
  __sanitizer_syscall_pre_impl_pmc_get_info((long)(ctr), (long)(op),           \
                                            (long)(args))
#define __sanitizer_syscall_post_pmc_get_info(res, ctr, op, args)              \
  __sanitizer_syscall_post_impl_pmc_get_info(res, (long)(ctr), (long)(op),     \
                                             (long)(args))
#define __sanitizer_syscall_pre_pmc_control(ctr, op, args)                     \
  __sanitizer_syscall_pre_impl_pmc_control((long)(ctr), (long)(op),            \
                                           (long)(args))
#define __sanitizer_syscall_post_pmc_control(res, ctr, op, args)               \
  __sanitizer_syscall_post_impl_pmc_control(res, (long)(ctr), (long)(op),      \
                                            (long)(args))
#define __sanitizer_syscall_pre_rasctl(addr, len, op)                          \
  __sanitizer_syscall_pre_impl_rasctl((long)(addr), (long)(len), (long)(op))
#define __sanitizer_syscall_post_rasctl(res, addr, len, op)                    \
  __sanitizer_syscall_post_impl_rasctl(res, (long)(addr), (long)(len),         \
                                       (long)(op))
#define __sanitizer_syscall_pre_kqueue() __sanitizer_syscall_pre_impl_kqueue()
#define __sanitizer_syscall_post_kqueue(res)                                   \
  __sanitizer_syscall_post_impl_kqueue(res)
#define __sanitizer_syscall_pre_compat_50_kevent(fd, changelist, nchanges,     \
                                                 eventlist, nevents, timeout)  \
  __sanitizer_syscall_pre_impl_compat_50_kevent(                               \
      (long)(fd), (long)(changelist), (long)(nchanges), (long)(eventlist),     \
      (long)(nevents), (long)(timeout))
#define __sanitizer_syscall_post_compat_50_kevent(                             \
    res, fd, changelist, nchanges, eventlist, nevents, timeout)                \
  __sanitizer_syscall_post_impl_compat_50_kevent(                              \
      res, (long)(fd), (long)(changelist), (long)(nchanges),                   \
      (long)(eventlist), (long)(nevents), (long)(timeout))
#define __sanitizer_syscall_pre__sched_setparam(pid, lid, policy, params)      \
  __sanitizer_syscall_pre_impl__sched_setparam((long)(pid), (long)(lid),       \
                                               (long)(policy), (long)(params))
#define __sanitizer_syscall_post__sched_setparam(res, pid, lid, policy,        \
                                                 params)                       \
  __sanitizer_syscall_post_impl__sched_setparam(                               \
      res, (long)(pid), (long)(lid), (long)(policy), (long)(params))
#define __sanitizer_syscall_pre__sched_getparam(pid, lid, policy, params)      \
  __sanitizer_syscall_pre_impl__sched_getparam((long)(pid), (long)(lid),       \
                                               (long)(policy), (long)(params))
#define __sanitizer_syscall_post__sched_getparam(res, pid, lid, policy,        \
                                                 params)                       \
  __sanitizer_syscall_post_impl__sched_getparam(                               \
      res, (long)(pid), (long)(lid), (long)(policy), (long)(params))
#define __sanitizer_syscall_pre__sched_setaffinity(pid, lid, size, cpuset)     \
  __sanitizer_syscall_pre_impl__sched_setaffinity(                             \
      (long)(pid), (long)(lid), (long)(size), (long)(cpuset))
#define __sanitizer_syscall_post__sched_setaffinity(res, pid, lid, size,       \
                                                    cpuset)                    \
  __sanitizer_syscall_post_impl__sched_setaffinity(                            \
      res, (long)(pid), (long)(lid), (long)(size), (long)(cpuset))
#define __sanitizer_syscall_pre__sched_getaffinity(pid, lid, size, cpuset)     \
  __sanitizer_syscall_pre_impl__sched_getaffinity(                             \
      (long)(pid), (long)(lid), (long)(size), (long)(cpuset))
#define __sanitizer_syscall_post__sched_getaffinity(res, pid, lid, size,       \
                                                    cpuset)                    \
  __sanitizer_syscall_post_impl__sched_getaffinity(                            \
      res, (long)(pid), (long)(lid), (long)(size), (long)(cpuset))
#define __sanitizer_syscall_pre_sched_yield()                                  \
  __sanitizer_syscall_pre_impl_sched_yield()
#define __sanitizer_syscall_post_sched_yield(res)                              \
  __sanitizer_syscall_post_impl_sched_yield(res)
#define __sanitizer_syscall_pre__sched_protect(priority)                       \
  __sanitizer_syscall_pre_impl__sched_protect((long)(priority))
#define __sanitizer_syscall_post__sched_protect(res, priority)                 \
  __sanitizer_syscall_post_impl__sched_protect(res, (long)(priority))
/* syscall 352 has been skipped */
/* syscall 353 has been skipped */
#define __sanitizer_syscall_pre_fsync_range(fd, flags, start, length)          \
  __sanitizer_syscall_pre_impl_fsync_range((long)(fd), (long)(flags),          \
                                           (long)(start), (long)(length))
#define __sanitizer_syscall_post_fsync_range(res, fd, flags, start, length)    \
  __sanitizer_syscall_post_impl_fsync_range(res, (long)(fd), (long)(flags),    \
                                            (long)(start), (long)(length))
#define __sanitizer_syscall_pre_uuidgen(store, count)                          \
  __sanitizer_syscall_pre_impl_uuidgen((long)(store), (long)(count))
#define __sanitizer_syscall_post_uuidgen(res, store, count)                    \
  __sanitizer_syscall_post_impl_uuidgen(res, (long)(store), (long)(count))
#define __sanitizer_syscall_pre_getvfsstat(buf, bufsize, flags)                \
  __sanitizer_syscall_pre_impl_getvfsstat((long)(buf), (long)(bufsize),        \
                                          (long)(flags))
#define __sanitizer_syscall_post_getvfsstat(res, buf, bufsize, flags)          \
  __sanitizer_syscall_post_impl_getvfsstat(res, (long)(buf), (long)(bufsize),  \
                                           (long)(flags))
#define __sanitizer_syscall_pre_statvfs1(path, buf, flags)                     \
  __sanitizer_syscall_pre_impl_statvfs1((long)(path), (long)(buf),             \
                                        (long)(flags))
#define __sanitizer_syscall_post_statvfs1(res, path, buf, flags)               \
  __sanitizer_syscall_post_impl_statvfs1(res, (long)(path), (long)(buf),       \
                                         (long)(flags))
#define __sanitizer_syscall_pre_fstatvfs1(fd, buf, flags)                      \
  __sanitizer_syscall_pre_impl_fstatvfs1((long)(fd), (long)(buf), (long)(flags))
#define __sanitizer_syscall_post_fstatvfs1(res, fd, buf, flags)                \
  __sanitizer_syscall_post_impl_fstatvfs1(res, (long)(fd), (long)(buf),        \
                                          (long)(flags))
#define __sanitizer_syscall_pre_compat_30_fhstatvfs1(fhp, buf, flags)          \
  __sanitizer_syscall_pre_impl_compat_30_fhstatvfs1((long)(fhp), (long)(buf),  \
                                                    (long)(flags))
#define __sanitizer_syscall_post_compat_30_fhstatvfs1(res, fhp, buf, flags)    \
  __sanitizer_syscall_post_impl_compat_30_fhstatvfs1(                          \
      res, (long)(fhp), (long)(buf), (long)(flags))
#define __sanitizer_syscall_pre_extattrctl(path, cmd, filename, attrnamespace, \
                                           attrname)                           \
  __sanitizer_syscall_pre_impl_extattrctl(                                     \
      (long)(path), (long)(cmd), (long)(filename), (long)(attrnamespace),      \
      (long)(attrname))
#define __sanitizer_syscall_post_extattrctl(res, path, cmd, filename,          \
                                            attrnamespace, attrname)           \
  __sanitizer_syscall_post_impl_extattrctl(                                    \
      res, (long)(path), (long)(cmd), (long)(filename), (long)(attrnamespace), \
      (long)(attrname))
#define __sanitizer_syscall_pre_extattr_set_file(path, attrnamespace,          \
                                                 attrname, data, nbytes)       \
  __sanitizer_syscall_pre_impl_extattr_set_file(                               \
      (long)(path), (long)(attrnamespace), (long)(attrname), (long)(data),     \
      (long)(nbytes))
#define __sanitizer_syscall_post_extattr_set_file(res, path, attrnamespace,    \
                                                  attrname, data, nbytes)      \
  __sanitizer_syscall_post_impl_extattr_set_file(                              \
      res, (long)(path), (long)(attrnamespace), (long)(attrname),              \
      (long)(data), (long)(nbytes))
#define __sanitizer_syscall_pre_extattr_get_file(path, attrnamespace,          \
                                                 attrname, data, nbytes)       \
  __sanitizer_syscall_pre_impl_extattr_get_file(                               \
      (long)(path), (long)(attrnamespace), (long)(attrname), (long)(data),     \
      (long)(nbytes))
#define __sanitizer_syscall_post_extattr_get_file(res, path, attrnamespace,    \
                                                  attrname, data, nbytes)      \
  __sanitizer_syscall_post_impl_extattr_get_file(                              \
      res, (long)(path), (long)(attrnamespace), (long)(attrname),              \
      (long)(data), (long)(nbytes))
#define __sanitizer_syscall_pre_extattr_delete_file(path, attrnamespace,       \
                                                    attrname)                  \
  __sanitizer_syscall_pre_impl_extattr_delete_file(                            \
      (long)(path), (long)(attrnamespace), (long)(attrname))
#define __sanitizer_syscall_post_extattr_delete_file(res, path, attrnamespace, \
                                                     attrname)                 \
  __sanitizer_syscall_post_impl_extattr_delete_file(                           \
      res, (long)(path), (long)(attrnamespace), (long)(attrname))
#define __sanitizer_syscall_pre_extattr_set_fd(fd, attrnamespace, attrname,    \
                                               data, nbytes)                   \
  __sanitizer_syscall_pre_impl_extattr_set_fd(                                 \
      (long)(fd), (long)(attrnamespace), (long)(attrname), (long)(data),       \
      (long)(nbytes))
#define __sanitizer_syscall_post_extattr_set_fd(res, fd, attrnamespace,        \
                                                attrname, data, nbytes)        \
  __sanitizer_syscall_post_impl_extattr_set_fd(                                \
      res, (long)(fd), (long)(attrnamespace), (long)(attrname), (long)(data),  \
      (long)(nbytes))
#define __sanitizer_syscall_pre_extattr_get_fd(fd, attrnamespace, attrname,    \
                                               data, nbytes)                   \
  __sanitizer_syscall_pre_impl_extattr_get_fd(                                 \
      (long)(fd), (long)(attrnamespace), (long)(attrname), (long)(data),       \
      (long)(nbytes))
#define __sanitizer_syscall_post_extattr_get_fd(res, fd, attrnamespace,        \
                                                attrname, data, nbytes)        \
  __sanitizer_syscall_post_impl_extattr_get_fd(                                \
      res, (long)(fd), (long)(attrnamespace), (long)(attrname), (long)(data),  \
      (long)(nbytes))
#define __sanitizer_syscall_pre_extattr_delete_fd(fd, attrnamespace, attrname) \
  __sanitizer_syscall_pre_impl_extattr_delete_fd(                              \
      (long)(fd), (long)(attrnamespace), (long)(attrname))
#define __sanitizer_syscall_post_extattr_delete_fd(res, fd, attrnamespace,     \
                                                   attrname)                   \
  __sanitizer_syscall_post_impl_extattr_delete_fd(                             \
      res, (long)(fd), (long)(attrnamespace), (long)(attrname))
#define __sanitizer_syscall_pre_extattr_set_link(path, attrnamespace,          \
                                                 attrname, data, nbytes)       \
  __sanitizer_syscall_pre_impl_extattr_set_link(                               \
      (long)(path), (long)(attrnamespace), (long)(attrname), (long)(data),     \
      (long)(nbytes))
#define __sanitizer_syscall_post_extattr_set_link(res, path, attrnamespace,    \
                                                  attrname, data, nbytes)      \
  __sanitizer_syscall_post_impl_extattr_set_link(                              \
      res, (long)(path), (long)(attrnamespace), (long)(attrname),              \
      (long)(data), (long)(nbytes))
#define __sanitizer_syscall_pre_extattr_get_link(path, attrnamespace,          \
                                                 attrname, data, nbytes)       \
  __sanitizer_syscall_pre_impl_extattr_get_link(                               \
      (long)(path), (long)(attrnamespace), (long)(attrname), (long)(data),     \
      (long)(nbytes))
#define __sanitizer_syscall_post_extattr_get_link(res, path, attrnamespace,    \
                                                  attrname, data, nbytes)      \
  __sanitizer_syscall_post_impl_extattr_get_link(                              \
      res, (long)(path), (long)(attrnamespace), (long)(attrname),              \
      (long)(data), (long)(nbytes))
#define __sanitizer_syscall_pre_extattr_delete_link(path, attrnamespace,       \
                                                    attrname)                  \
  __sanitizer_syscall_pre_impl_extattr_delete_link(                            \
      (long)(path), (long)(attrnamespace), (long)(attrname))
#define __sanitizer_syscall_post_extattr_delete_link(res, path, attrnamespace, \
                                                     attrname)                 \
  __sanitizer_syscall_post_impl_extattr_delete_link(                           \
      res, (long)(path), (long)(attrnamespace), (long)(attrname))
#define __sanitizer_syscall_pre_extattr_list_fd(fd, attrnamespace, data,       \
                                                nbytes)                        \
  __sanitizer_syscall_pre_impl_extattr_list_fd(                                \
      (long)(fd), (long)(attrnamespace), (long)(data), (long)(nbytes))
#define __sanitizer_syscall_post_extattr_list_fd(res, fd, attrnamespace, data, \
                                                 nbytes)                       \
  __sanitizer_syscall_post_impl_extattr_list_fd(                               \
      res, (long)(fd), (long)(attrnamespace), (long)(data), (long)(nbytes))
#define __sanitizer_syscall_pre_extattr_list_file(path, attrnamespace, data,   \
                                                  nbytes)                      \
  __sanitizer_syscall_pre_impl_extattr_list_file(                              \
      (long)(path), (long)(attrnamespace), (long)(data), (long)(nbytes))
#define __sanitizer_syscall_post_extattr_list_file(res, path, attrnamespace,   \
                                                   data, nbytes)               \
  __sanitizer_syscall_post_impl_extattr_list_file(                             \
      res, (long)(path), (long)(attrnamespace), (long)(data), (long)(nbytes))
#define __sanitizer_syscall_pre_extattr_list_link(path, attrnamespace, data,   \
                                                  nbytes)                      \
  __sanitizer_syscall_pre_impl_extattr_list_link(                              \
      (long)(path), (long)(attrnamespace), (long)(data), (long)(nbytes))
#define __sanitizer_syscall_post_extattr_list_link(res, path, attrnamespace,   \
                                                   data, nbytes)               \
  __sanitizer_syscall_post_impl_extattr_list_link(                             \
      res, (long)(path), (long)(attrnamespace), (long)(data), (long)(nbytes))
#define __sanitizer_syscall_pre_compat_50_pselect(nd, in, ou, ex, ts, mask)    \
  __sanitizer_syscall_pre_impl_compat_50_pselect((long)(nd), (long)(in),       \
                                                 (long)(ou), (long)(ex),       \
                                                 (long)(ts), (long)(mask))
#define __sanitizer_syscall_post_compat_50_pselect(res, nd, in, ou, ex, ts,    \
                                                   mask)                       \
  __sanitizer_syscall_post_impl_compat_50_pselect(res, (long)(nd), (long)(in), \
                                                  (long)(ou), (long)(ex),      \
                                                  (long)(ts), (long)(mask))
#define __sanitizer_syscall_pre_compat_50_pollts(fds, nfds, ts, mask)          \
  __sanitizer_syscall_pre_impl_compat_50_pollts((long)(fds), (long)(nfds),     \
                                                (long)(ts), (long)(mask))
#define __sanitizer_syscall_post_compat_50_pollts(res, fds, nfds, ts, mask)    \
  __sanitizer_syscall_post_impl_compat_50_pollts(                              \
      res, (long)(fds), (long)(nfds), (long)(ts), (long)(mask))
#define __sanitizer_syscall_pre_setxattr(path, name, value, size, flags)       \
  __sanitizer_syscall_pre_impl_setxattr(                                       \
      (long)(path), (long)(name), (long)(value), (long)(size), (long)(flags))
#define __sanitizer_syscall_post_setxattr(res, path, name, value, size, flags) \
  __sanitizer_syscall_post_impl_setxattr(res, (long)(path), (long)(name),      \
                                         (long)(value), (long)(size),          \
                                         (long)(flags))
#define __sanitizer_syscall_pre_lsetxattr(path, name, value, size, flags)      \
  __sanitizer_syscall_pre_impl_lsetxattr(                                      \
      (long)(path), (long)(name), (long)(value), (long)(size), (long)(flags))
#define __sanitizer_syscall_post_lsetxattr(res, path, name, value, size,       \
                                           flags)                              \
  __sanitizer_syscall_post_impl_lsetxattr(res, (long)(path), (long)(name),     \
                                          (long)(value), (long)(size),         \
                                          (long)(flags))
#define __sanitizer_syscall_pre_fsetxattr(fd, name, value, size, flags)        \
  __sanitizer_syscall_pre_impl_fsetxattr(                                      \
      (long)(fd), (long)(name), (long)(value), (long)(size), (long)(flags))
#define __sanitizer_syscall_post_fsetxattr(res, fd, name, value, size, flags)  \
  __sanitizer_syscall_post_impl_fsetxattr(res, (long)(fd), (long)(name),       \
                                          (long)(value), (long)(size),         \
                                          (long)(flags))
#define __sanitizer_syscall_pre_getxattr(path, name, value, size)              \
  __sanitizer_syscall_pre_impl_getxattr((long)(path), (long)(name),            \
                                        (long)(value), (long)(size))
#define __sanitizer_syscall_post_getxattr(res, path, name, value, size)        \
  __sanitizer_syscall_post_impl_getxattr(res, (long)(path), (long)(name),      \
                                         (long)(value), (long)(size))
#define __sanitizer_syscall_pre_lgetxattr(path, name, value, size)             \
  __sanitizer_syscall_pre_impl_lgetxattr((long)(path), (long)(name),           \
                                         (long)(value), (long)(size))
#define __sanitizer_syscall_post_lgetxattr(res, path, name, value, size)       \
  __sanitizer_syscall_post_impl_lgetxattr(res, (long)(path), (long)(name),     \
                                          (long)(value), (long)(size))
#define __sanitizer_syscall_pre_fgetxattr(fd, name, value, size)               \
  __sanitizer_syscall_pre_impl_fgetxattr((long)(fd), (long)(name),             \
                                         (long)(value), (long)(size))
#define __sanitizer_syscall_post_fgetxattr(res, fd, name, value, size)         \
  __sanitizer_syscall_post_impl_fgetxattr(res, (long)(fd), (long)(name),       \
                                          (long)(value), (long)(size))
#define __sanitizer_syscall_pre_listxattr(path, list, size)                    \
  __sanitizer_syscall_pre_impl_listxattr((long)(path), (long)(list),           \
                                         (long)(size))
#define __sanitizer_syscall_post_listxattr(res, path, list, size)              \
  __sanitizer_syscall_post_impl_listxattr(res, (long)(path), (long)(list),     \
                                          (long)(size))
#define __sanitizer_syscall_pre_llistxattr(path, list, size)                   \
  __sanitizer_syscall_pre_impl_llistxattr((long)(path), (long)(list),          \
                                          (long)(size))
#define __sanitizer_syscall_post_llistxattr(res, path, list, size)             \
  __sanitizer_syscall_post_impl_llistxattr(res, (long)(path), (long)(list),    \
                                           (long)(size))
#define __sanitizer_syscall_pre_flistxattr(fd, list, size)                     \
  __sanitizer_syscall_pre_impl_flistxattr((long)(fd), (long)(list),            \
                                          (long)(size))
#define __sanitizer_syscall_post_flistxattr(res, fd, list, size)               \
  __sanitizer_syscall_post_impl_flistxattr(res, (long)(fd), (long)(list),      \
                                           (long)(size))
#define __sanitizer_syscall_pre_removexattr(path, name)                        \
  __sanitizer_syscall_pre_impl_removexattr((long)(path), (long)(name))
#define __sanitizer_syscall_post_removexattr(res, path, name)                  \
  __sanitizer_syscall_post_impl_removexattr(res, (long)(path), (long)(name))
#define __sanitizer_syscall_pre_lremovexattr(path, name)                       \
  __sanitizer_syscall_pre_impl_lremovexattr((long)(path), (long)(name))
#define __sanitizer_syscall_post_lremovexattr(res, path, name)                 \
  __sanitizer_syscall_post_impl_lremovexattr(res, (long)(path), (long)(name))
#define __sanitizer_syscall_pre_fremovexattr(fd, name)                         \
  __sanitizer_syscall_pre_impl_fremovexattr((long)(fd), (long)(name))
#define __sanitizer_syscall_post_fremovexattr(res, fd, name)                   \
  __sanitizer_syscall_post_impl_fremovexattr(res, (long)(fd), (long)(name))
#define __sanitizer_syscall_pre_compat_50___stat30(path, ub)                   \
  __sanitizer_syscall_pre_impl_compat_50___stat30((long)(path), (long)(ub))
#define __sanitizer_syscall_post_compat_50___stat30(res, path, ub)             \
  __sanitizer_syscall_post_impl_compat_50___stat30(res, (long)(path),          \
                                                   (long)(ub))
#define __sanitizer_syscall_pre_compat_50___fstat30(fd, sb)                    \
  __sanitizer_syscall_pre_impl_compat_50___fstat30((long)(fd), (long)(sb))
#define __sanitizer_syscall_post_compat_50___fstat30(res, fd, sb)              \
  __sanitizer_syscall_post_impl_compat_50___fstat30(res, (long)(fd), (long)(sb))
#define __sanitizer_syscall_pre_compat_50___lstat30(path, ub)                  \
  __sanitizer_syscall_pre_impl_compat_50___lstat30((long)(path), (long)(ub))
#define __sanitizer_syscall_post_compat_50___lstat30(res, path, ub)            \
  __sanitizer_syscall_post_impl_compat_50___lstat30(res, (long)(path),         \
                                                    (long)(ub))
#define __sanitizer_syscall_pre___getdents30(fd, buf, count)                   \
  __sanitizer_syscall_pre_impl___getdents30((long)(fd), (long)(buf),           \
                                            (long)(count))
#define __sanitizer_syscall_post___getdents30(res, fd, buf, count)             \
  __sanitizer_syscall_post_impl___getdents30(res, (long)(fd), (long)(buf),     \
                                             (long)(count))
#define __sanitizer_syscall_pre_posix_fadvise()                                \
  __sanitizer_syscall_pre_impl_posix_fadvise((long)())
#define __sanitizer_syscall_post_posix_fadvise(res)                            \
  __sanitizer_syscall_post_impl_posix_fadvise(res, (long)())
#define __sanitizer_syscall_pre_compat_30___fhstat30(fhp, sb)                  \
  __sanitizer_syscall_pre_impl_compat_30___fhstat30((long)(fhp), (long)(sb))
#define __sanitizer_syscall_post_compat_30___fhstat30(res, fhp, sb)            \
  __sanitizer_syscall_post_impl_compat_30___fhstat30(res, (long)(fhp),         \
                                                     (long)(sb))
#define __sanitizer_syscall_pre_compat_50___ntp_gettime30(ntvp)                \
  __sanitizer_syscall_pre_impl_compat_50___ntp_gettime30((long)(ntvp))
#define __sanitizer_syscall_post_compat_50___ntp_gettime30(res, ntvp)          \
  __sanitizer_syscall_post_impl_compat_50___ntp_gettime30(res, (long)(ntvp))
#define __sanitizer_syscall_pre___socket30(domain, type, protocol)             \
  __sanitizer_syscall_pre_impl___socket30((long)(domain), (long)(type),        \
                                          (long)(protocol))
#define __sanitizer_syscall_post___socket30(res, domain, type, protocol)       \
  __sanitizer_syscall_post_impl___socket30(res, (long)(domain), (long)(type),  \
                                           (long)(protocol))
#define __sanitizer_syscall_pre___getfh30(fname, fhp, fh_size)                 \
  __sanitizer_syscall_pre_impl___getfh30((long)(fname), (long)(fhp),           \
                                         (long)(fh_size))
#define __sanitizer_syscall_post___getfh30(res, fname, fhp, fh_size)           \
  __sanitizer_syscall_post_impl___getfh30(res, (long)(fname), (long)(fhp),     \
                                          (long)(fh_size))
#define __sanitizer_syscall_pre___fhopen40(fhp, fh_size, flags)                \
  __sanitizer_syscall_pre_impl___fhopen40((long)(fhp), (long)(fh_size),        \
                                          (long)(flags))
#define __sanitizer_syscall_post___fhopen40(res, fhp, fh_size, flags)          \
  __sanitizer_syscall_post_impl___fhopen40(res, (long)(fhp), (long)(fh_size),  \
                                           (long)(flags))
#define __sanitizer_syscall_pre___fhstatvfs140(fhp, fh_size, buf, flags)       \
  __sanitizer_syscall_pre_impl___fhstatvfs140((long)(fhp), (long)(fh_size),    \
                                              (long)(buf), (long)(flags))
#define __sanitizer_syscall_post___fhstatvfs140(res, fhp, fh_size, buf, flags) \
  __sanitizer_syscall_post_impl___fhstatvfs140(                                \
      res, (long)(fhp), (long)(fh_size), (long)(buf), (long)(flags))
#define __sanitizer_syscall_pre_compat_50___fhstat40(fhp, fh_size, sb)         \
  __sanitizer_syscall_pre_impl_compat_50___fhstat40(                           \
      (long)(fhp), (long)(fh_size), (long)(sb))
#define __sanitizer_syscall_post_compat_50___fhstat40(res, fhp, fh_size, sb)   \
  __sanitizer_syscall_post_impl_compat_50___fhstat40(                          \
      res, (long)(fhp), (long)(fh_size), (long)(sb))
#define __sanitizer_syscall_pre_aio_cancel(fildes, aiocbp)                     \
  __sanitizer_syscall_pre_impl_aio_cancel((long)(fildes), (long)(aiocbp))
#define __sanitizer_syscall_post_aio_cancel(res, fildes, aiocbp)               \
  __sanitizer_syscall_post_impl_aio_cancel(res, (long)(fildes), (long)(aiocbp))
#define __sanitizer_syscall_pre_aio_error(aiocbp)                              \
  __sanitizer_syscall_pre_impl_aio_error((long)(aiocbp))
#define __sanitizer_syscall_post_aio_error(res, aiocbp)                        \
  __sanitizer_syscall_post_impl_aio_error(res, (long)(aiocbp))
#define __sanitizer_syscall_pre_aio_fsync(op, aiocbp)                          \
  __sanitizer_syscall_pre_impl_aio_fsync((long)(op), (long)(aiocbp))
#define __sanitizer_syscall_post_aio_fsync(res, op, aiocbp)                    \
  __sanitizer_syscall_post_impl_aio_fsync(res, (long)(op), (long)(aiocbp))
#define __sanitizer_syscall_pre_aio_read(aiocbp)                               \
  __sanitizer_syscall_pre_impl_aio_read((long)(aiocbp))
#define __sanitizer_syscall_post_aio_read(res, aiocbp)                         \
  __sanitizer_syscall_post_impl_aio_read(res, (long)(aiocbp))
#define __sanitizer_syscall_pre_aio_return(aiocbp)                             \
  __sanitizer_syscall_pre_impl_aio_return((long)(aiocbp))
#define __sanitizer_syscall_post_aio_return(res, aiocbp)                       \
  __sanitizer_syscall_post_impl_aio_return(res, (long)(aiocbp))
#define __sanitizer_syscall_pre_compat_50_aio_suspend(list, nent, timeout)     \
  __sanitizer_syscall_pre_impl_compat_50_aio_suspend(                          \
      (long)(list), (long)(nent), (long)(timeout))
#define __sanitizer_syscall_post_compat_50_aio_suspend(res, list, nent,        \
                                                       timeout)                \
  __sanitizer_syscall_post_impl_compat_50_aio_suspend(                         \
      res, (long)(list), (long)(nent), (long)(timeout))
#define __sanitizer_syscall_pre_aio_write(aiocbp)                              \
  __sanitizer_syscall_pre_impl_aio_write((long)(aiocbp))
#define __sanitizer_syscall_post_aio_write(res, aiocbp)                        \
  __sanitizer_syscall_post_impl_aio_write(res, (long)(aiocbp))
#define __sanitizer_syscall_pre_lio_listio(mode, list, nent, sig)              \
  __sanitizer_syscall_pre_impl_lio_listio((long)(mode), (long)(list),          \
                                          (long)(nent), (long)(sig))
#define __sanitizer_syscall_post_lio_listio(res, mode, list, nent, sig)        \
  __sanitizer_syscall_post_impl_lio_listio(res, (long)(mode), (long)(list),    \
                                           (long)(nent), (long)(sig))
/* syscall 407 has been skipped */
/* syscall 408 has been skipped */
/* syscall 409 has been skipped */
#define __sanitizer_syscall_pre___mount50(type, path, flags, data, data_len)   \
  __sanitizer_syscall_pre_impl___mount50((long)(type), (long)(path),           \
                                         (long)(flags), (long)(data),          \
                                         (long)(data_len))
#define __sanitizer_syscall_post___mount50(res, type, path, flags, data,       \
                                           data_len)                           \
  __sanitizer_syscall_post_impl___mount50(res, (long)(type), (long)(path),     \
                                          (long)(flags), (long)(data),         \
                                          (long)(data_len))
#define __sanitizer_syscall_pre_mremap(old_address, old_size, new_address,     \
                                       new_size, flags)                        \
  __sanitizer_syscall_pre_impl_mremap((long)(old_address), (long)(old_size),   \
                                      (long)(new_address), (long)(new_size),   \
                                      (long)(flags))
#define __sanitizer_syscall_post_mremap(res, old_address, old_size,            \
                                        new_address, new_size, flags)          \
  __sanitizer_syscall_post_impl_mremap(res, (long)(old_address),               \
                                       (long)(old_size), (long)(new_address),  \
                                       (long)(new_size), (long)(flags))
#define __sanitizer_syscall_pre_pset_create(psid)                              \
  __sanitizer_syscall_pre_impl_pset_create((long)(psid))
#define __sanitizer_syscall_post_pset_create(res, psid)                        \
  __sanitizer_syscall_post_impl_pset_create(res, (long)(psid))
#define __sanitizer_syscall_pre_pset_destroy(psid)                             \
  __sanitizer_syscall_pre_impl_pset_destroy((long)(psid))
#define __sanitizer_syscall_post_pset_destroy(res, psid)                       \
  __sanitizer_syscall_post_impl_pset_destroy(res, (long)(psid))
#define __sanitizer_syscall_pre_pset_assign(psid, cpuid, opsid)                \
  __sanitizer_syscall_pre_impl_pset_assign((long)(psid), (long)(cpuid),        \
                                           (long)(opsid))
#define __sanitizer_syscall_post_pset_assign(res, psid, cpuid, opsid)          \
  __sanitizer_syscall_post_impl_pset_assign(res, (long)(psid), (long)(cpuid),  \
                                            (long)(opsid))
#define __sanitizer_syscall_pre__pset_bind(idtype, first_id, second_id, psid,  \
                                           opsid)                              \
  __sanitizer_syscall_pre_impl__pset_bind((long)(idtype), (long)(first_id),    \
                                          (long)(second_id), (long)(psid),     \
                                          (long)(opsid))
#define __sanitizer_syscall_post__pset_bind(res, idtype, first_id, second_id,  \
                                            psid, opsid)                       \
  __sanitizer_syscall_post_impl__pset_bind(                                    \
      res, (long)(idtype), (long)(first_id), (long)(second_id), (long)(psid),  \
      (long)(opsid))
#define __sanitizer_syscall_pre___posix_fadvise50(fd, PAD, offset, len,        \
                                                  advice)                      \
  __sanitizer_syscall_pre_impl___posix_fadvise50(                              \
      (long)(fd), (long)(PAD), (long)(offset), (long)(len), (long)(advice))
#define __sanitizer_syscall_post___posix_fadvise50(res, fd, PAD, offset, len,  \
                                                   advice)                     \
  __sanitizer_syscall_post_impl___posix_fadvise50(res, (long)(fd),             \
                                                  (long)(PAD), (long)(offset), \
                                                  (long)(len), (long)(advice))
#define __sanitizer_syscall_pre___select50(nd, in, ou, ex, tv)                 \
  __sanitizer_syscall_pre_impl___select50((long)(nd), (long)(in), (long)(ou),  \
                                          (long)(ex), (long)(tv))
#define __sanitizer_syscall_post___select50(res, nd, in, ou, ex, tv)           \
  __sanitizer_syscall_post_impl___select50(res, (long)(nd), (long)(in),        \
                                           (long)(ou), (long)(ex), (long)(tv))
#define __sanitizer_syscall_pre___gettimeofday50(tp, tzp)                      \
  __sanitizer_syscall_pre_impl___gettimeofday50((long)(tp), (long)(tzp))
#define __sanitizer_syscall_post___gettimeofday50(res, tp, tzp)                \
  __sanitizer_syscall_post_impl___gettimeofday50(res, (long)(tp), (long)(tzp))
#define __sanitizer_syscall_pre___settimeofday50(tv, tzp)                      \
  __sanitizer_syscall_pre_impl___settimeofday50((long)(tv), (long)(tzp))
#define __sanitizer_syscall_post___settimeofday50(res, tv, tzp)                \
  __sanitizer_syscall_post_impl___settimeofday50(res, (long)(tv), (long)(tzp))
#define __sanitizer_syscall_pre___utimes50(path, tptr)                         \
  __sanitizer_syscall_pre_impl___utimes50((long)(path), (long)(tptr))
#define __sanitizer_syscall_post___utimes50(res, path, tptr)                   \
  __sanitizer_syscall_post_impl___utimes50(res, (long)(path), (long)(tptr))
#define __sanitizer_syscall_pre___adjtime50(delta, olddelta)                   \
  __sanitizer_syscall_pre_impl___adjtime50((long)(delta), (long)(olddelta))
#define __sanitizer_syscall_post___adjtime50(res, delta, olddelta)             \
  __sanitizer_syscall_post_impl___adjtime50(res, (long)(delta),                \
                                            (long)(olddelta))
#define __sanitizer_syscall_pre___lfs_segwait50(fsidp, tv)                     \
  __sanitizer_syscall_pre_impl___lfs_segwait50((long)(fsidp), (long)(tv))
#define __sanitizer_syscall_post___lfs_segwait50(res, fsidp, tv)               \
  __sanitizer_syscall_post_impl___lfs_segwait50(res, (long)(fsidp), (long)(tv))
#define __sanitizer_syscall_pre___futimes50(fd, tptr)                          \
  __sanitizer_syscall_pre_impl___futimes50((long)(fd), (long)(tptr))
#define __sanitizer_syscall_post___futimes50(res, fd, tptr)                    \
  __sanitizer_syscall_post_impl___futimes50(res, (long)(fd), (long)(tptr))
#define __sanitizer_syscall_pre___lutimes50(path, tptr)                        \
  __sanitizer_syscall_pre_impl___lutimes50((long)(path), (long)(tptr))
#define __sanitizer_syscall_post___lutimes50(res, path, tptr)                  \
  __sanitizer_syscall_post_impl___lutimes50(res, (long)(path), (long)(tptr))
#define __sanitizer_syscall_pre___setitimer50(which, itv, oitv)                \
  __sanitizer_syscall_pre_impl___setitimer50((long)(which), (long)(itv),       \
                                             (long)(oitv))
#define __sanitizer_syscall_post___setitimer50(res, which, itv, oitv)          \
  __sanitizer_syscall_post_impl___setitimer50(res, (long)(which), (long)(itv), \
                                              (long)(oitv))
#define __sanitizer_syscall_pre___getitimer50(which, itv)                      \
  __sanitizer_syscall_pre_impl___getitimer50((long)(which), (long)(itv))
#define __sanitizer_syscall_post___getitimer50(res, which, itv)                \
  __sanitizer_syscall_post_impl___getitimer50(res, (long)(which), (long)(itv))
#define __sanitizer_syscall_pre___clock_gettime50(clock_id, tp)                \
  __sanitizer_syscall_pre_impl___clock_gettime50((long)(clock_id), (long)(tp))
#define __sanitizer_syscall_post___clock_gettime50(res, clock_id, tp)          \
  __sanitizer_syscall_post_impl___clock_gettime50(res, (long)(clock_id),       \
                                                  (long)(tp))
#define __sanitizer_syscall_pre___clock_settime50(clock_id, tp)                \
  __sanitizer_syscall_pre_impl___clock_settime50((long)(clock_id), (long)(tp))
#define __sanitizer_syscall_post___clock_settime50(res, clock_id, tp)          \
  __sanitizer_syscall_post_impl___clock_settime50(res, (long)(clock_id),       \
                                                  (long)(tp))
#define __sanitizer_syscall_pre___clock_getres50(clock_id, tp)                 \
  __sanitizer_syscall_pre_impl___clock_getres50((long)(clock_id), (long)(tp))
#define __sanitizer_syscall_post___clock_getres50(res, clock_id, tp)           \
  __sanitizer_syscall_post_impl___clock_getres50(res, (long)(clock_id),        \
                                                 (long)(tp))
#define __sanitizer_syscall_pre___nanosleep50(rqtp, rmtp)                      \
  __sanitizer_syscall_pre_impl___nanosleep50((long)(rqtp), (long)(rmtp))
#define __sanitizer_syscall_post___nanosleep50(res, rqtp, rmtp)                \
  __sanitizer_syscall_post_impl___nanosleep50(res, (long)(rqtp), (long)(rmtp))
#define __sanitizer_syscall_pre_____sigtimedwait50(set, info, timeout)         \
  __sanitizer_syscall_pre_impl_____sigtimedwait50((long)(set), (long)(info),   \
                                                  (long)(timeout))
#define __sanitizer_syscall_post_____sigtimedwait50(res, set, info, timeout)   \
  __sanitizer_syscall_post_impl_____sigtimedwait50(                            \
      res, (long)(set), (long)(info), (long)(timeout))
#define __sanitizer_syscall_pre___mq_timedsend50(mqdes, msg_ptr, msg_len,      \
                                                 msg_prio, abs_timeout)        \
  __sanitizer_syscall_pre_impl___mq_timedsend50(                               \
      (long)(mqdes), (long)(msg_ptr), (long)(msg_len), (long)(msg_prio),       \
      (long)(abs_timeout))
#define __sanitizer_syscall_post___mq_timedsend50(                             \
    res, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)                       \
  __sanitizer_syscall_post_impl___mq_timedsend50(                              \
      res, (long)(mqdes), (long)(msg_ptr), (long)(msg_len), (long)(msg_prio),  \
      (long)(abs_timeout))
#define __sanitizer_syscall_pre___mq_timedreceive50(mqdes, msg_ptr, msg_len,   \
                                                    msg_prio, abs_timeout)     \
  __sanitizer_syscall_pre_impl___mq_timedreceive50(                            \
      (long)(mqdes), (long)(msg_ptr), (long)(msg_len), (long)(msg_prio),       \
      (long)(abs_timeout))
#define __sanitizer_syscall_post___mq_timedreceive50(                          \
    res, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout)                       \
  __sanitizer_syscall_post_impl___mq_timedreceive50(                           \
      res, (long)(mqdes), (long)(msg_ptr), (long)(msg_len), (long)(msg_prio),  \
      (long)(abs_timeout))
#define __sanitizer_syscall_pre_compat_60__lwp_park(ts, unpark, hint,          \
                                                    unparkhint)                \
  __sanitizer_syscall_pre_impl_compat_60__lwp_park(                            \
      (long)(ts), (long)(unpark), (long)(hint), (long)(unparkhint))
#define __sanitizer_syscall_post_compat_60__lwp_park(res, ts, unpark, hint,    \
                                                     unparkhint)               \
  __sanitizer_syscall_post_impl_compat_60__lwp_park(                           \
      res, (long)(ts), (long)(unpark), (long)(hint), (long)(unparkhint))
#define __sanitizer_syscall_pre___kevent50(fd, changelist, nchanges,           \
                                           eventlist, nevents, timeout)        \
  __sanitizer_syscall_pre_impl___kevent50((long)(fd), (long)(changelist),      \
                                          (long)(nchanges), (long)(eventlist), \
                                          (long)(nevents), (long)(timeout))
#define __sanitizer_syscall_post___kevent50(res, fd, changelist, nchanges,     \
                                            eventlist, nevents, timeout)       \
  __sanitizer_syscall_post_impl___kevent50(                                    \
      res, (long)(fd), (long)(changelist), (long)(nchanges),                   \
      (long)(eventlist), (long)(nevents), (long)(timeout))
#define __sanitizer_syscall_pre___pselect50(nd, in, ou, ex, ts, mask)          \
  __sanitizer_syscall_pre_impl___pselect50((long)(nd), (long)(in), (long)(ou), \
                                           (long)(ex), (long)(ts),             \
                                           (long)(mask))
#define __sanitizer_syscall_post___pselect50(res, nd, in, ou, ex, ts, mask)    \
  __sanitizer_syscall_post_impl___pselect50(res, (long)(nd), (long)(in),       \
                                            (long)(ou), (long)(ex),            \
                                            (long)(ts), (long)(mask))
#define __sanitizer_syscall_pre___pollts50(fds, nfds, ts, mask)                \
  __sanitizer_syscall_pre_impl___pollts50((long)(fds), (long)(nfds),           \
                                          (long)(ts), (long)(mask))
#define __sanitizer_syscall_post___pollts50(res, fds, nfds, ts, mask)          \
  __sanitizer_syscall_post_impl___pollts50(res, (long)(fds), (long)(nfds),     \
                                           (long)(ts), (long)(mask))
#define __sanitizer_syscall_pre___aio_suspend50(list, nent, timeout)           \
  __sanitizer_syscall_pre_impl___aio_suspend50((long)(list), (long)(nent),     \
                                               (long)(timeout))
#define __sanitizer_syscall_post___aio_suspend50(res, list, nent, timeout)     \
  __sanitizer_syscall_post_impl___aio_suspend50(res, (long)(list),             \
                                                (long)(nent), (long)(timeout))
#define __sanitizer_syscall_pre___stat50(path, ub)                             \
  __sanitizer_syscall_pre_impl___stat50((long)(path), (long)(ub))
#define __sanitizer_syscall_post___stat50(res, path, ub)                       \
  __sanitizer_syscall_post_impl___stat50(res, (long)(path), (long)(ub))
#define __sanitizer_syscall_pre___fstat50(fd, sb)                              \
  __sanitizer_syscall_pre_impl___fstat50((long)(fd), (long)(sb))
#define __sanitizer_syscall_post___fstat50(res, fd, sb)                        \
  __sanitizer_syscall_post_impl___fstat50(res, (long)(fd), (long)(sb))
#define __sanitizer_syscall_pre___lstat50(path, ub)                            \
  __sanitizer_syscall_pre_impl___lstat50((long)(path), (long)(ub))
#define __sanitizer_syscall_post___lstat50(res, path, ub)                      \
  __sanitizer_syscall_post_impl___lstat50(res, (long)(path), (long)(ub))
#define __sanitizer_syscall_pre_____semctl50(semid, semnum, cmd, arg)          \
  __sanitizer_syscall_pre_impl_____semctl50((long)(semid), (long)(semnum),     \
                                            (long)(cmd), (long)(arg))
#define __sanitizer_syscall_post_____semctl50(res, semid, semnum, cmd, arg)    \
  __sanitizer_syscall_post_impl_____semctl50(                                  \
      res, (long)(semid), (long)(semnum), (long)(cmd), (long)(arg))
#define __sanitizer_syscall_pre___shmctl50(shmid, cmd, buf)                    \
  __sanitizer_syscall_pre_impl___shmctl50((long)(shmid), (long)(cmd),          \
                                          (long)(buf))
#define __sanitizer_syscall_post___shmctl50(res, shmid, cmd, buf)              \
  __sanitizer_syscall_post_impl___shmctl50(res, (long)(shmid), (long)(cmd),    \
                                           (long)(buf))
#define __sanitizer_syscall_pre___msgctl50(msqid, cmd, buf)                    \
  __sanitizer_syscall_pre_impl___msgctl50((long)(msqid), (long)(cmd),          \
                                          (long)(buf))
#define __sanitizer_syscall_post___msgctl50(res, msqid, cmd, buf)              \
  __sanitizer_syscall_post_impl___msgctl50(res, (long)(msqid), (long)(cmd),    \
                                           (long)(buf))
#define __sanitizer_syscall_pre___getrusage50(who, rusage)                     \
  __sanitizer_syscall_pre_impl___getrusage50((long)(who), (long)(rusage))
#define __sanitizer_syscall_post___getrusage50(res, who, rusage)               \
  __sanitizer_syscall_post_impl___getrusage50(res, (long)(who), (long)(rusage))
#define __sanitizer_syscall_pre___timer_settime50(timerid, flags, value,       \
                                                  ovalue)                      \
  __sanitizer_syscall_pre_impl___timer_settime50(                              \
      (long)(timerid), (long)(flags), (long)(value), (long)(ovalue))
#define __sanitizer_syscall_post___timer_settime50(res, timerid, flags, value, \
                                                   ovalue)                     \
  __sanitizer_syscall_post_impl___timer_settime50(                             \
      res, (long)(timerid), (long)(flags), (long)(value), (long)(ovalue))
#define __sanitizer_syscall_pre___timer_gettime50(timerid, value)              \
  __sanitizer_syscall_pre_impl___timer_gettime50((long)(timerid), (long)(value))
#define __sanitizer_syscall_post___timer_gettime50(res, timerid, value)        \
  __sanitizer_syscall_post_impl___timer_gettime50(res, (long)(timerid),        \
                                                  (long)(value))
#if defined(NTP) || !defined(_KERNEL_OPT)
#define __sanitizer_syscall_pre___ntp_gettime50(ntvp)                          \
  __sanitizer_syscall_pre_impl___ntp_gettime50((long)(ntvp))
#define __sanitizer_syscall_post___ntp_gettime50(res, ntvp)                    \
  __sanitizer_syscall_post_impl___ntp_gettime50(res, (long)(ntvp))
#else
/* syscall 448 has been skipped */
#endif
#define __sanitizer_syscall_pre___wait450(pid, status, options, rusage)        \
  __sanitizer_syscall_pre_impl___wait450((long)(pid), (long)(status),          \
                                         (long)(options), (long)(rusage))
#define __sanitizer_syscall_post___wait450(res, pid, status, options, rusage)  \
  __sanitizer_syscall_post_impl___wait450(res, (long)(pid), (long)(status),    \
                                          (long)(options), (long)(rusage))
#define __sanitizer_syscall_pre___mknod50(path, mode, dev)                     \
  __sanitizer_syscall_pre_impl___mknod50((long)(path), (long)(mode),           \
                                         (long)(dev))
#define __sanitizer_syscall_post___mknod50(res, path, mode, dev)               \
  __sanitizer_syscall_post_impl___mknod50(res, (long)(path), (long)(mode),     \
                                          (long)(dev))
#define __sanitizer_syscall_pre___fhstat50(fhp, fh_size, sb)                   \
  __sanitizer_syscall_pre_impl___fhstat50((long)(fhp), (long)(fh_size),        \
                                          (long)(sb))
#define __sanitizer_syscall_post___fhstat50(res, fhp, fh_size, sb)             \
  __sanitizer_syscall_post_impl___fhstat50(res, (long)(fhp), (long)(fh_size),  \
                                           (long)(sb))
/* syscall 452 has been skipped */
#define __sanitizer_syscall_pre_pipe2(fildes, flags)                           \
  __sanitizer_syscall_pre_impl_pipe2((long)(fildes), (long)(flags))
#define __sanitizer_syscall_post_pipe2(res, fildes, flags)                     \
  __sanitizer_syscall_post_impl_pipe2(res, (long)(fildes), (long)(flags))
#define __sanitizer_syscall_pre_dup3(from, to, flags)                          \
  __sanitizer_syscall_pre_impl_dup3((long)(from), (long)(to), (long)(flags))
#define __sanitizer_syscall_post_dup3(res, from, to, flags)                    \
  __sanitizer_syscall_post_impl_dup3(res, (long)(from), (long)(to),            \
                                     (long)(flags))
#define __sanitizer_syscall_pre_kqueue1(flags)                                 \
  __sanitizer_syscall_pre_impl_kqueue1((long)(flags))
#define __sanitizer_syscall_post_kqueue1(res, flags)                           \
  __sanitizer_syscall_post_impl_kqueue1(res, (long)(flags))
#define __sanitizer_syscall_pre_paccept(s, name, anamelen, mask, flags)        \
  __sanitizer_syscall_pre_impl_paccept(                                        \
      (long)(s), (long)(name), (long)(anamelen), (long)(mask), (long)(flags))
#define __sanitizer_syscall_post_paccept(res, s, name, anamelen, mask, flags)  \
  __sanitizer_syscall_post_impl_paccept(res, (long)(s), (long)(name),          \
                                        (long)(anamelen), (long)(mask),        \
                                        (long)(flags))
#define __sanitizer_syscall_pre_linkat(fd1, name1, fd2, name2, flags)          \
  __sanitizer_syscall_pre_impl_linkat((long)(fd1), (long)(name1), (long)(fd2), \
                                      (long)(name2), (long)(flags))
#define __sanitizer_syscall_post_linkat(res, fd1, name1, fd2, name2, flags)    \
  __sanitizer_syscall_post_impl_linkat(res, (long)(fd1), (long)(name1),        \
                                       (long)(fd2), (long)(name2),             \
                                       (long)(flags))
#define __sanitizer_syscall_pre_renameat(fromfd, from, tofd, to)               \
  __sanitizer_syscall_pre_impl_renameat((long)(fromfd), (long)(from),          \
                                        (long)(tofd), (long)(to))
#define __sanitizer_syscall_post_renameat(res, fromfd, from, tofd, to)         \
  __sanitizer_syscall_post_impl_renameat(res, (long)(fromfd), (long)(from),    \
                                         (long)(tofd), (long)(to))
#define __sanitizer_syscall_pre_mkfifoat(fd, path, mode)                       \
  __sanitizer_syscall_pre_impl_mkfifoat((long)(fd), (long)(path), (long)(mode))
#define __sanitizer_syscall_post_mkfifoat(res, fd, path, mode)                 \
  __sanitizer_syscall_post_impl_mkfifoat(res, (long)(fd), (long)(path),        \
                                         (long)(mode))
#define __sanitizer_syscall_pre_mknodat(fd, path, mode, PAD, dev)              \
  __sanitizer_syscall_pre_impl_mknodat((long)(fd), (long)(path), (long)(mode), \
                                       (long)(PAD), (long)(dev))
#define __sanitizer_syscall_post_mknodat(res, fd, path, mode, PAD, dev)        \
  __sanitizer_syscall_post_impl_mknodat(                                       \
      res, (long)(fd), (long)(path), (long)(mode), (long)(PAD), (long)(dev))
#define __sanitizer_syscall_pre_mkdirat(fd, path, mode)                        \
  __sanitizer_syscall_pre_impl_mkdirat((long)(fd), (long)(path), (long)(mode))
#define __sanitizer_syscall_post_mkdirat(res, fd, path, mode)                  \
  __sanitizer_syscall_post_impl_mkdirat(res, (long)(fd), (long)(path),         \
                                        (long)(mode))
#define __sanitizer_syscall_pre_faccessat(fd, path, amode, flag)               \
  __sanitizer_syscall_pre_impl_faccessat((long)(fd), (long)(path),             \
                                         (long)(amode), (long)(flag))
#define __sanitizer_syscall_post_faccessat(res, fd, path, amode, flag)         \
  __sanitizer_syscall_post_impl_faccessat(res, (long)(fd), (long)(path),       \
                                          (long)(amode), (long)(flag))
#define __sanitizer_syscall_pre_fchmodat(fd, path, mode, flag)                 \
  __sanitizer_syscall_pre_impl_fchmodat((long)(fd), (long)(path),              \
                                        (long)(mode), (long)(flag))
#define __sanitizer_syscall_post_fchmodat(res, fd, path, mode, flag)           \
  __sanitizer_syscall_post_impl_fchmodat(res, (long)(fd), (long)(path),        \
                                         (long)(mode), (long)(flag))
#define __sanitizer_syscall_pre_fchownat(fd, path, owner, group, flag)         \
  __sanitizer_syscall_pre_impl_fchownat(                                       \
      (long)(fd), (long)(path), (long)(owner), (long)(group), (long)(flag))
#define __sanitizer_syscall_post_fchownat(res, fd, path, owner, group, flag)   \
  __sanitizer_syscall_post_impl_fchownat(res, (long)(fd), (long)(path),        \
                                         (long)(owner), (long)(group),         \
                                         (long)(flag))
#define __sanitizer_syscall_pre_fexecve(fd, argp, envp)                        \
  __sanitizer_syscall_pre_impl_fexecve((long)(fd), (long)(argp), (long)(envp))
#define __sanitizer_syscall_post_fexecve(res, fd, argp, envp)                  \
  __sanitizer_syscall_post_impl_fexecve(res, (long)(fd), (long)(argp),         \
                                        (long)(envp))
#define __sanitizer_syscall_pre_fstatat(fd, path, buf, flag)                   \
  __sanitizer_syscall_pre_impl_fstatat((long)(fd), (long)(path), (long)(buf),  \
                                       (long)(flag))
#define __sanitizer_syscall_post_fstatat(res, fd, path, buf, flag)             \
  __sanitizer_syscall_post_impl_fstatat(res, (long)(fd), (long)(path),         \
                                        (long)(buf), (long)(flag))
#define __sanitizer_syscall_pre_utimensat(fd, path, tptr, flag)                \
  __sanitizer_syscall_pre_impl_utimensat((long)(fd), (long)(path),             \
                                         (long)(tptr), (long)(flag))
#define __sanitizer_syscall_post_utimensat(res, fd, path, tptr, flag)          \
  __sanitizer_syscall_post_impl_utimensat(res, (long)(fd), (long)(path),       \
                                          (long)(tptr), (long)(flag))
#define __sanitizer_syscall_pre_openat(fd, path, oflags, mode)                 \
  __sanitizer_syscall_pre_impl_openat((long)(fd), (long)(path),                \
                                      (long)(oflags), (long)(mode))
#define __sanitizer_syscall_post_openat(res, fd, path, oflags, mode)           \
  __sanitizer_syscall_post_impl_openat(res, (long)(fd), (long)(path),          \
                                       (long)(oflags), (long)(mode))
#define __sanitizer_syscall_pre_readlinkat(fd, path, buf, bufsize)             \
  __sanitizer_syscall_pre_impl_readlinkat((long)(fd), (long)(path),            \
                                          (long)(buf), (long)(bufsize))
#define __sanitizer_syscall_post_readlinkat(res, fd, path, buf, bufsize)       \
  __sanitizer_syscall_post_impl_readlinkat(res, (long)(fd), (long)(path),      \
                                           (long)(buf), (long)(bufsize))
#define __sanitizer_syscall_pre_symlinkat(path1, fd, path2)                    \
  __sanitizer_syscall_pre_impl_symlinkat((long)(path1), (long)(fd),            \
                                         (long)(path2))
#define __sanitizer_syscall_post_symlinkat(res, path1, fd, path2)              \
  __sanitizer_syscall_post_impl_symlinkat(res, (long)(path1), (long)(fd),      \
                                          (long)(path2))
#define __sanitizer_syscall_pre_unlinkat(fd, path, flag)                       \
  __sanitizer_syscall_pre_impl_unlinkat((long)(fd), (long)(path), (long)(flag))
#define __sanitizer_syscall_post_unlinkat(res, fd, path, flag)                 \
  __sanitizer_syscall_post_impl_unlinkat(res, (long)(fd), (long)(path),        \
                                         (long)(flag))
#define __sanitizer_syscall_pre_futimens(fd, tptr)                             \
  __sanitizer_syscall_pre_impl_futimens((long)(fd), (long)(tptr))
#define __sanitizer_syscall_post_futimens(res, fd, tptr)                       \
  __sanitizer_syscall_post_impl_futimens(res, (long)(fd), (long)(tptr))
#define __sanitizer_syscall_pre___quotactl(path, args)                         \
  __sanitizer_syscall_pre_impl___quotactl((long)(path), (long)(args))
#define __sanitizer_syscall_post___quotactl(res, path, args)                   \
  __sanitizer_syscall_post_impl___quotactl(res, (long)(path), (long)(args))
#define __sanitizer_syscall_pre_posix_spawn(pid, path, file_actions, attrp,    \
                                            argv, envp)                        \
  __sanitizer_syscall_pre_impl_posix_spawn(                                    \
      (long)(pid), (long)(path), (long)(file_actions), (long)(attrp),          \
      (long)(argv), (long)(envp))
#define __sanitizer_syscall_post_posix_spawn(res, pid, path, file_actions,     \
                                             attrp, argv, envp)                \
  __sanitizer_syscall_post_impl_posix_spawn(                                   \
      res, (long)(pid), (long)(path), (long)(file_actions), (long)(attrp),     \
      (long)(argv), (long)(envp))
#define __sanitizer_syscall_pre_recvmmsg(s, mmsg, vlen, flags, timeout)        \
  __sanitizer_syscall_pre_impl_recvmmsg((long)(s), (long)(mmsg), (long)(vlen), \
                                        (long)(flags), (long)(timeout))
#define __sanitizer_syscall_post_recvmmsg(res, s, mmsg, vlen, flags, timeout)  \
  __sanitizer_syscall_post_impl_recvmmsg(res, (long)(s), (long)(mmsg),         \
                                         (long)(vlen), (long)(flags),          \
                                         (long)(timeout))
#define __sanitizer_syscall_pre_sendmmsg(s, mmsg, vlen, flags)                 \
  __sanitizer_syscall_pre_impl_sendmmsg((long)(s), (long)(mmsg), (long)(vlen), \
                                        (long)(flags))
#define __sanitizer_syscall_post_sendmmsg(res, s, mmsg, vlen, flags)           \
  __sanitizer_syscall_post_impl_sendmmsg(res, (long)(s), (long)(mmsg),         \
                                         (long)(vlen), (long)(flags))
#define __sanitizer_syscall_pre_clock_nanosleep(clock_id, flags, rqtp, rmtp)   \
  __sanitizer_syscall_pre_impl_clock_nanosleep(                                \
      (long)(clock_id), (long)(flags), (long)(rqtp), (long)(rmtp))
#define __sanitizer_syscall_post_clock_nanosleep(res, clock_id, flags, rqtp,   \
                                                 rmtp)                         \
  __sanitizer_syscall_post_impl_clock_nanosleep(                               \
      res, (long)(clock_id), (long)(flags), (long)(rqtp), (long)(rmtp))
#define __sanitizer_syscall_pre____lwp_park60(clock_id, flags, ts, unpark,     \
                                              hint, unparkhint)                \
  __sanitizer_syscall_pre_impl____lwp_park60((long)(clock_id), (long)(flags),  \
                                             (long)(ts), (long)(unpark),       \
                                             (long)(hint), (long)(unparkhint))
#define __sanitizer_syscall_post____lwp_park60(res, clock_id, flags, ts,       \
                                               unpark, hint, unparkhint)       \
  __sanitizer_syscall_post_impl____lwp_park60(                                 \
      res, (long)(clock_id), (long)(flags), (long)(ts), (long)(unpark),        \
      (long)(hint), (long)(unparkhint))
#define __sanitizer_syscall_pre_posix_fallocate(fd, PAD, pos, len)             \
  __sanitizer_syscall_pre_impl_posix_fallocate((long)(fd), (long)(PAD),        \
                                               (long)(pos), (long)(len))
#define __sanitizer_syscall_post_posix_fallocate(res, fd, PAD, pos, len)       \
  __sanitizer_syscall_post_impl_posix_fallocate(res, (long)(fd), (long)(PAD),  \
                                                (long)(pos), (long)(len))
#define __sanitizer_syscall_pre_fdiscard(fd, PAD, pos, len)                    \
  __sanitizer_syscall_pre_impl_fdiscard((long)(fd), (long)(PAD), (long)(pos),  \
                                        (long)(len))
#define __sanitizer_syscall_post_fdiscard(res, fd, PAD, pos, len)              \
  __sanitizer_syscall_post_impl_fdiscard(res, (long)(fd), (long)(PAD),         \
                                         (long)(pos), (long)(len))
#define __sanitizer_syscall_pre_wait6(idtype, id, status, options, wru, info)  \
  __sanitizer_syscall_pre_impl_wait6((long)(idtype), (long)(id),               \
                                     (long)(status), (long)(options),          \
                                     (long)(wru), (long)(info))
#define __sanitizer_syscall_post_wait6(res, idtype, id, status, options, wru,  \
                                       info)                                   \
  __sanitizer_syscall_post_impl_wait6(res, (long)(idtype), (long)(id),         \
                                      (long)(status), (long)(options),         \
                                      (long)(wru), (long)(info))
#define __sanitizer_syscall_pre_clock_getcpuclockid2(idtype, id, clock_id)     \
  __sanitizer_syscall_pre_impl_clock_getcpuclockid2(                           \
      (long)(idtype), (long)(id), (long)(clock_id))
#define __sanitizer_syscall_post_clock_getcpuclockid2(res, idtype, id,         \
                                                      clock_id)                \
  __sanitizer_syscall_post_impl_clock_getcpuclockid2(                          \
      res, (long)(idtype), (long)(id), (long)(clock_id))

#ifdef __cplusplus
extern "C" {
#endif

// Private declarations. Do not call directly from user code. Use macros above.

// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!

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
#if !defined(_LP64)
void __sanitizer_syscall_pre_impl_compat_10_osemsys();
void __sanitizer_syscall_post_impl_compat_10_osemsys();
#else
/* syscall 169 has been skipped */
#if !defined(_LP64)
void __sanitizer_syscall_pre_impl_compat_10_omsgsys();
void __sanitizer_syscall_post_impl_compat_10_omsgsys();
#else
/* syscall 170 has been skipped */
#if !defined(_LP64)
void __sanitizer_syscall_pre_impl_compat_10_oshmsys();
void __sanitizer_syscall_post_impl_compat_10_oshmsys();
#else
/* syscall 171 has been skipped */
#endif
/* syscall 172 has been skipped */
void __sanitizer_syscall_pre_impl_pread();
void __sanitizer_syscall_post_impl_pread();
void __sanitizer_syscall_pre_impl_pwrite();
void __sanitizer_syscall_post_impl_pwrite();
void __sanitizer_syscall_pre_impl_compat_30_ntp_gettime();
void __sanitizer_syscall_post_impl_compat_30_ntp_gettime();
#if defined(NTP) || !defined(_KERNEL_OPT)
void __sanitizer_syscall_pre_impl_ntp_adjtime();
void __sanitizer_syscall_post_impl_ntp_adjtime();
#else
/* syscall 176 has been skipped */
#endif
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
#if defined(NTP) || !defined(_KERNEL_OPT)
void __sanitizer_syscall_pre_impl___ntp_gettime50();
void __sanitizer_syscall_post_impl___ntp_gettime50();
#else
/* syscall 448 has been skipped */
#endif
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

// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!

#endif // SANITIZER_NETBSD_SYSCALL_HOOKS_H
