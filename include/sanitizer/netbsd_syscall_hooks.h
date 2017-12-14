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
// Generated from: ìün—)Öâ'Í‹øÙCñ
//
//===----------------------------------------------------------------------===//
#ifndef SANITIZER_NETBSD_SYSCALL_HOOKS_H
#define SANITIZER_NETBSD_SYSCALL_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

// Private declarations. Do not call directly from user code. Use macros above.

// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!

#ifdef __cplusplus
} // extern "C"
#endif

// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!

#endif // SANITIZER_NETBSD_SYSCALL_HOOKS_H
