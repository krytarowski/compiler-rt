#!/bin/sh
#===-- makenetbsdsyscalls.sh -----------------------------------------------===#
#
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
#
# This file is a generator of:
#  - include/sanitizer/netbsd_syscall_hooks.h
#  - lib/sanitizer_common/sanitizer_common_syscalls.inc
#
# This script accepts on the input syscalls.master by default located in the
# /usr/src/sys/kern/syscalls.master path in the NetBSD distribution.
#
# All the per-syscall rules are hardcoded in this file.
#
#===------------------------------------------------------------------------===#

set -e

if [ $# -ne 1 ]; then
	echo "Usage: $0 syscalls.master"
	exit 1
fi

if [ ! -e $1 ]; then
	echo "Usage: $0 syscalls.master"
	echo "File $1: not found"
	exit 1
fi

# NetBSD awk(1) or compatible (like gawk(1)).
nbawk=${AWK:-awk}

topdir=${TOPDIR:-..}
nbsdsyscallhooksh=$topdir/include/sanitizer/netbsd_syscall_hooks.h
sanitizernbsyscallsinc=$topdir/lib/sanitizer_common/sanitizer_common_syscalls.inc

# Generate include/sanitizer/netbsd_syscall_hooks.h

echo -n "Generating include/sanitizer/netbsd_syscall_hooks.h..."

cat $1 | $nbawk '
BEGIN {
}
NR == 1 {
  printf "//===-- sanitizer_netbsd_syscalls.inc ---------------------------*- C++ -*-===//\n"
  printf "//\n"
  printf "//                     The LLVM Compiler Infrastructure\n"
  printf "//\n"
  printf "// This file is distributed under the University of Illinois Open Source\n"
  printf "// License. See LICENSE.TXT for details.\n"
  printf "//\n"
  printf "//===----------------------------------------------------------------------===//\n"
  printf "//\n"
  printf "// NetBSD syscalls handlers for tools like AddressSanitizer,\n"
  printf "// ThreadSanitizer, MemorySanitizer, etc.\n"
  printf "//\n"
  printf "// DO NOT EDIT! THIS FILE HAS BEEN AUTOMATICALLY GENERATED\n"
  printf "//\n"
  printf "//===----------------------------------------------------------------------===//\n"
}
' > $nbsdsyscallhooksh

echo "OK"

# Generate lib/sanitizer_common/sanitizer_common_syscalls.inc

echo -n "Generating lib/sanitizer_common/sanitizer_common_syscalls.inc..."

cat $1 | $nbawk "
 
" > $nbsdsyscallhooksh

echo "OK"
