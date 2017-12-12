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
clangformat=${CLANGFORMAT:-clang-format}

topdir=${TOPDIR:-..}
nbsdsyscallhooksh=$topdir/include/sanitizer/netbsd_syscall_hooks.h
sanitizernbsyscallsinc=$topdir/lib/sanitizer_common/sanitizer_common_syscalls.inc

# Generate include/sanitizer/netbsd_syscall_hooks.h

echo -n "Generating include/sanitizer/netbsd_syscall_hooks.h ..."

cat $1 | $nbawk '
BEGIN {
  parsingheader=1

  parsedsyscalls=0

  print "//===-- netbsd_syscall_hooks.h --------------------------------------------===//"
  print "//"
  print "//                     The LLVM Compiler Infrastructure"
  print "//"
  print "// This file is distributed under the University of Illinois Open Source"
  print "// License. See LICENSE.TXT for details."
  print "//"
  print "//===----------------------------------------------------------------------===//"
  print "//"
  print "// This file is a part of public sanitizer interface."
  print "//"
  print "// System call handlers."
  print "//"
  print "// Interface methods declared in this header implement pre- and post- syscall"
  print "// actions for the active sanitizer."
  print "// Usage:"
  print "//   __sanitizer_syscall_pre_getfoo(...args...);"
  print "//   long res = syscall(SYS_getfoo, ...args...);"
  print "//   __sanitizer_syscall_post_getfoo(res, ...args...);"
  print "//"
  print "// DO NOT EDIT! THIS FILE HAS BEEN AUTOMATICALLY GENERATED"
  print "//"
  print "//===----------------------------------------------------------------------===//"
  print "#ifndef SANITIZER_NETBSD_SYSCALL_HOOKS_H"
  print "#define SANITIZER_NETBSD_SYSCALL_HOOKS_H"
  print ""
}

# skip the following lines
#  - empty
NF == 0 {
  next
}
#  - comment
$1 == ";" {
  next
}

# separator between the header and table with syscalls
$0 == "%%" {
  parsingheader = 0
  next
}

# preserve 'if/elif/else/endif' C preprocessor as-is
parsingheader == 0 && $0 ~ /^#/ {
  ifelifelseendif[parsedsyscalls] = $0
  next
}

# parsing of syscall definitions
parsingheader == 0 && $1 ~ /^[0-9]+$/ {
  # first join multiple lines into single one
  while (sub(/\\$/, "")) {
    getline line
    $0 = $0 "" line
  }

  # Skip unwanted syscalls
  skip=0
  if ($0 ~ /OBSOL/ || $0 ~ /EXCL/ || $0 ~ /UNIMPL/) {
    skip=1
  }

  # Compose the syscall name
  #  - compat?
  compat=""
  if (match($0, /COMPAT_[0-9]+/)) {
    compat = tolower(substr($0, RSTART, RLENGTH))
  }
  # - alias name?
  alias=""
  if ($(NF) != "}" && !skip) {
    alias = alias "" $(NF)
  }
  # - compat version?
  compatver=""
  if (match($0, /\|[0-9]+\|/)) {
    compatver = tolower(substr($0, RSTART + 1, RLENGTH - 2))
  }
  # - basename?
  basename=""
  if (skip) {
    basename = $1
  } else {
    if (match($0, /\|[_a-z0-9]+\(/)) {
      basename = tolower(substr($0, RSTART + 1, RLENGTH - 2))
    }
  }

  syscallname=""

  if (skip) {
    syscallname= syscallname "$"
  }

  if (length(compat) > 0) {
    syscallname = syscallname "" compat "_";
  }
  if (length(alias) > 0) {
    syscallname = syscallname "" alias;
  } else {
    if (length(compatver) > 0) {
      syscallname = syscallname "__" basename "" compatver;
    } else {
      syscallname = syscallname "" basename;
    }
  }

  # Store the syscallname
  syscalls[parsedsyscalls]=syscallname;
  parsedsyscalls++;

  # Done with this line
  next
}

END {
  for (i = 0; i < parsedsyscalls; i++) {

    if (i in ifelifelseendif) {
      print ifelifelseendif[i]
    }

    sn = syscalls[i];

    if (sn ~ /^\$/) {
      print "/* syscall " substr(sn,2) " has been skipped */"
      continue
    }

    print "#define __sanitizer_syscall_pre_" sn "() \\"
    print "  __sanitizer_syscall_pre_impl_" sn "()"
    print "#define __sanitizer_syscall_post_" sn "() \\"
    print "  __sanitizer_syscall_post_impl_" sn "()"
  }

  print ""
  print "#ifdef __cplusplus"
  print "extern \"C\" {"
  print "#endif"
  print ""
  print "// Private declarations. Do not call directly from user code. Use macros above."

  for (i = 0; i < parsedsyscalls; i++) {
    sn = syscalls[i];

    if (sn ~ /^\$/) {
      print "/* syscall " substr(sn,2) " has been skipped */"
      continue
    }

    print "void __sanitizer_syscall_pre_impl_" sn "();"
    print "void __sanitizer_syscall_post_impl_" sn "();"
  }

  print ""
  print "#ifdef __cplusplus"
  print "} // extern \"C\""
  print "#endif"
  print ""
  print "#endif  // SANITIZER_NETBSD_SYSCALL_HOOKS_H"
}
' | $clangformat - > $nbsdsyscallhooksh

echo "OK"

# Generate lib/sanitizer_common/sanitizer_common_syscalls.inc

echo -n "Generating lib/sanitizer_common/sanitizer_common_syscalls.inc ..."

cat $1 | $nbawk '
BEGIN {
}
NR == 1 {
  print "//===-- sanitizer_netbsd_syscalls.inc ---------------------------*- C++ -*-===//"
  print "//"
  print "//                     The LLVM Compiler Infrastructure"
  print "//"
  print "// This file is distributed under the University of Illinois Open Source"
  print "// License. See LICENSE.TXT for details."
  print "//"
  print "//===----------------------------------------------------------------------===//"
  print "//"
  print "// NetBSD syscalls handlers for tools like AddressSanitizer,"
  print "// ThreadSanitizer, MemorySanitizer, etc."
  print "//"
  print "// DO NOT EDIT! THIS FILE HAS BEEN AUTOMATICALLY GENERATED"
  print "//"
  print "//===----------------------------------------------------------------------===//"
}
' | $clangformat - > $sanitizernbsyscallsinc

echo "OK"
