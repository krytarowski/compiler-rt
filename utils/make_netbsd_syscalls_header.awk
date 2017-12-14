#!/usr/bin/awk -f

#===-- make_netbsd_syscalls_header.awk -------------------------------------===#
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
#
# This script accepts on the input syscalls.master by default located in the
# /usr/src/sys/kern/syscalls.master path in the NetBSD distribution.
#
#===------------------------------------------------------------------------===#

BEGIN {
  # harcode the script name
  script_name = "make_netbsd_syscalls_header.awk"
  output = "../include/sanitizer/netbsd_syscall_hooks.h"

  # assert that we are in the directory with scripts
  in_utils = system("test -f " script_name " && exit 1 || exit 0")
  if (in_utils == 0) {
    usage()
  }

  # assert 1 argument passed
  if (ARGC != 2) {
    usage()
  }

  # assert argument is a valid file path to syscall.master
  if (system("test -f " ARGV[1]) != 0) {
    usage()
  }

  # sanity check that the path ends with "syscall.master"
  if (ARGV[1] !~ /syscalls\.master$/) {
    usage()
  }

  # accept overloading CLANGFORMAT from environment
  clangformat = "clang-format"
  if ("CLANGFORMAT" in ENVIRON) {
    clangformat = ENVIRON["CLANGFORMAT"]
  }

  # parsing specific symbols
  parsingheader=1

  parsedsyscalls=0
  SYS_MAXSYSARGS=8
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

  # Extract syscall arguments
  if (match($0, /\([^)]+\)/)) {
    print substr($0, RSTART + 1, RLENGTH - 2)
  }

  parsedsyscalls++;

  # Done with this line
  next
}


END {
  # Handle abnormal exit
  if (abnormal_exit) {
    exit(abnormal_exit)
  }

  # open pipe
  cmd = clangformat " > " output

  print "hello world" | cmd
  print "//===-- netbsd_syscall_hooks.h --------------------------------------------===//" | cmd
  print "//" | cmd
  print "//                     The LLVM Compiler Infrastructure" | cmd
  print "//" | cmd
  print "// This file is distributed under the University of Illinois Open Source" | cmd
  print "// License. See LICENSE.TXT for details." | cmd
  print "//" | cmd
  print "//===----------------------------------------------------------------------===//" | cmd
  print "//" | cmd
  print "// This file is a part of public sanitizer interface." | cmd
  print "//" | cmd
  print "// System call handlers." | cmd
  print "//" | cmd
  print "// Interface methods declared in this header implement pre- and post- syscall" | cmd
  print "// actions for the active sanitizer." | cmd
  print "// Usage:" | cmd
  print "//   __sanitizer_syscall_pre_getfoo(...args...);" | cmd
  print "//   long res = syscall(SYS_getfoo, ...args...);" | cmd
  print "//   __sanitizer_syscall_post_getfoo(res, ...args...);" | cmd
  print "//" | cmd
  print "// DO NOT EDIT! THIS FILE HAS BEEN AUTOMATICALLY GENERATED" | cmd
  print "//" | cmd
  print "//===----------------------------------------------------------------------===//" | cmd
  print "#ifndef SANITIZER_NETBSD_SYSCALL_HOOKS_H" | cmd
  print "#define SANITIZER_NETBSD_SYSCALL_HOOKS_H" | cmd
  print "" | cmd

  for (i = 0; i < parsedsyscalls; i++) {

    if (i in ifelifelseendif) { 
      print ifelifelseendif[i]
    } 

    sn = syscalls[i];
   
    if (sn ~ /^\$/) {
      print "/* syscall " substr(sn,2) " has been skipped */" | cmd
      continue
    }

    print "#define __sanitizer_syscall_pre_" sn "() \\" | cmd
    print "  __sanitizer_syscall_pre_impl_" sn "()" | cmd
    print "#define __sanitizer_syscall_post_" sn "() \\" | cmd
    print "  __sanitizer_syscall_post_impl_" sn "()" | cmd
  }

  print "" | cmd
  print "#ifdef __cplusplus" | cmd
  print "extern \"C\" {" | cmd
  print "#endif" | cmd
  print "" | cmd
  print "// Private declarations. Do not call directly from user code. Use macros above." | cmd

  for (i = 0; i < parsedsyscalls; i++) {
    sn = syscalls[i];
   
    if (sn ~ /^\$/) {
      print "/* syscall " substr(sn,2) " has been skipped */" | cmd
      continue
    }

    print "void __sanitizer_syscall_pre_impl_" sn "();" | cmd
    print "void __sanitizer_syscall_post_impl_" sn "();" | cmd
  }

  print "" | cmd
  print "#ifdef __cplusplus" | cmd
  print "} // extern \"C\"" | cmd
  print "#endif" | cmd
  print "" | cmd
  print "#endif  // SANITIZER_NETBSD_SYSCALL_HOOKS_H" | cmd

  close(cmd)
}

function usage()
{
  print "Usage: " script_name " syscalls.master"
  abnormal_exit = 1
  exit 1
}
