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

# Parse the RCS ID from syscall.master
parsingheader == 1 && NR == 1 {
  if (match($0, /\$[^$]+\$/)) {
    # trim initial '$NetBSD: ' and trailing ' $'
    syscallmasterversion = substr($0, RSTART + 9, RLENGTH - 11)
  } else {
    # wrong file?
    usage()
  }
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
    syscallname = syscallname "" compat "_"
  }
  if (length(alias) > 0) {
    syscallname = syscallname "" alias
  } else {
    if (length(compatver) > 0) {
      syscallname = syscallname "__" basename "" compatver
    } else {
      syscallname = syscallname "" basename
    }
  }

  # Store the syscallname
  syscalls[parsedsyscalls]=syscallname

  # Extract syscall arguments
  if (match($0, /\([^)]+\)/)) {
    args = substr($0, RSTART + 1, RLENGTH - 2)
    if (args == "void") {
      syscallargs[parsedsyscalls] = "void"
    } else {
      n = split(args, a, ",")

      # Handle the first argument
      gsub(".+[ *]", "", a[1])
      syscallargs[parsedsyscalls] = a[1]

      # Handle the rest of arguments
      for (i = 1; i <= n; i++) {
	gsub(".+[ *]", "", a[i])
        syscallargs[parsedsyscalls] = syscallargs[parsedsyscalls] "," a[i]
      }
      syscallargs[parsedsyscalls] = "void"
    }
  }

  parsedsyscalls++

  # Done with this line
  next
}


END {
  # empty file?
  if (NR < 1 && !abnormal_exit) {
    usage()
  }

  # Handle abnormal exit
  if (abnormal_exit) {
    exit(abnormal_exit)
  }

  # open pipe
  cmd = clangformat " > " output

  pcmd("//===-- netbsd_syscall_hooks.h --------------------------------------------===//")
  pcmd("//")
  pcmd("//                     The LLVM Compiler Infrastructure")
  pcmd("//")
  pcmd("// This file is distributed under the University of Illinois Open Source")
  pcmd("// License. See LICENSE.TXT for details.")
  pcmd("//")
  pcmd("//===----------------------------------------------------------------------===//")
  pcmd("//")
  pcmd("// This file is a part of public sanitizer interface.")
  pcmd("//")
  pcmd("// System call handlers.")
  pcmd("//")
  pcmd("// Interface methods declared in this header implement pre- and post- syscall")
  pcmd("// actions for the active sanitizer.")
  pcmd("// Usage:")
  pcmd("//   __sanitizer_syscall_pre_getfoo(...args...);")
  pcmd("//   long res = syscall(SYS_getfoo, ...args...);")
  pcmd("//   __sanitizer_syscall_post_getfoo(res, ...args...);")
  pcmd("//")
  pcmd("// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!")
  pcmd("//")
  pcmd("// Generated with: " script_name)
  pcmd("// Generated date: " strftime("%F"))
  pcmd("// Generated from: " syscallmasterversion)
  pcmd("//")
  pcmd("//===----------------------------------------------------------------------===//")
  pcmd("#ifndef SANITIZER_NETBSD_SYSCALL_HOOKS_H")
  pcmd("#define SANITIZER_NETBSD_SYSCALL_HOOKS_H")
  pcmd("")

  for (i = 0; i < parsedsyscalls; i++) {

    if (i in ifelifelseendif) { 
      pcmd(ifelifelseendif[i])
    } 

    sn = syscalls[i]
   
    if (sn ~ /^\$/) {
      pcmd("/* syscall " substr(sn,2) " has been skipped */")
      continue
    }

    preargs = ""

    if (syscallargs[i] != "void") {
      preargs = syscallargs[i]
      gsub(/,/, /, /, preargs)
    }

    postargs = "res"

    pcmd("#define __sanitizer_syscall_pre_" sn "(" preargs ") \\")
    pcmd("  __sanitizer_syscall_pre_impl_" sn "()")
    pcmd("#define __sanitizer_syscall_post_" sn "(res) \\")
    pcmd("  __sanitizer_syscall_post_impl_" sn "(res, )")
  }

  pcmd("")
  pcmd("#ifdef __cplusplus")
  pcmd("extern \"C\" {")
  pcmd("#endif")
  pcmd("")
  pcmd("// Private declarations. Do not call directly from user code. Use macros above.")
  pcmd("")
  pcmd("// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!")
  pcmd("")

  for (i = 0; i < parsedsyscalls; i++) {

    if (i in ifelifelseendif) {
      pcmd(ifelifelseendif[i])
    }

    sn = syscalls[i]

    if (sn ~ /^\$/) {
      pcmd("/* syscall " substr(sn,2) " has been skipped */")
      continue
    }

    pcmd("void __sanitizer_syscall_pre_impl_" sn "();")
    pcmd("void __sanitizer_syscall_post_impl_" sn "();")
  }

  pcmd("")
  pcmd("#ifdef __cplusplus")
  pcmd("} // extern \"C\"")
  pcmd("#endif")

  pcmd("")
  pcmd("// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!")
  pcmd("")

  pcmd("#endif  // SANITIZER_NETBSD_SYSCALL_HOOKS_H")

  close(cmd)
}

function usage()
{
  print "Usage: " script_name " syscalls.master"
  abnormal_exit = 1
  exit 1
}

function pcmd(string)
{
	print string | cmd
}
