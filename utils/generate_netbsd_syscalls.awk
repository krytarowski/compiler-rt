#!/usr/bin/awk -f

# TODO:
# - Research Linux specific restart_syscall for NetBSD, not needed?
#

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
  script_name = "generate_netbsd_syscalls.awk"
  outputh = "../include/sanitizer/netbsd_syscall_hooks.h"
  outputinc = "../lib/sanitizer_common/sanitizer_netbsd_syscalls.inc"

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

  # Hardcoded in algorithm
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
  if (parsedsyscalls in ifelifelseendif) {
    ifelifelseendif[parsedsyscalls] = ifelifelseendif[parsedsyscalls] "\n" $0
  } else {
    ifelifelseendif[parsedsyscalls] = $0
  }
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
      syscallfullargs[parsedsyscalls] = "void"
    } else {
      n = split(args, a, ",")

      # Handle the first argument
      match(a[1], /[*_a-z0-9\[\]]+$/)
      syscallfullargs[parsedsyscalls] = substr(a[1], RSTART)

      gsub(".+[ *]", "", a[1])
      syscallargs[parsedsyscalls] = a[1]

      # Handle the rest of arguments
      for (i = 2; i <= n; i++) {
        match(a[i], /[*_a-zA-Z0-9\[\]]+$/)
        syscallfullargs[parsedsyscalls] = syscallfullargs[parsedsyscalls] "$" substr(a[i], RSTART)
	gsub(".+[ *]", "", a[i])
        syscallargs[parsedsyscalls] = syscallargs[parsedsyscalls] "$" a[i]
      }

      # Handle array arguments for syscall(2) and __syscall(2)
      nargs = "arg0$arg1$arg2$arg3$arg4$arg5$arg6$arg7"
      gsub(/args\[SYS_MAXSYSARGS\]/, nargs, syscallargs[parsedsyscalls])
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

  # Generate sanitizer_common_syscalls.inc

  # open pipe
  cmd = clangformat " > " outputh

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

    inargs = ""

    if (syscallargs[i] != "void") {
      inargs = syscallargs[i]
      gsub(/\$/, ", ", inargs)
    }

    outargs = ""

    if (syscallargs[i] != "void") {
      outargs = "(long)(" syscallargs[i] ")"
      gsub(/\$/, "), (long)(", outargs)
    }

    pcmd("#define __sanitizer_syscall_pre_" sn "(" inargs ") \\")
    pcmd("  __sanitizer_syscall_pre_impl_" sn "(" outargs ")")

    if (inargs == "") {
      inargs = "res"
    } else {
      inargs = "res, " inargs
    }

    if (outargs == "") {
      outargs = "res"
    } else {
      outargs = "res, " outargs
    }

    pcmd("#define __sanitizer_syscall_post_" sn "(" inargs ") \\")
    pcmd("  __sanitizer_syscall_post_impl_" sn "(" outargs ")")
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

    preargs = syscallargs[i]

    if (preargs != "void") {
      preargs = "long " preargs
      gsub(/\$/, ", long ", preargs)
    }

    if (preargs == "void") {
      postargs = "long res"
    } else {
      postargs = "long res, " preargs
    }

    pcmd("void __sanitizer_syscall_pre_impl_" sn "(" preargs ");")
    pcmd("void __sanitizer_syscall_post_impl_" sn "(" postargs ");")
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

  # Generate sanitizer_common_syscalls.inc

  # open pipe
  cmd = clangformat " > " outputinc

  pcmd("//===-- sanitizer_common_syscalls.inc ---------------------------*- C++ -*-===//")
  pcmd("//")
  pcmd("//                     The LLVM Compiler Infrastructure")
  pcmd("//")
  pcmd("// This file is distributed under the University of Illinois Open Source")
  pcmd("// License. See LICENSE.TXT for details.")
  pcmd("//")
  pcmd("//===----------------------------------------------------------------------===//")
  pcmd("//")
  pcmd("// Common syscalls handlers for tools like AddressSanitizer,")
  pcmd("// ThreadSanitizer, MemorySanitizer, etc.")
  pcmd("//")
  pcmd("// This file should be included into the tool's interceptor file,")
  pcmd("// which has to define it's own macros:")
  pcmd("//   COMMON_SYSCALL_PRE_READ_RANGE")
  pcmd("//          Called in prehook for regions that will be read by the kernel and")
  pcmd("//          must be initialized.")
  pcmd("//   COMMON_SYSCALL_PRE_WRITE_RANGE")
  pcmd("//          Called in prehook for regions that will be written to by the kernel")
  pcmd("//          and must be addressable. The actual write range may be smaller than")
  pcmd("//          reported in the prehook. See POST_WRITE_RANGE.")
  pcmd("//   COMMON_SYSCALL_POST_READ_RANGE")
  pcmd("//          Called in posthook for regions that were read by the kernel. Does")
  pcmd("//          not make much sense.")
  pcmd("//   COMMON_SYSCALL_POST_WRITE_RANGE")
  pcmd("//          Called in posthook for regions that were written to by the kernel")
  pcmd("//          and are now initialized.")
  pcmd("//   COMMON_SYSCALL_ACQUIRE(addr)")
  pcmd("//          Acquire memory visibility from addr.")
  pcmd("//   COMMON_SYSCALL_RELEASE(addr)")
  pcmd("//          Release memory visibility to addr.")
  pcmd("//   COMMON_SYSCALL_FD_CLOSE(fd)")
  pcmd("//          Called before closing file descriptor fd.")
  pcmd("//   COMMON_SYSCALL_FD_ACQUIRE(fd)")
  pcmd("//          Acquire memory visibility from fd.")
  pcmd("//   COMMON_SYSCALL_FD_RELEASE(fd)")
  pcmd("//          Release memory visibility to fd.")
  pcmd("//   COMMON_SYSCALL_PRE_FORK()")
  pcmd("//          Called before fork syscall.")
  pcmd("//   COMMON_SYSCALL_POST_FORK(long res)")
  pcmd("//          Called after fork syscall.")
  pcmd("//")
  pcmd("// DO NOT EDIT! THIS FILE HAS BEEN GENERATED!")
  pcmd("//")
  pcmd("// Generated with: " script_name)
  pcmd("// Generated date: " strftime("%F"))
  pcmd("// Generated from: " syscallmasterversion)
  pcmd("//")
  pcmd("//===----------------------------------------------------------------------===//")
  pcmd("")
  pcmd("#include \"sanitizer_platform.h\"")
  pcmd("#if SANITIZER_NETBSD")
  pcmd("")
  pcmd("#include \"sanitizer_libc.h\"")
  pcmd("")
  pcmd("#define PRE_SYSCALL(name)                                                      \\")
  pcmd("  SANITIZER_INTERFACE_ATTRIBUTE void __sanitizer_syscall_pre_impl_##name")
  pcmd("#define PRE_READ(p, s) COMMON_SYSCALL_PRE_READ_RANGE(p, s)")
  pcmd("#define PRE_WRITE(p, s) COMMON_SYSCALL_PRE_WRITE_RANGE(p, s)")
  pcmd("")
  pcmd("#define POST_SYSCALL(name)                                                     \\")
  pcmd("  SANITIZER_INTERFACE_ATTRIBUTE void __sanitizer_syscall_post_impl_##name")
  pcmd("#define POST_READ(p, s) COMMON_SYSCALL_POST_READ_RANGE(p, s)")
  pcmd("#define POST_WRITE(p, s) COMMON_SYSCALL_POST_WRITE_RANGE(p, s)")
  pcmd("")
  pcmd("#ifndef COMMON_SYSCALL_ACQUIRE")
  pcmd("# define COMMON_SYSCALL_ACQUIRE(addr) ((void)(addr))")
  pcmd("#endif")
  pcmd("")
  pcmd("#ifndef COMMON_SYSCALL_RELEASE")
  pcmd("# define COMMON_SYSCALL_RELEASE(addr) ((void)(addr))")
  pcmd("#endif")
  pcmd("")
  pcmd("#ifndef COMMON_SYSCALL_FD_CLOSE")
  pcmd("# define COMMON_SYSCALL_FD_CLOSE(fd) ((void)(fd))")
  pcmd("#endif")
  pcmd("")
  pcmd("#ifndef COMMON_SYSCALL_FD_ACQUIRE")
  pcmd("# define COMMON_SYSCALL_FD_ACQUIRE(fd) ((void)(fd))")
  pcmd("#endif")
  pcmd("")
  pcmd("#ifndef COMMON_SYSCALL_FD_RELEASE")
  pcmd("# define COMMON_SYSCALL_FD_RELEASE(fd) ((void)(fd))")
  pcmd("#endif")
  pcmd("")
  pcmd("#ifndef COMMON_SYSCALL_PRE_FORK")
  pcmd("# define COMMON_SYSCALL_PRE_FORK() {}")
  pcmd("#endif")
  pcmd("")
  pcmd("#ifndef COMMON_SYSCALL_POST_FORK")
  pcmd("# define COMMON_SYSCALL_POST_FORK(res) {}")
  pcmd("#endif")
  pcmd("")
  pcmd("// FIXME: do some kind of PRE_READ for all syscall arguments (int(s) and such).")
  pcmd("")
  pcmd("extern \"C\" {")
  pcmd("#define SYS_MAXSYSARGS " SYS_MAXSYSARGS)

  for (i = 0; i < parsedsyscalls; i++) {

    if (i in ifelifelseendif) {
      pcmd(ifelifelseendif[i])
    }

    sn = syscalls[i]

    if (sn ~ /^\$/) {
      pcmd("/* syscall " substr(sn,2) " has been skipped */")
      continue
    }

    preargs = syscallfullargs[i]

    if (preargs != "void") {
      preargs = "long " preargs
      gsub(/\$/, ", long ", preargs)
      gsub(/long \*/, "void *", preargs)
    }

    if (preargs == "void") {
      postargs = "long res"
    } else {
      postargs = "long res, " preargs
    }

    pcmd("PRE_SYSCALL(" sn ")(" preargs ")")
    pcmd("{")
    pre_syscall(sn)
    pcmd("}")

    pcmd("POST_SYSCALL(" sn ")(" postargs ") {}")
    pcmd("{")
    pre_syscall(sn)
    pcmd("}")
  }

  pcmd("#undef SYS_MAXSYSARGS")
  pcmd("}  // extern \"C\"")
  pcmd("")
  pcmd("#undef PRE_SYSCALL")
  pcmd("#undef PRE_READ")
  pcmd("#undef PRE_WRITE")
  pcmd("#undef POST_SYSCALL")
  pcmd("#undef POST_READ")
  pcmd("#undef POST_WRITE")
  pcmd("")
  pcmd("#endif  // SANITIZER_NETBSD")

  close(cmd)

  # Hack for preprocessed code
  system("sed -i 's,^ \\([^ ]\\),  \\1,' " outputinc)
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

function pre_syscall(syscall)
{
  # Hardcode sanitizing rules here
  # These syscalls don't change often so they are hand coded
  if (syscall == "syscall") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "exit") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fork") {
    pcmd("COMMON_SYSCALL_PRE_FORK();")
  } else if (syscall == "read") {
    pcmd("if (buf) {")
    pcmd("  PRE_WRITE(buf, nbyte);")
    pcmd("}")
  } else if (syscall == "write") {
    pcmd("if (buf) {")
    pcmd("  PRE_READ(buf, nbyte);")
    pcmd("}")
  } else if (syscall == "open") {
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);")
    pcmd("}")
  } else if (syscall == "close") {
    pcmd("COMMON_SYSCALL_FD_CLOSE((int)fd);")
  } else if (syscall == "compat_50_wait4") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_ocreat") {
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);")
    pcmd("}")
  } else if (syscall == "link") {
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);")
    pcmd("}")
    pcmd("if (link) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen((const char *)link) + 1);")
    pcmd("}")
  } else if (syscall == "unlink") {
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);")
    pcmd("}")
  } else if (syscall == "chdir") {
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);")
    pcmd("}")
  } else if (syscall == "fchdir") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_mknod") {\
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);")
    pcmd("}")
  } else if (syscall == "chmod") {
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);")
    pcmd("}")
  } else if (syscall == "chown") {
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen((const char *)path) + 1);")
    pcmd("}")
  } else if (syscall == "break") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_20_getfsstat") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_olseek") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getpid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_40_mount") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "unmount") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setuid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getuid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "geteuid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "ptrace") {
    pcmd("if (req == pt_io) {")
    pcmd("  if (data == pt_io) {")
    pcmd("    struct __sanitizer_ptrace_io_desc *piod = addr;")
    pcmd("    if (piod->piod_op == ptrace_piod_write_d || piod->piod_op == ptrace_piod_write_i) {")
    pcmd("      PRE_READ(piod->piod_addr, piod->piod_len);")
    pcmd("    }")
    pcmd("  }")
    pcmd("}")
  } else if (syscall == "recvmsg") {
  } else if (syscall == "sendmsg") {
  } else if (syscall == "recvfrom") {
  } else if (syscall == "accept") {
  } else if (syscall == "getpeername") {
  } else if (syscall == "getsockname") {
  } else if (syscall == "access") {
  } else if (syscall == "chflags") {
  } else if (syscall == "fchflags") {
  } else if (syscall == "sync") {
  } else if (syscall == "kill") {
  } else if (syscall == "compat_43_stat43") {
  } else if (syscall == "getppid") {
  } else if (syscall == "compat_43_lstat43") {
  } else if (syscall == "dup") {
  } else if (syscall == "pipe") {
  } else if (syscall == "getegid") {
  } else if (syscall == "profil") {
  } else if (syscall == "ktrace") {
  } else if (syscall == "compat_13_sigaction13") {
  } else if (syscall == "getgid") {
  } else if (syscall == "compat_13_sigprocmask13") {
  } else if (syscall == "__getlogin") {
  } else if (syscall == "__setlogin") {
  } else if (syscall == "acct") {
  } else if (syscall == "compat_13_sigpending13") {
  } else if (syscall == "compat_13_sigaltstack13") {
  } else if (syscall == "ioctl") {
  } else if (syscall == "compat_12_oreboot") {
  } else if (syscall == "revoke") {
  } else if (syscall == "symlink") {
  } else if (syscall == "readlink") {
  } else if (syscall == "execve") {
  } else if (syscall == "umask") {
  } else if (syscall == "chroot") {
  } else if (syscall == "compat_43_fstat43") {
  } else if (syscall == "compat_43_ogetkerninfo") {
  } else if (syscall == "compat_43_ogetpagesize") {
  } else if (syscall == "compat_12_msync") {
  } else if (syscall == "vfork") {
  } else if (syscall == "sbrk") {
  } else if (syscall == "sstk") {
  } else if (syscall == "compat_43_ommap") {
  } else if (syscall == "vadvise") {
  } else if (syscall == "munmap") {
  } else if (syscall == "mprotect") {
  } else if (syscall == "madvise") {
  } else if (syscall == "mincore") {
  } else if (syscall == "getgroups") {
  } else if (syscall == "setgroups") {
  } else if (syscall == "getpgrp") {
  } else if (syscall == "setpgid") {
  } else if (syscall == "compat_50_setitimer") {
  } else if (syscall == "compat_43_owait") {
  } else if (syscall == "compat_12_oswapon") {
  } else if (syscall == "compat_50_getitimer") {
  } else if (syscall == "compat_43_ogethostname") {
  } else if (syscall == "compat_43_osethostname") {
  } else if (syscall == "compat_43_ogetdtablesize") {
  } else if (syscall == "dup2") {
  } else if (syscall == "fcntl") {
  } else if (syscall == "compat_50_select") {
  } else if (syscall == "fsync") {
  } else if (syscall == "setpriority") {
  } else if (syscall == "compat_30_socket") {
  } else if (syscall == "connect") {
  } else if (syscall == "compat_43_oaccept") {
  } else if (syscall == "getpriority") {
  } else if (syscall == "compat_43_osend") {
  } else if (syscall == "compat_43_orecv") {
  } else if (syscall == "compat_13_sigreturn13") {
  } else if (syscall == "bind") {
  } else if (syscall == "setsockopt") {
  } else if (syscall == "listen") {
  } else if (syscall == "compat_43_osigvec") {
  } else if (syscall == "compat_43_osigblock") {
  } else if (syscall == "compat_43_osigsetmask") {
  } else if (syscall == "compat_13_sigsuspend13") {
  } else if (syscall == "compat_43_osigstack") {
  } else if (syscall == "compat_43_orecvmsg") {
  } else if (syscall == "compat_43_osendmsg") {
  } else if (syscall == "compat_50_gettimeofday") {
  } else if (syscall == "compat_50_getrusage") {
  } else if (syscall == "getsockopt") {
  } else if (syscall == "readv") {
  } else if (syscall == "writev") {
  } else if (syscall == "compat_50_settimeofday") {
  } else if (syscall == "fchown") {
  } else if (syscall == "fchmod") {
  } else if (syscall == "compat_43_orecvfrom") {
  } else if (syscall == "setreuid") {
  } else if (syscall == "setregid") {
  } else if (syscall == "rename") {
  } else if (syscall == "compat_43_otruncate") {
  } else if (syscall == "compat_43_oftruncate") {
  } else if (syscall == "flock") {
  } else if (syscall == "mkfifo") {
  } else if (syscall == "sendto") {
  } else if (syscall == "shutdown") {
  } else if (syscall == "socketpair") {
  } else if (syscall == "mkdir") {
  } else if (syscall == "rmdir") {
  } else if (syscall == "compat_50_utimes") {
  } else if (syscall == "compat_50_adjtime") {
  } else if (syscall == "compat_43_ogetpeername") {
  } else if (syscall == "compat_43_ogethostid") {
  } else if (syscall == "compat_43_osethostid") {
  } else if (syscall == "compat_43_ogetrlimit") {
  } else if (syscall == "compat_43_osetrlimit") {
  } else if (syscall == "compat_43_okillpg") {
  } else if (syscall == "setsid") {
  } else if (syscall == "compat_50_quotactl") {
  } else if (syscall == "compat_43_oquota") {
  } else if (syscall == "compat_43_ogetsockname") {
  } else if (syscall == "nfssvc") {
  } else if (syscall == "compat_43_ogetdirentries") {
  } else if (syscall == "compat_20_statfs") {
  } else if (syscall == "compat_20_fstatfs") {
  } else if (syscall == "compat_30_getfh") {
  } else if (syscall == "compat_09_ogetdomainname") {
  } else if (syscall == "compat_09_osetdomainname") {
  } else if (syscall == "compat_09_ouname") {
  } else if (syscall == "sysarch") {
  } else if (syscall == "compat_10_osemsys") {
  } else if (syscall == "compat_10_omsgsys") {
  } else if (syscall == "compat_10_oshmsys") {
  } else if (syscall == "pread") {
  } else if (syscall == "pwrite") {
  } else if (syscall == "compat_30_ntp_gettime") {
  } else if (syscall == "ntp_adjtime") {
  } else if (syscall == "setgid") {
  } else if (syscall == "setegid") {
  } else if (syscall == "seteuid") {
  } else if (syscall == "lfs_bmapv") {
  } else if (syscall == "lfs_markv") {
  } else if (syscall == "lfs_segclean") {
  } else if (syscall == "compat_50_lfs_segwait") {
  } else if (syscall == "compat_12_stat12") {
  } else if (syscall == "compat_12_fstat12") {
  } else if (syscall == "compat_12_lstat12") {
  } else if (syscall == "pathconf") {
  } else if (syscall == "fpathconf") {
  } else if (syscall == "getrlimit") {
  } else if (syscall == "setrlimit") {
  } else if (syscall == "compat_12_getdirentries") {
  } else if (syscall == "mmap") {
  } else if (syscall == "__syscall") {
  } else if (syscall == "lseek") {
  } else if (syscall == "truncate") {
  } else if (syscall == "ftruncate") {
  } else if (syscall == "__sysctl") {
  } else if (syscall == "mlock") {
  } else if (syscall == "munlock") {
  } else if (syscall == "undelete") {
  } else if (syscall == "compat_50_futimes") {
  } else if (syscall == "getpgid") {
  } else if (syscall == "reboot") {
  } else if (syscall == "poll") {
  } else if (syscall == "afssys") {
  } else if (syscall == "compat_14___semctl") {
  } else if (syscall == "semget") {
  } else if (syscall == "semop") {
  } else if (syscall == "semconfig") {
  } else if (syscall == "compat_14_msgctl") {
  } else if (syscall == "msgget") {
  } else if (syscall == "msgsnd") {
  } else if (syscall == "msgrcv") {
  } else if (syscall == "shmat") {
  } else if (syscall == "compat_14_shmctl") {
  } else if (syscall == "shmdt") {
  } else if (syscall == "shmget") {
  } else if (syscall == "compat_50_clock_gettime") {
  } else if (syscall == "compat_50_clock_settime") {
  } else if (syscall == "compat_50_clock_getres") {
  } else if (syscall == "timer_create") {
  } else if (syscall == "timer_delete") {
  } else if (syscall == "compat_50_timer_settime") {
  } else if (syscall == "compat_50_timer_gettime") {
  } else if (syscall == "timer_getoverrun") {
  } else if (syscall == "compat_50_nanosleep") {
  } else if (syscall == "fdatasync") {
  } else if (syscall == "mlockall") {
  } else if (syscall == "munlockall") {
  } else if (syscall == "compat_50___sigtimedwait") {
  } else if (syscall == "sigqueueinfo") {
  } else if (syscall == "modctl") {
  } else if (syscall == "_ksem_init") {
  } else if (syscall == "_ksem_open") {
  } else if (syscall == "_ksem_unlink") {
  } else if (syscall == "_ksem_close") {
  } else if (syscall == "_ksem_post") {
  } else if (syscall == "_ksem_wait") {
  } else if (syscall == "_ksem_trywait") {
  } else if (syscall == "_ksem_getvalue") {
  } else if (syscall == "_ksem_destroy") {
  } else if (syscall == "_ksem_timedwait") {
  } else if (syscall == "mq_open") {
  } else if (syscall == "mq_close") {
  } else if (syscall == "mq_unlink") {
  } else if (syscall == "mq_getattr") {
  } else if (syscall == "mq_setattr") {
  } else if (syscall == "mq_notify") {
  } else if (syscall == "mq_send") {
  } else if (syscall == "mq_receive") {
  } else if (syscall == "compat_50_mq_timedsend") {
  } else if (syscall == "compat_50_mq_timedreceive") {
  } else if (syscall == "__posix_rename") {
  } else if (syscall == "swapctl") {
  } else if (syscall == "compat_30_getdents") {
  } else if (syscall == "minherit") {
  } else if (syscall == "lchmod") {
  } else if (syscall == "lchown") {
  } else if (syscall == "compat_50_lutimes") {
  } else if (syscall == "__msync13") {
  } else if (syscall == "compat_30___stat13") {
  } else if (syscall == "compat_30___fstat13") {
  } else if (syscall == "compat_30___lstat13") {
  } else if (syscall == "__sigaltstack14") {
  } else if (syscall == "__vfork14") {
  } else if (syscall == "__posix_chown") {
  } else if (syscall == "__posix_fchown") {
  } else if (syscall == "__posix_lchown") {
  } else if (syscall == "getsid") {
  } else if (syscall == "__clone") {
  } else if (syscall == "fktrace") {
  } else if (syscall == "preadv") {
  } else if (syscall == "pwritev") {
  } else if (syscall == "compat_16___sigaction14") {
  } else if (syscall == "__sigpending14") {
  } else if (syscall == "__sigprocmask14") {
  } else if (syscall == "__sigsuspend14") {
  } else if (syscall == "compat_16___sigreturn14") {
  } else if (syscall == "__getcwd") {
  } else if (syscall == "fchroot") {
  } else if (syscall == "compat_30_fhopen") {
  } else if (syscall == "compat_30_fhstat") {
  } else if (syscall == "compat_20_fhstatfs") {
  } else if (syscall == "compat_50_____semctl13") {
  } else if (syscall == "compat_50___msgctl13") {
  } else if (syscall == "compat_50___shmctl13") {
  } else if (syscall == "lchflags") {
  } else if (syscall == "issetugid") {
  } else if (syscall == "utrace") {
  } else if (syscall == "getcontext") {
  } else if (syscall == "setcontext") {
  } else if (syscall == "_lwp_create") {
  } else if (syscall == "_lwp_exit") {
  } else if (syscall == "_lwp_self") {
  } else if (syscall == "_lwp_wait") {
  } else if (syscall == "_lwp_suspend") {
  } else if (syscall == "_lwp_continue") {
  } else if (syscall == "_lwp_wakeup") {
  } else if (syscall == "_lwp_getprivate") {
  } else if (syscall == "_lwp_setprivate") {
  } else if (syscall == "_lwp_kill") {
  } else if (syscall == "_lwp_detach") {
  } else if (syscall == "compat_50__lwp_park") {
  } else if (syscall == "_lwp_unpark") {
  } else if (syscall == "_lwp_unpark_all") {
  } else if (syscall == "_lwp_setname") {
  } else if (syscall == "_lwp_getname") {
  } else if (syscall == "_lwp_ctl") {
  } else if (syscall == "compat_60_sa_register") {
  } else if (syscall == "compat_60_sa_stacks") {
  } else if (syscall == "compat_60_sa_enable") {
  } else if (syscall == "compat_60_sa_setconcurrency") {
  } else if (syscall == "compat_60_sa_yield") {
  } else if (syscall == "compat_60_sa_preempt") {
  } else if (syscall == "__sigaction_sigtramp") {
  } else if (syscall == "pmc_get_info") {
  } else if (syscall == "pmc_control") {
  } else if (syscall == "rasctl") {
  } else if (syscall == "kqueue") {
  } else if (syscall == "compat_50_kevent") {
  } else if (syscall == "_sched_setparam") {
  } else if (syscall == "_sched_getparam") {
  } else if (syscall == "_sched_setaffinity") {
  } else if (syscall == "_sched_getaffinity") {
  } else if (syscall == "sched_yield") {
  } else if (syscall == "_sched_protect") {
  } else if (syscall == "fsync_range") {
  } else if (syscall == "uuidgen") {
  } else if (syscall == "getvfsstat") {
  } else if (syscall == "statvfs1") {
  } else if (syscall == "fstatvfs1") {
  } else if (syscall == "compat_30_fhstatvfs1") {
  } else if (syscall == "extattrctl") {
  } else if (syscall == "extattr_set_file") {
  } else if (syscall == "extattr_get_file") {
  } else if (syscall == "extattr_delete_file") {
  } else if (syscall == "extattr_set_fd") {
  } else if (syscall == "extattr_get_fd") {
  } else if (syscall == "extattr_delete_fd") {
  } else if (syscall == "extattr_set_link") {
  } else if (syscall == "extattr_get_link") {
  } else if (syscall == "extattr_delete_link") {
  } else if (syscall == "extattr_list_fd") {
  } else if (syscall == "extattr_list_file") {
  } else if (syscall == "extattr_list_link") {
  } else if (syscall == "compat_50_pselect") {
  } else if (syscall == "compat_50_pollts") {
  } else if (syscall == "setxattr") {
  } else if (syscall == "lsetxattr") {
  } else if (syscall == "fsetxattr") {
  } else if (syscall == "getxattr") {
  } else if (syscall == "lgetxattr") {
  } else if (syscall == "fgetxattr") {
  } else if (syscall == "listxattr") {
  } else if (syscall == "llistxattr") {
  } else if (syscall == "flistxattr") {
  } else if (syscall == "removexattr") {
  } else if (syscall == "lremovexattr") {
  } else if (syscall == "fremovexattr") {
  } else if (syscall == "compat_50___stat30") {
  } else if (syscall == "compat_50___fstat30") {
  } else if (syscall == "compat_50___lstat30") {
  } else if (syscall == "__getdents30") {
  } else if (syscall == "posix_fadvise") {
  } else if (syscall == "compat_30___fhstat30") {
  } else if (syscall == "compat_50___ntp_gettime30") {
  } else if (syscall == "__socket30") {
  } else if (syscall == "__getfh30") {
  } else if (syscall == "__fhopen40") {
  } else if (syscall == "__fhstatvfs140") {
  } else if (syscall == "compat_50___fhstat40") {
  } else if (syscall == "aio_cancel") {
  } else if (syscall == "aio_error") {
  } else if (syscall == "aio_fsync") {
  } else if (syscall == "aio_read") {
  } else if (syscall == "aio_return") {
  } else if (syscall == "compat_50_aio_suspend") {
  } else if (syscall == "aio_write") {
  } else if (syscall == "lio_listio") {
  } else if (syscall == "__mount50") {
  } else if (syscall == "mremap") {
  } else if (syscall == "pset_create") {
  } else if (syscall == "pset_destroy") {
  } else if (syscall == "pset_assign") {
  } else if (syscall == "_pset_bind") {
  } else if (syscall == "__posix_fadvise50") {
  } else if (syscall == "__select50") {
  } else if (syscall == "__gettimeofday50") {
  } else if (syscall == "__settimeofday50") {
  } else if (syscall == "__utimes50") {
  } else if (syscall == "__adjtime50") {
  } else if (syscall == "__lfs_segwait50") {
  } else if (syscall == "__futimes50") {
  } else if (syscall == "__lutimes50") {
  } else if (syscall == "__setitimer50") {
  } else if (syscall == "__getitimer50") {
  } else if (syscall == "__clock_gettime50") {
  } else if (syscall == "__clock_settime50") {
  } else if (syscall == "__clock_getres50") {
  } else if (syscall == "__nanosleep50") {
  } else if (syscall == "____sigtimedwait50") {
  } else if (syscall == "__mq_timedsend50") {
  } else if (syscall == "__mq_timedreceive50") {
  } else if (syscall == "compat_60__lwp_park") {
  } else if (syscall == "__kevent50") {
  } else if (syscall == "__pselect50") {
  } else if (syscall == "__pollts50") {
  } else if (syscall == "__aio_suspend50") {
  } else if (syscall == "__stat50") {
  } else if (syscall == "__fstat50") {
  } else if (syscall == "__lstat50") {
  } else if (syscall == "____semctl50") {
  } else if (syscall == "__shmctl50") {
  } else if (syscall == "__msgctl50") {
  } else if (syscall == "__getrusage50") {
  } else if (syscall == "__timer_settime50") {
  } else if (syscall == "__timer_gettime50") {
  } else if (syscall == "__ntp_gettime50") {
  } else if (syscall == "__wait450") {
  } else if (syscall == "__mknod50") {
  } else if (syscall == "__fhstat50") {
  } else if (syscall == "pipe2") {
  } else if (syscall == "dup3") {
  } else if (syscall == "kqueue1") {
  } else if (syscall == "paccept") {
  } else if (syscall == "linkat") {
  } else if (syscall == "renameat") {
  } else if (syscall == "mkfifoat") {
  } else if (syscall == "mknodat") {
  } else if (syscall == "mkdirat") {
  } else if (syscall == "faccessat") {
  } else if (syscall == "fchmodat") {
  } else if (syscall == "fchownat") {
  } else if (syscall == "fexecve") {
  } else if (syscall == "fstatat") {
  } else if (syscall == "utimensat") {
  } else if (syscall == "openat") {
  } else if (syscall == "readlinkat") {
  } else if (syscall == "symlinkat") {
  } else if (syscall == "unlinkat") {
  } else if (syscall == "futimens") {
  } else if (syscall == "__quotactl") {
  } else if (syscall == "posix_spawn") {
  } else if (syscall == "recvmmsg") {
  } else if (syscall == "sendmmsg") {
  } else if (syscall == "clock_nanosleep") {
  } else if (syscall == "___lwp_park60") {
  } else if (syscall == "posix_fallocate") {
  } else if (syscall == "fdiscard") {
  } else if (syscall == "wait6") {
  } else if (syscall == "clock_getcpuclockid2") {
  } else {
    print "Unrecognized syscall: " syscall
    abnormal_exit = 1
    exit 1
  }
}

function post_syscall(syscall)
{
  # Hardcode sanitizing rules here
  # These syscalls don't change often so they are hand coded
  if (syscall == "syscall") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "exit") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fork") {
    pcmd("COMMON_SYSCALL_POST_FORK(res);")
  } else if (syscall == "read") {
  } else if (syscall == "write") {
  } else if (syscall == "open") {
  } else if (syscall == "close") {
  } else if (syscall == "compat_50_wait4") {
  } else if (syscall == "compat_43_ocreat") {
  } else if (syscall == "link") {
  } else if (syscall == "unlink") {
  } else if (syscall == "chdir") {
  } else if (syscall == "fchdir") {
  } else if (syscall == "compat_50_mknod") {
  } else if (syscall == "chmod") {
  } else if (syscall == "chown") {
  } else if (syscall == "break") {
  } else if (syscall == "compat_20_getfsstat") {
  } else if (syscall == "compat_43_olseek") {
  } else if (syscall == "getpid") {
  } else if (syscall == "compat_40_mount") {
  } else if (syscall == "unmount") {
  } else if (syscall == "setuid") {
  } else if (syscall == "getuid") {
  } else if (syscall == "geteuid") {
  } else if (syscall == "ptrace") {
  } else if (syscall == "recvmsg") {
  } else if (syscall == "sendmsg") {
  } else if (syscall == "recvfrom") {
  } else if (syscall == "accept") {
  } else if (syscall == "getpeername") {
  } else if (syscall == "getsockname") {
  } else if (syscall == "access") {
  } else if (syscall == "chflags") {
  } else if (syscall == "fchflags") {
  } else if (syscall == "sync") {
  } else if (syscall == "kill") {
  } else if (syscall == "compat_43_stat43") {
  } else if (syscall == "getppid") {
  } else if (syscall == "compat_43_lstat43") {
  } else if (syscall == "dup") {
  } else if (syscall == "pipe") {
  } else if (syscall == "getegid") {
  } else if (syscall == "profil") {
  } else if (syscall == "ktrace") {
  } else if (syscall == "compat_13_sigaction13") {
  } else if (syscall == "getgid") {
  } else if (syscall == "compat_13_sigprocmask13") {
  } else if (syscall == "__getlogin") {
  } else if (syscall == "__setlogin") {
  } else if (syscall == "acct") {
  } else if (syscall == "compat_13_sigpending13") {
  } else if (syscall == "compat_13_sigaltstack13") {
  } else if (syscall == "ioctl") {
  } else if (syscall == "compat_12_oreboot") {
  } else if (syscall == "revoke") {
  } else if (syscall == "symlink") {
  } else if (syscall == "readlink") {
  } else if (syscall == "execve") {
  } else if (syscall == "umask") {
  } else if (syscall == "chroot") {
  } else if (syscall == "compat_43_fstat43") {
  } else if (syscall == "compat_43_ogetkerninfo") {
  } else if (syscall == "compat_43_ogetpagesize") {
  } else if (syscall == "compat_12_msync") {
  } else if (syscall == "vfork") {
  } else if (syscall == "sbrk") {
  } else if (syscall == "sstk") {
  } else if (syscall == "compat_43_ommap") {
  } else if (syscall == "vadvise") {
  } else if (syscall == "munmap") {
  } else if (syscall == "mprotect") {
  } else if (syscall == "madvise") {
  } else if (syscall == "mincore") {
  } else if (syscall == "getgroups") {
  } else if (syscall == "setgroups") {
  } else if (syscall == "getpgrp") {
  } else if (syscall == "setpgid") {
  } else if (syscall == "compat_50_setitimer") {
  } else if (syscall == "compat_43_owait") {
  } else if (syscall == "compat_12_oswapon") {
  } else if (syscall == "compat_50_getitimer") {
  } else if (syscall == "compat_43_ogethostname") {
  } else if (syscall == "compat_43_osethostname") {
  } else if (syscall == "compat_43_ogetdtablesize") {
  } else if (syscall == "dup2") {
  } else if (syscall == "fcntl") {
  } else if (syscall == "compat_50_select") {
  } else if (syscall == "fsync") {
  } else if (syscall == "setpriority") {
  } else if (syscall == "compat_30_socket") {
  } else if (syscall == "connect") {
  } else if (syscall == "compat_43_oaccept") {
  } else if (syscall == "getpriority") {
  } else if (syscall == "compat_43_osend") {
  } else if (syscall == "compat_43_orecv") {
  } else if (syscall == "compat_13_sigreturn13") {
  } else if (syscall == "bind") {
  } else if (syscall == "setsockopt") {
  } else if (syscall == "listen") {
  } else if (syscall == "compat_43_osigvec") {
  } else if (syscall == "compat_43_osigblock") {
  } else if (syscall == "compat_43_osigsetmask") {
  } else if (syscall == "compat_13_sigsuspend13") {
  } else if (syscall == "compat_43_osigstack") {
  } else if (syscall == "compat_43_orecvmsg") {
  } else if (syscall == "compat_43_osendmsg") {
  } else if (syscall == "compat_50_gettimeofday") {
  } else if (syscall == "compat_50_getrusage") {
  } else if (syscall == "getsockopt") {
  } else if (syscall == "readv") {
  } else if (syscall == "writev") {
  } else if (syscall == "compat_50_settimeofday") {
  } else if (syscall == "fchown") {
  } else if (syscall == "fchmod") {
  } else if (syscall == "compat_43_orecvfrom") {
  } else if (syscall == "setreuid") {
  } else if (syscall == "setregid") {
  } else if (syscall == "rename") {
  } else if (syscall == "compat_43_otruncate") {
  } else if (syscall == "compat_43_oftruncate") {
  } else if (syscall == "flock") {
  } else if (syscall == "mkfifo") {
  } else if (syscall == "sendto") {
  } else if (syscall == "shutdown") {
  } else if (syscall == "socketpair") {
  } else if (syscall == "mkdir") {
  } else if (syscall == "rmdir") {
  } else if (syscall == "compat_50_utimes") {
  } else if (syscall == "compat_50_adjtime") {
  } else if (syscall == "compat_43_ogetpeername") {
  } else if (syscall == "compat_43_ogethostid") {
  } else if (syscall == "compat_43_osethostid") {
  } else if (syscall == "compat_43_ogetrlimit") {
  } else if (syscall == "compat_43_osetrlimit") {
  } else if (syscall == "compat_43_okillpg") {
  } else if (syscall == "setsid") {
  } else if (syscall == "compat_50_quotactl") {
  } else if (syscall == "compat_43_oquota") {
  } else if (syscall == "compat_43_ogetsockname") {
  } else if (syscall == "nfssvc") {
  } else if (syscall == "compat_43_ogetdirentries") {
  } else if (syscall == "compat_20_statfs") {
  } else if (syscall == "compat_20_fstatfs") {
  } else if (syscall == "compat_30_getfh") {
  } else if (syscall == "compat_09_ogetdomainname") {
  } else if (syscall == "compat_09_osetdomainname") {
  } else if (syscall == "compat_09_ouname") {
  } else if (syscall == "sysarch") {
  } else if (syscall == "compat_10_osemsys") {
  } else if (syscall == "compat_10_omsgsys") {
  } else if (syscall == "compat_10_oshmsys") {
  } else if (syscall == "pread") {
  } else if (syscall == "pwrite") {
  } else if (syscall == "compat_30_ntp_gettime") {
  } else if (syscall == "ntp_adjtime") {
  } else if (syscall == "setgid") {
  } else if (syscall == "setegid") {
  } else if (syscall == "seteuid") {
  } else if (syscall == "lfs_bmapv") {
  } else if (syscall == "lfs_markv") {
  } else if (syscall == "lfs_segclean") {
  } else if (syscall == "compat_50_lfs_segwait") {
  } else if (syscall == "compat_12_stat12") {
  } else if (syscall == "compat_12_fstat12") {
  } else if (syscall == "compat_12_lstat12") {
  } else if (syscall == "pathconf") {
  } else if (syscall == "fpathconf") {
  } else if (syscall == "getrlimit") {
  } else if (syscall == "setrlimit") {
  } else if (syscall == "compat_12_getdirentries") {
  } else if (syscall == "mmap") {
  } else if (syscall == "__syscall") {
  } else if (syscall == "lseek") {
  } else if (syscall == "truncate") {
  } else if (syscall == "ftruncate") {
  } else if (syscall == "__sysctl") {
  } else if (syscall == "mlock") {
  } else if (syscall == "munlock") {
  } else if (syscall == "undelete") {
  } else if (syscall == "compat_50_futimes") {
  } else if (syscall == "getpgid") {
  } else if (syscall == "reboot") {
  } else if (syscall == "poll") {
  } else if (syscall == "afssys") {
  } else if (syscall == "compat_14___semctl") {
  } else if (syscall == "semget") {
  } else if (syscall == "semop") {
  } else if (syscall == "semconfig") {
  } else if (syscall == "compat_14_msgctl") {
  } else if (syscall == "msgget") {
  } else if (syscall == "msgsnd") {
  } else if (syscall == "msgrcv") {
  } else if (syscall == "shmat") {
  } else if (syscall == "compat_14_shmctl") {
  } else if (syscall == "shmdt") {
  } else if (syscall == "shmget") {
  } else if (syscall == "compat_50_clock_gettime") {
  } else if (syscall == "compat_50_clock_settime") {
  } else if (syscall == "compat_50_clock_getres") {
  } else if (syscall == "timer_create") {
  } else if (syscall == "timer_delete") {
  } else if (syscall == "compat_50_timer_settime") {
  } else if (syscall == "compat_50_timer_gettime") {
  } else if (syscall == "timer_getoverrun") {
  } else if (syscall == "compat_50_nanosleep") {
  } else if (syscall == "fdatasync") {
  } else if (syscall == "mlockall") {
  } else if (syscall == "munlockall") {
  } else if (syscall == "compat_50___sigtimedwait") {
  } else if (syscall == "sigqueueinfo") {
  } else if (syscall == "modctl") {
  } else if (syscall == "_ksem_init") {
  } else if (syscall == "_ksem_open") {
  } else if (syscall == "_ksem_unlink") {
  } else if (syscall == "_ksem_close") {
  } else if (syscall == "_ksem_post") {
  } else if (syscall == "_ksem_wait") {
  } else if (syscall == "_ksem_trywait") {
  } else if (syscall == "_ksem_getvalue") {
  } else if (syscall == "_ksem_destroy") {
  } else if (syscall == "_ksem_timedwait") {
  } else if (syscall == "mq_open") {
  } else if (syscall == "mq_close") {
  } else if (syscall == "mq_unlink") {
  } else if (syscall == "mq_getattr") {
  } else if (syscall == "mq_setattr") {
  } else if (syscall == "mq_notify") {
  } else if (syscall == "mq_send") {
  } else if (syscall == "mq_receive") {
  } else if (syscall == "compat_50_mq_timedsend") {
  } else if (syscall == "compat_50_mq_timedreceive") {
  } else if (syscall == "__posix_rename") {
  } else if (syscall == "swapctl") {
  } else if (syscall == "compat_30_getdents") {
  } else if (syscall == "minherit") {
  } else if (syscall == "lchmod") {
  } else if (syscall == "lchown") {
  } else if (syscall == "compat_50_lutimes") {
  } else if (syscall == "__msync13") {
  } else if (syscall == "compat_30___stat13") {
  } else if (syscall == "compat_30___fstat13") {
  } else if (syscall == "compat_30___lstat13") {
  } else if (syscall == "__sigaltstack14") {
  } else if (syscall == "__vfork14") {
  } else if (syscall == "__posix_chown") {
  } else if (syscall == "__posix_fchown") {
  } else if (syscall == "__posix_lchown") {
  } else if (syscall == "getsid") {
  } else if (syscall == "__clone") {
  } else if (syscall == "fktrace") {
  } else if (syscall == "preadv") {
  } else if (syscall == "pwritev") {
  } else if (syscall == "compat_16___sigaction14") {
  } else if (syscall == "__sigpending14") {
  } else if (syscall == "__sigprocmask14") {
  } else if (syscall == "__sigsuspend14") {
  } else if (syscall == "compat_16___sigreturn14") {
  } else if (syscall == "__getcwd") {
  } else if (syscall == "fchroot") {
  } else if (syscall == "compat_30_fhopen") {
  } else if (syscall == "compat_30_fhstat") {
  } else if (syscall == "compat_20_fhstatfs") {
  } else if (syscall == "compat_50_____semctl13") {
  } else if (syscall == "compat_50___msgctl13") {
  } else if (syscall == "compat_50___shmctl13") {
  } else if (syscall == "lchflags") {
  } else if (syscall == "issetugid") {
  } else if (syscall == "utrace") {
  } else if (syscall == "getcontext") {
  } else if (syscall == "setcontext") {
  } else if (syscall == "_lwp_create") {
  } else if (syscall == "_lwp_exit") {
  } else if (syscall == "_lwp_self") {
  } else if (syscall == "_lwp_wait") {
  } else if (syscall == "_lwp_suspend") {
  } else if (syscall == "_lwp_continue") {
  } else if (syscall == "_lwp_wakeup") {
  } else if (syscall == "_lwp_getprivate") {
  } else if (syscall == "_lwp_setprivate") {
  } else if (syscall == "_lwp_kill") {
  } else if (syscall == "_lwp_detach") {
  } else if (syscall == "compat_50__lwp_park") {
  } else if (syscall == "_lwp_unpark") {
  } else if (syscall == "_lwp_unpark_all") {
  } else if (syscall == "_lwp_setname") {
  } else if (syscall == "_lwp_getname") {
  } else if (syscall == "_lwp_ctl") {
  } else if (syscall == "compat_60_sa_register") {
  } else if (syscall == "compat_60_sa_stacks") {
  } else if (syscall == "compat_60_sa_enable") {
  } else if (syscall == "compat_60_sa_setconcurrency") {
  } else if (syscall == "compat_60_sa_yield") {
  } else if (syscall == "compat_60_sa_preempt") {
  } else if (syscall == "__sigaction_sigtramp") {
  } else if (syscall == "pmc_get_info") {
  } else if (syscall == "pmc_control") {
  } else if (syscall == "rasctl") {
  } else if (syscall == "kqueue") {
  } else if (syscall == "compat_50_kevent") {
  } else if (syscall == "_sched_setparam") {
  } else if (syscall == "_sched_getparam") {
  } else if (syscall == "_sched_setaffinity") {
  } else if (syscall == "_sched_getaffinity") {
  } else if (syscall == "sched_yield") {
  } else if (syscall == "_sched_protect") {
  } else if (syscall == "fsync_range") {
  } else if (syscall == "uuidgen") {
  } else if (syscall == "getvfsstat") {
  } else if (syscall == "statvfs1") {
  } else if (syscall == "fstatvfs1") {
  } else if (syscall == "compat_30_fhstatvfs1") {
  } else if (syscall == "extattrctl") {
  } else if (syscall == "extattr_set_file") {
  } else if (syscall == "extattr_get_file") {
  } else if (syscall == "extattr_delete_file") {
  } else if (syscall == "extattr_set_fd") {
  } else if (syscall == "extattr_get_fd") {
  } else if (syscall == "extattr_delete_fd") {
  } else if (syscall == "extattr_set_link") {
  } else if (syscall == "extattr_get_link") {
  } else if (syscall == "extattr_delete_link") {
  } else if (syscall == "extattr_list_fd") {
  } else if (syscall == "extattr_list_file") {
  } else if (syscall == "extattr_list_link") {
  } else if (syscall == "compat_50_pselect") {
  } else if (syscall == "compat_50_pollts") {
  } else if (syscall == "setxattr") {
  } else if (syscall == "lsetxattr") {
  } else if (syscall == "fsetxattr") {
  } else if (syscall == "getxattr") {
  } else if (syscall == "lgetxattr") {
  } else if (syscall == "fgetxattr") {
  } else if (syscall == "listxattr") {
  } else if (syscall == "llistxattr") {
  } else if (syscall == "flistxattr") {
  } else if (syscall == "removexattr") {
  } else if (syscall == "lremovexattr") {
  } else if (syscall == "fremovexattr") {
  } else if (syscall == "compat_50___stat30") {
  } else if (syscall == "compat_50___fstat30") {
  } else if (syscall == "compat_50___lstat30") {
  } else if (syscall == "__getdents30") {
  } else if (syscall == "posix_fadvise") {
  } else if (syscall == "compat_30___fhstat30") {
  } else if (syscall == "compat_50___ntp_gettime30") {
  } else if (syscall == "__socket30") {
  } else if (syscall == "__getfh30") {
  } else if (syscall == "__fhopen40") {
  } else if (syscall == "__fhstatvfs140") {
  } else if (syscall == "compat_50___fhstat40") {
  } else if (syscall == "aio_cancel") {
  } else if (syscall == "aio_error") {
  } else if (syscall == "aio_fsync") {
  } else if (syscall == "aio_read") {
  } else if (syscall == "aio_return") {
  } else if (syscall == "compat_50_aio_suspend") {
  } else if (syscall == "aio_write") {
  } else if (syscall == "lio_listio") {
  } else if (syscall == "__mount50") {
  } else if (syscall == "mremap") {
  } else if (syscall == "pset_create") {
  } else if (syscall == "pset_destroy") {
  } else if (syscall == "pset_assign") {
  } else if (syscall == "_pset_bind") {
  } else if (syscall == "__posix_fadvise50") {
  } else if (syscall == "__select50") {
  } else if (syscall == "__gettimeofday50") {
  } else if (syscall == "__settimeofday50") {
  } else if (syscall == "__utimes50") {
  } else if (syscall == "__adjtime50") {
  } else if (syscall == "__lfs_segwait50") {
  } else if (syscall == "__futimes50") {
  } else if (syscall == "__lutimes50") {
  } else if (syscall == "__setitimer50") {
  } else if (syscall == "__getitimer50") {
  } else if (syscall == "__clock_gettime50") {
  } else if (syscall == "__clock_settime50") {
  } else if (syscall == "__clock_getres50") {
  } else if (syscall == "__nanosleep50") {
  } else if (syscall == "____sigtimedwait50") {
  } else if (syscall == "__mq_timedsend50") {
  } else if (syscall == "__mq_timedreceive50") {
  } else if (syscall == "compat_60__lwp_park") {
  } else if (syscall == "__kevent50") {
  } else if (syscall == "__pselect50") {
  } else if (syscall == "__pollts50") {
  } else if (syscall == "__aio_suspend50") {
  } else if (syscall == "__stat50") {
  } else if (syscall == "__fstat50") {
  } else if (syscall == "__lstat50") {
  } else if (syscall == "____semctl50") {
  } else if (syscall == "__shmctl50") {
  } else if (syscall == "__msgctl50") {
  } else if (syscall == "__getrusage50") {
  } else if (syscall == "__timer_settime50") {
  } else if (syscall == "__timer_gettime50") {
  } else if (syscall == "__ntp_gettime50") {
  } else if (syscall == "__wait450") {
  } else if (syscall == "__mknod50") {
  } else if (syscall == "__fhstat50") {
  } else if (syscall == "pipe2") {
  } else if (syscall == "dup3") {
  } else if (syscall == "kqueue1") {
  } else if (syscall == "paccept") {
  } else if (syscall == "linkat") {
  } else if (syscall == "renameat") {
  } else if (syscall == "mkfifoat") {
  } else if (syscall == "mknodat") {
  } else if (syscall == "mkdirat") {
  } else if (syscall == "faccessat") {
  } else if (syscall == "fchmodat") {
  } else if (syscall == "fchownat") {
  } else if (syscall == "fexecve") {
  } else if (syscall == "fstatat") {
  } else if (syscall == "utimensat") {
  } else if (syscall == "openat") {
  } else if (syscall == "readlinkat") {
  } else if (syscall == "symlinkat") {
  } else if (syscall == "unlinkat") {
  } else if (syscall == "futimens") {
  } else if (syscall == "__quotactl") {
  } else if (syscall == "posix_spawn") {
  } else if (syscall == "recvmmsg") {
  } else if (syscall == "sendmmsg") {
  } else if (syscall == "clock_nanosleep") {
  } else if (syscall == "___lwp_park60") {
  } else if (syscall == "posix_fallocate") {
  } else if (syscall == "fdiscard") {
  } else if (syscall == "wait6") {
  } else if (syscall == "clock_getcpuclockid2") {
  } else {
    print "Unrecognized syscall: " syscall
    abnormal_exit = 1
    exit 1
  }
}
