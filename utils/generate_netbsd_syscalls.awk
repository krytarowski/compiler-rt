#!/usr/bin/awk -f

#===-- generate_netbsd_syscalls.awk ----------------------------------------===#
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
    # trim initial 'NetBSD: ' and trailing ' $'
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
      # Normalize 'type * argument' to 'type *argument'
      gsub("\\*[ \t]+", "*", args)

      n = split(args, a, ",")

      # Handle the first argument
      match(a[1], /[*_a-z0-9\[\]]+$/)
      syscallfullargs[parsedsyscalls] = substr(a[1], RSTART) "_"

      gsub(".+[ *]", "", a[1])
      syscallargs[parsedsyscalls] = a[1]

      # Handle the rest of arguments
      for (i = 2; i <= n; i++) {
        match(a[i], /[*_a-zA-Z0-9\[\]]+$/)
        fs = substr(a[i], RSTART)
        if (fs ~ /\[/) {
          sub(/\[/, "_[", fs)
        } else {
          fs = fs "_"
        }
        syscallfullargs[parsedsyscalls] = syscallfullargs[parsedsyscalls] "$" fs
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
    syscall_body(sn, "pre")
    pcmd("}")

    pcmd("POST_SYSCALL(" sn ")(" postargs ")")
    pcmd("{")
    syscall_body(sn, "post")
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

function syscall_body(syscall, mode)
{
  # Hardcode sanitizing rules here
  # These syscalls don't change often so they are hand coded
  if (syscall == "syscall") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "exit") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fork") {
    if (mode == "pre") {
      pcmd("COMMON_SYSCALL_PRE_FORK();")
    } else {
      pcmd("COMMON_SYSCALL_POST_FORK(res);")
    }
  } else if (syscall == "read") {
    if (mode == "pre") {
      pcmd("if (buf_) {")
      pcmd("  PRE_WRITE(buf_, nbyte_);")
      pcmd("}")
    } else {
      pcmd("if (res > 0) {")
      pcmd("  POST_WRITE(buf_, res);")
      pcmd("}")
    }
  } else if (syscall == "write") {
    if (mode == "pre") {
      pcmd("if (buf_) {")
      pcmd("  PRE_READ(buf_, nbyte_);")
      pcmd("}")
    } else {
      pcmd("if (res > 0) {")
      pcmd("  POST_READ(buf_, res);")
      pcmd("}")
    }
  } else if (syscall == "open") {
    if (mode == "pre") {
      pcmd("const char *path = (const char *)path_;")
      pcmd("if (path) {")
      pcmd("  " mode "_READ(path, __sanitizer::internal_strlen(path) + 1);")
      pcmd("}")
    } else {
      pcmd("/* Nothing to do */")
    }
  } else if (syscall == "close") {
    if (mode == "pre") {
      pcmd("COMMON_SYSCALL_FD_CLOSE((int)fd_);")
    } else {
      pcmd("/* Nothing to do */")
    }
  } else if (syscall == "compat_50_wait4") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_ocreat") {
    pcmd("/* TODO */")
  } else if (syscall == "link") {
    if (mode == "pre") {
      pcmd("const char *path = (const char *)path_;")
      pcmd("const char *link = (const char *)link_;")
      pcmd("if (path) {")
      pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
      pcmd("}")
      pcmd("if (link) {")
      pcmd("  PRE_READ(path, __sanitizer::internal_strlen(link) + 1);")
      pcmd("}")
    } else {
      pcmd("/* Nothing to do */")
    }
  } else if (syscall == "unlink") {
    if (mode == "pre") {
      pcmd("const char *path = (const char *)path_;")
      pcmd("if (path) {")
      pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
      pcmd("}")
    } else {
      pcmd("/* Nothing to do */")
    }
  } else if (syscall == "chdir") {
    if (mode == "pre") {
      pcmd("const char *path = (const char *)path_;")
      pcmd("if (path) {")
      pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
      pcmd("}")
    } else {
      pcmd("/* Nothing to do */")
    }
  } else if (syscall == "fchdir") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_mknod") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "chmod") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "chown") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
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
    pcmd("if (req_ == ptrace_pt_io) {")
    pcmd("  struct __sanitizer_ptrace_io_desc *piod = (struct __sanitizer_ptrace_io_desc *)addr_;")
    pcmd("  if (piod->piod_op == ptrace_piod_write_d || piod->piod_op == ptrace_piod_write_i) {")
    pcmd("    PRE_READ(piod->piod_addr, piod->piod_len);")
    pcmd("  }")
    pcmd("} else if (req_ == ptrace_pt_set_event_mask) {")
    pcmd("  PRE_READ(addr_, struct_ptrace_ptrace_event_struct_sz);")
    pcmd("} else if (req_ == ptrace_pt_set_siginfo) {")
    pcmd("  PRE_READ(addr_, struct_ptrace_ptrace_siginfo_struct_sz);")
    pcmd("} else if (req_ == ptrace_pt_set_sigmask) {")
    pcmd("  PRE_READ(addr_, sizeof(__sanitizer_sigset_t));")
    pcmd("} else if (req_ == ptrace_pt_setregs) {")
    pcmd("  PRE_READ(addr_, struct_ptrace_reg_struct_sz);")
    pcmd("} else if (req_ == ptrace_pt_setfpregs) {")
    pcmd("  PRE_READ(addr_, struct_ptrace_fpreg_struct_sz);")
    pcmd("} else if (req_ == ptrace_pt_setdbregs) {")
    pcmd("  PRE_READ(addr_, struct_ptrace_dbreg_struct_sz);")
    pcmd("}")
  } else if (syscall == "recvmsg") {
    pcmd("PRE_READ(msg_, sizeof(__sanitizer_msghdr));")
  } else if (syscall == "sendmsg") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "recvfrom") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "accept") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getpeername") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getsockname") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "access") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "chflags") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "fchflags") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "sync") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "kill") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_stat43") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "getppid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_lstat43") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "dup") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "pipe") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getegid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "profil") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "ktrace") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_13_sigaction13") {
    pcmd("struct __sanitizer_sigaction13 *nsa = (struct __sanitizer_sigaction13 *)nsa_;")
    pcmd("if (nsa) {")
    pcmd("  PRE_READ(&nsa->osa_handler, sizeof(nsa->osa_handler));")
    pcmd("  PRE_READ(&nsa->osa_flags, sizeof(nsa->osa_flags));")
    pcmd("  PRE_READ(&nsa->osa_mask, sizeof(nsa->osa_mask));")
    pcmd("}")
  } else if (syscall == "getgid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_13_sigprocmask13") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__getlogin") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__setlogin") {
    pcmd("const char *namebuf = (const char *)namebuf_;")
    pcmd("if (namebuf) {")
    pcmd("  PRE_READ(namebuf, __sanitizer::internal_strlen(namebuf) + 1);")
    pcmd("}")
  } else if (syscall == "acct") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "compat_13_sigpending13") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_13_sigaltstack13") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "ioctl") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_12_oreboot") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "revoke") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "symlink") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("const char *link = (const char *)link_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
    pcmd("if (link) {")
    pcmd("  PRE_READ(link, __sanitizer::internal_strlen(link) + 1);")
    pcmd("}")
  } else if (syscall == "readlink") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "execve") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("char **argp = (char **)argp_;")
    pcmd("char **envp = (char **)envp_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
    pcmd("if (argp && argp[0]) {")
    pcmd("  char *a = argp[0];")
    pcmd("  while (a++) {")
    pcmd("    PRE_READ(a, __sanitizer::internal_strlen(a) + 1);")
    pcmd("  }")
    pcmd("}")
    pcmd("if (envp && envp[0]) {")
    pcmd("  char *e = envp[0];")
    pcmd("  while (e++) {")
    pcmd("    PRE_READ(e, __sanitizer::internal_strlen(e) + 1);")
    pcmd("  }")
    pcmd("}")
  } else if (syscall == "umask") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "chroot") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "compat_43_fstat43") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_ogetkerninfo") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_ogetpagesize") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_12_msync") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "vfork") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_ommap") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "munmap") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "mprotect") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "madvise") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "mincore") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getgroups") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setgroups") {
    pcmd("unsigned int *gidset = (unsigned int *)gidset_;")
    pcmd("if (gidset) {")
    pcmd("  PRE_READ(gidset, sizeof(*gidset) * gidsetsize_);")
    pcmd("}")
  } else if (syscall == "getpgrp") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setpgid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_setitimer") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_owait") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_12_oswapon") {
    pcmd("const char *name = (const char *)name_;")
    pcmd("if (name) {")
    pcmd("  PRE_READ(name, __sanitizer::internal_strlen(name) + 1);")
    pcmd("}")
  } else if (syscall == "compat_50_getitimer") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_ogethostname") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_osethostname") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_ogetdtablesize") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "dup2") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fcntl") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_select") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fsync") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setpriority") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_30_socket") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "connect") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_oaccept") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getpriority") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_osend") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_orecv") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_13_sigreturn13") {
    pcmd("/* Missing on amd64? */")
  } else if (syscall == "bind") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setsockopt") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "listen") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_osigvec") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_osigblock") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_osigsetmask") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_13_sigsuspend13") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_osigstack") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_orecvmsg") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_osendmsg") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_gettimeofday") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_getrusage") {
    pcmd("/* TODO */")
  } else if (syscall == "getsockopt") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "readv") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "writev") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_settimeofday") {
    pcmd("/* TODO */")
  } else if (syscall == "fchown") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fchmod") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_orecvfrom") {
    pcmd("/* TODO */")
  } else if (syscall == "setreuid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setregid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "rename") {
    pcmd("const char *from = (const char *)from_;")
    pcmd("const char *to = (const char *)to_;")
    pcmd("if (from) {")
    pcmd("  PRE_READ(from, __sanitizer::internal_strlen(from) + 1);")
    pcmd("}")
    pcmd("if (to) {")
    pcmd("  PRE_READ(to, __sanitizer::internal_strlen(to) + 1);")
    pcmd("}")
  } else if (syscall == "compat_43_otruncate") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_oftruncate") {
    pcmd("/* TODO */")
  } else if (syscall == "flock") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "mkfifo") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "sendto") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "shutdown") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "socketpair") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "mkdir") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "rmdir") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "compat_50_utimes") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_adjtime") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_ogetpeername") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_ogethostid") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_osethostid") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_ogetrlimit") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_osetrlimit") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_okillpg") {
    pcmd("/* TODO */")
  } else if (syscall == "setsid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_quotactl") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_oquota") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_43_ogetsockname") {
    pcmd("/* TODO */")
  } else if (syscall == "nfssvc") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_43_ogetdirentries") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_20_statfs") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_20_fstatfs") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_30_getfh") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_09_ogetdomainname") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_09_osetdomainname") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_09_ouname") {
    pcmd("/* TODO */")
  } else if (syscall == "sysarch") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_10_osemsys") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_10_omsgsys") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_10_oshmsys") {
    pcmd("/* TODO */")
  } else if (syscall == "pread") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "pwrite") {
    pcmd("if (buf_) {")
    pcmd("  PRE_READ(buf_, nbyte_);")
    pcmd("}")
  } else if (syscall == "compat_30_ntp_gettime") {
    pcmd("/* TODO */")
  } else if (syscall == "ntp_adjtime") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setgid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setegid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "seteuid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "lfs_bmapv") {
    pcmd("/* TODO */")
  } else if (syscall == "lfs_markv") {
    pcmd("/* TODO */")
  } else if (syscall == "lfs_segclean") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_lfs_segwait") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_12_stat12") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "compat_12_fstat12") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_12_lstat12") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "pathconf") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "fpathconf") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getrlimit") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setrlimit") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_12_getdirentries") {
    pcmd("/* TODO */")
  } else if (syscall == "mmap") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__syscall") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "lseek") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "truncate") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "ftruncate") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__sysctl") {
    pcmd("const int *name = (const int *)name_;")
    pcmd("if (name) {")
    pcmd("  PRE_READ(name, namelen_ * sizeof(*name));")
    pcmd("}")
    pcmd("if (newv_) {")
    pcmd("  PRE_READ(name, newlen_);")
    pcmd("}")
  } else if (syscall == "mlock") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "munlock") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "undelete") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "compat_50_futimes") {
    pcmd("/* TODO */")
  } else if (syscall == "getpgid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "reboot") {
    pcmd("const char *bootstr = (const char *)bootstr_;")
    pcmd("if (bootstr) {")
    pcmd("  PRE_READ(bootstr, __sanitizer::internal_strlen(bootstr) + 1);")
    pcmd("}")
  } else if (syscall == "poll") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "afssys") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_14___semctl") {
    pcmd("/* TODO */")
  } else if (syscall == "semget") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "semop") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "semconfig") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_14_msgctl") {
    pcmd("/* TODO */")
  } else if (syscall == "msgget") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "msgsnd") {
    pcmd("if (msgp_) {")
    pcmd("  PRE_READ(msgp_, msgsz_);")
    pcmd("}")
  } else if (syscall == "msgrcv") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "shmat") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_14_shmctl") {
    pcmd("/* TODO */")
  } else if (syscall == "shmdt") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "shmget") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_clock_gettime") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_clock_settime") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_clock_getres") {
    pcmd("/* TODO */")
  } else if (syscall == "timer_create") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "timer_delete") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_timer_settime") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_timer_gettime") {
    pcmd("/* TODO */")
  } else if (syscall == "timer_getoverrun") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_nanosleep") {
    pcmd("/* TODO */")
  } else if (syscall == "fdatasync") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "mlockall") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "munlockall") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50___sigtimedwait") {
    pcmd("/* TODO */")
  } else if (syscall == "sigqueueinfo") {
    pcmd("if (info_) {")
    pcmd("  PRE_READ(info_, siginfo_t_sz);")
    pcmd("}")
  } else if (syscall == "modctl") {
    pcmd("/* TODO */")
  } else if (syscall == "_ksem_init") {
#    pcmd("if (idp) {")
#    pcmd("  PRE_READ(idp, sizeof(intptr_t));")
#    pcmd("}")
  } else if (syscall == "_ksem_open") {
    pcmd("const char *name = (const char *)name_;")
    pcmd("if (name) {")
    pcmd("  PRE_READ(name, __sanitizer::internal_strlen(name) + 1);")
    pcmd("}")
  } else if (syscall == "_ksem_unlink") {
    pcmd("const char *name = (const char *)name_;")
    pcmd("if (name) {")
    pcmd("  PRE_READ(name, __sanitizer::internal_strlen(name) + 1);")
    pcmd("}")
  } else if (syscall == "_ksem_close") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_ksem_post") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_ksem_wait") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_ksem_trywait") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_ksem_getvalue") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_ksem_destroy") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_ksem_timedwait") {
    pcmd("if (abstime_) {")
    pcmd("  PRE_READ(abstime_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "mq_open") {
    pcmd("const char *name = (const char *)name_;")
    pcmd("if (name) {")
    pcmd("  PRE_READ(name, __sanitizer::internal_strlen(name) + 1);")
    pcmd("}")
  } else if (syscall == "mq_close") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "mq_unlink") {
    pcmd("const char *name = (const char *)name_;")
    pcmd("if (name) {")
    pcmd("  PRE_READ(name, __sanitizer::internal_strlen(name) + 1);")
    pcmd("}")
  } else if (syscall == "mq_getattr") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "mq_setattr") {
    pcmd("if (mqstat_) {")
    pcmd("  PRE_READ(mqstat_, struct_mq_attr_sz);")
    pcmd("}")
  } else if (syscall == "mq_notify") {
    pcmd("if (notification_) {")
    pcmd("  PRE_READ(notification_, struct_sigevent_sz);")
    pcmd("}")
  } else if (syscall == "mq_send") {
    pcmd("if (msg_ptr_) {")
    pcmd("  PRE_READ(msg_ptr_, msg_len_);")
    pcmd("}")
  } else if (syscall == "mq_receive") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_mq_timedsend") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_mq_timedreceive") {
    pcmd("/* TODO */")
  } else if (syscall == "__posix_rename") {
    pcmd("const char *from = (const char *)from_;")
    pcmd("const char *to = (const char *)to_;")
    pcmd("if (from_) {")
    pcmd("  PRE_READ(from, __sanitizer::internal_strlen(from) + 1);")
    pcmd("}")
    pcmd("if (to) {")
    pcmd("  PRE_READ(to, __sanitizer::internal_strlen(to) + 1);")
    pcmd("}")
  } else if (syscall == "swapctl") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_30_getdents") {
    pcmd("/* TODO */")
  } else if (syscall == "minherit") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "lchmod") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "lchown") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "compat_50_lutimes") {
    pcmd("/* TODO */")
  } else if (syscall == "__msync13") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_30___stat13") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_30___fstat13") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_30___lstat13") {
    pcmd("/* TODO */")
  } else if (syscall == "__sigaltstack14") {
    pcmd("if (nss_) {")
    pcmd("  PRE_READ(nss_, struct_sigaltstack_sz);")
    pcmd("}")
    pcmd("if (oss_) {")
    pcmd("  PRE_READ(oss_, struct_sigaltstack_sz);")
    pcmd("}")
  } else if (syscall == "__vfork14") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__posix_chown") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "__posix_fchown") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__posix_lchown") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "getsid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__clone") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fktrace") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "preadv") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "pwritev") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_16___sigaction14") {
    pcmd("/* TODO */")
  } else if (syscall == "__sigpending14") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__sigprocmask14") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__sigsuspend14") {
    pcmd("if (set_) {")
    pcmd("  PRE_READ(set_, sizeof(__sanitizer_sigset_t));")
    pcmd("}")
  } else if (syscall == "compat_16___sigreturn14") {
    pcmd("/* TODO */")
  } else if (syscall == "__getcwd") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fchroot") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_30_fhopen") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_30_fhstat") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_20_fhstatfs") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_____semctl13") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50___msgctl13") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50___shmctl13") {
    pcmd("/* TODO */")
  } else if (syscall == "lchflags") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "issetugid") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "utrace") {
    pcmd("const char *label = (const char *)label_;")
    pcmd("if (label) {")
    pcmd("  PRE_READ(label, __sanitizer::internal_strlen(label) + 1);")
    pcmd("}")
    pcmd("if (addr_) {")
    pcmd("  PRE_READ(addr_, len_);")
    pcmd("}")
  } else if (syscall == "getcontext") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "setcontext") {
    pcmd("if (ucp_) {")
    pcmd("  PRE_READ(ucp_, ucontext_t_sz);")
    pcmd("}")
  } else if (syscall == "_lwp_create") {
    pcmd("if (ucp_) {")
    pcmd("  PRE_READ(ucp_, ucontext_t_sz);")
    pcmd("}")
  } else if (syscall == "_lwp_exit") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_self") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_wait") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_suspend") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_continue") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_wakeup") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_getprivate") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_setprivate") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_kill") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_detach") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50__lwp_park") {
    pcmd("/* TODO */")
  } else if (syscall == "_lwp_unpark") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_unpark_all") {
    pcmd("if (targets_) {")
    pcmd("  PRE_READ(targets_, ntargets_ * sizeof(__sanitizer_lwpid_t));")
    pcmd("}")
  } else if (syscall == "_lwp_setname") {
    pcmd("const char *name = (const char *)name_;")
    pcmd("if (name) {")
    pcmd("  PRE_READ(name, __sanitizer::internal_strlen(name) + 1);")
    pcmd("}")
  } else if (syscall == "_lwp_getname") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_lwp_ctl") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_60_sa_register") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_60_sa_stacks") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_60_sa_enable") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_60_sa_setconcurrency") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_60_sa_yield") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_60_sa_preempt") {
    pcmd("/* TODO */")
  } else if (syscall == "__sigaction_sigtramp") {
    pcmd("if (nsa_) {")
    pcmd("  PRE_READ(nsa_, sizeof(__sanitizer_sigaction));")
    pcmd("}")
  } else if (syscall == "pmc_get_info") {
    pcmd("/* TODO */")
  } else if (syscall == "pmc_control") {
    pcmd("/* TODO */")
  } else if (syscall == "rasctl") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "kqueue") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_50_kevent") {
    pcmd("/* TODO */")
  } else if (syscall == "_sched_setparam") {
    pcmd("if (params_) {")
    pcmd("  PRE_READ(params_, struct_sched_param_sz);")
    pcmd("}")
  } else if (syscall == "_sched_getparam") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_sched_setaffinity") {
    pcmd("if (cpuset_) {")
    pcmd("  PRE_READ(cpuset_, size_);")
    pcmd("}")
  } else if (syscall == "_sched_getaffinity") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "sched_yield") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_sched_protect") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fsync_range") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "uuidgen") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getvfsstat") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "statvfs1") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "fstatvfs1") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_30_fhstatvfs1") {
    pcmd("/* TODO */")
  } else if (syscall == "extattrctl") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "extattr_set_file") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "extattr_get_file") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "extattr_delete_file") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "extattr_set_fd") {
    pcmd("/* TODO */")
  } else if (syscall == "extattr_get_fd") {
    pcmd("/* TODO */")
  } else if (syscall == "extattr_delete_fd") {
    pcmd("/* TODO */")
  } else if (syscall == "extattr_set_link") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "extattr_get_link") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "extattr_delete_link") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "extattr_list_fd") {
    pcmd("/* TODO */")
  } else if (syscall == "extattr_list_file") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "extattr_list_link") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "compat_50_pselect") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50_pollts") {
    pcmd("/* TODO */")
  } else if (syscall == "setxattr") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "lsetxattr") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "fsetxattr") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "getxattr") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "lgetxattr") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "fgetxattr") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "listxattr") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "llistxattr") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "flistxattr") {
    pcmd("/* TODO */")
  } else if (syscall == "removexattr") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "lremovexattr") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "fremovexattr") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50___stat30") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50___fstat30") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50___lstat30") {
    pcmd("/* TODO */")
  } else if (syscall == "__getdents30") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "posix_fadvise") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "compat_30___fhstat30") {
    pcmd("/* TODO */")
  } else if (syscall == "compat_50___ntp_gettime30") {
    pcmd("/* TODO */")
  } else if (syscall == "__socket30") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__getfh30") {
    pcmd("const char *fname = (const char *)fname_;")
    pcmd("if (fname) {")
    pcmd("  PRE_READ(fname, __sanitizer::internal_strlen(fname) + 1);")
    pcmd("}")
  } else if (syscall == "__fhopen40") {
    pcmd("if (fhp_) {")
    pcmd("  PRE_READ(fhp_, fh_size_);")
    pcmd("}")
  } else if (syscall == "__fhstatvfs140") {
    pcmd("if (fhp_) {")
    pcmd("  PRE_READ(fhp_, fh_size_);")
    pcmd("}")
  } else if (syscall == "compat_50___fhstat40") {
    pcmd("if (fhp_) {")
    pcmd("  PRE_READ(fhp_, fh_size_);")
    pcmd("}")
  } else if (syscall == "aio_cancel") {
    pcmd("if (aiocbp_) {")
    pcmd("  PRE_READ(aiocbp_, sizeof(struct __sanitizer_aiocb));")
    pcmd("}")
  } else if (syscall == "aio_error") {
    pcmd("if (aiocbp_) {")
    pcmd("  PRE_READ(aiocbp_, sizeof(struct __sanitizer_aiocb));")
    pcmd("}")
  } else if (syscall == "aio_fsync") {
    pcmd("if (aiocbp_) {")
    pcmd("  PRE_READ(aiocbp_, sizeof(struct __sanitizer_aiocb));")
    pcmd("}")
  } else if (syscall == "aio_read") {
    pcmd("if (aiocbp_) {")
    pcmd("  PRE_READ(aiocbp_, sizeof(struct __sanitizer_aiocb));")
    pcmd("}")
  } else if (syscall == "aio_return") {
    pcmd("if (aiocbp_) {")
    pcmd("  PRE_READ(aiocbp_, sizeof(struct __sanitizer_aiocb));")
    pcmd("}")
  } else if (syscall == "compat_50_aio_suspend") {
    pcmd("/* TODO */")
  } else if (syscall == "aio_write") {
    pcmd("if (aiocbp_) {")
    pcmd("  PRE_READ(aiocbp_, sizeof(struct __sanitizer_aiocb));")
    pcmd("}")
  } else if (syscall == "lio_listio") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__mount50") {
    pcmd("const char *type = (const char *)type_;")
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (type) {")
    pcmd("  PRE_READ(type, __sanitizer::internal_strlen(type) + 1);")
    pcmd("}")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
    pcmd("if (data_) {")
    pcmd("  PRE_READ(data_, data_len_);")
    pcmd("}")
  } else if (syscall == "mremap") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "pset_create") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "pset_destroy") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "pset_assign") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "_pset_bind") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__posix_fadvise50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__select50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__gettimeofday50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__settimeofday50") {
    pcmd("if (tv_) {")
    pcmd("  PRE_READ(tv_, timeval_sz);")
    pcmd("}")
    pcmd("if (tzp_) {")
    pcmd("  PRE_READ(tzp_, struct_timezone_sz);")
    pcmd("}")
  } else if (syscall == "__utimes50") {
    pcmd("struct __sanitizer_timespec **tptr = (struct __sanitizer_timespec **)tptr_;")
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
    pcmd("if (tptr) {")
    pcmd("  PRE_READ(tptr[0], struct_timespec_sz);")
    pcmd("  PRE_READ(tptr[1], struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "__adjtime50") {
    pcmd("if (delta_) {")
    pcmd("  PRE_READ(delta_, timeval_sz);")
    pcmd("}")
  } else if (syscall == "__lfs_segwait50") {
    pcmd("/* TODO */")
  } else if (syscall == "__futimes50") {
    pcmd("struct __sanitizer_timespec **tptr = (struct __sanitizer_timespec **)tptr_;")
    pcmd("if (tptr) {")
    pcmd("  PRE_READ(tptr[0], struct_timespec_sz);")
    pcmd("  PRE_READ(tptr[1], struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "__lutimes50") {
    pcmd("struct __sanitizer_timespec **tptr = (struct __sanitizer_timespec **)tptr_;")
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
    pcmd("if (tptr) {")
    pcmd("  PRE_READ(tptr[0], struct_timespec_sz);")
    pcmd("  PRE_READ(tptr[1], struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "__setitimer50") {
    pcmd("struct __sanitizer_itimerval *itv = (struct __sanitizer_itimerval *)itv_;")
    pcmd("if (itv) {")
    pcmd("  PRE_READ(&itv->it_interval.tv_sec, sizeof(__sanitizer_time_t));")
    pcmd("  PRE_READ(&itv->it_interval.tv_usec, sizeof(__sanitizer_suseconds_t));")
    pcmd("  PRE_READ(&itv->it_value.tv_sec, sizeof(__sanitizer_time_t));")
    pcmd("  PRE_READ(&itv->it_value.tv_usec, sizeof(__sanitizer_suseconds_t));")
    pcmd("}")
  } else if (syscall == "__getitimer50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__clock_gettime50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__clock_settime50") {
    pcmd("if (tp_) {")
    pcmd("  PRE_READ(tp_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "__clock_getres50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__nanosleep50") {
    pcmd("if (rqtp_) {")
    pcmd("  PRE_READ(rqtp_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "____sigtimedwait50") {
    pcmd("if (set_) {")
    pcmd("  PRE_READ(set_, sizeof(__sanitizer_sigset_t));")
    pcmd("}")
    pcmd("if (timeout_) {")
    pcmd("  PRE_READ(timeout_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "__mq_timedsend50") {
    pcmd("if (msg_ptr_) {")
    pcmd("  PRE_READ(msg_ptr_, msg_len_);")
    pcmd("}")
    pcmd("if (abs_timeout_) {")
    pcmd("  PRE_READ(abs_timeout_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "__mq_timedreceive50") {
    pcmd("if (msg_ptr_) {")
    pcmd("  PRE_READ(msg_ptr_, msg_len_);")
    pcmd("}")
    pcmd("if (abs_timeout_) {")
    pcmd("  PRE_READ(abs_timeout_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "compat_60__lwp_park") {
    pcmd("/* TODO */")
  } else if (syscall == "__kevent50") {
    pcmd("if (changelist_) {")
    pcmd("  PRE_READ(changelist_, nchanges_ * struct_kevent_sz);")
    pcmd("}")
    pcmd("if (timeout_) {")
    pcmd("  PRE_READ(timeout_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "__pselect50") {
    pcmd("if (ts_) {")
    pcmd("  PRE_READ(ts_, struct_timespec_sz);")
    pcmd("}")
    pcmd("if (mask_) {")
    pcmd("  PRE_READ(mask_, sizeof(struct __sanitizer_sigset_t));")
    pcmd("}")
  } else if (syscall == "__pollts50") {
    pcmd("if (ts_) {")
    pcmd("  PRE_READ(ts_, struct_timespec_sz);")
    pcmd("}")
    pcmd("if (mask_) {")
    pcmd("  PRE_READ(mask_, sizeof(struct __sanitizer_sigset_t));")
    pcmd("}")
  } else if (syscall == "__aio_suspend50") {
    pcmd("int i;")
    pcmd("const struct aiocb * const *list = (const struct aiocb * const *)list_;")
    pcmd("if (list) {")
    pcmd("  for (i = 0; i < nent_; i++) {")
    pcmd("    if (list[i]) {")
    pcmd("      PRE_READ(list[i], sizeof(struct __sanitizer_aiocb));")
    pcmd("    }")
    pcmd("  }")
    pcmd("}")
    pcmd("if (timeout_) {")
    pcmd("  PRE_READ(timeout_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "__stat50") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "__fstat50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__lstat50") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "____semctl50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__shmctl50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__msgctl50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__getrusage50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__timer_settime50") {
    pcmd("struct __sanitizer_itimerval *value = (struct __sanitizer_itimerval *)value_;")
    pcmd("if (value) {")
    pcmd("  PRE_READ(&value->it_interval.tv_sec, sizeof(__sanitizer_time_t));")
    pcmd("  PRE_READ(&value->it_interval.tv_usec, sizeof(__sanitizer_suseconds_t));")
    pcmd("  PRE_READ(&value->it_value.tv_sec, sizeof(__sanitizer_time_t));")
    pcmd("  PRE_READ(&value->it_value.tv_usec, sizeof(__sanitizer_suseconds_t));")
    pcmd("}")
  } else if (syscall == "__timer_gettime50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__ntp_gettime50") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__wait450") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "__mknod50") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "__fhstat50") {
    pcmd("if (fhp_) {")
    pcmd("  PRE_READ(fhp_, fh_size_);")
    pcmd("}")
  } else if (syscall == "pipe2") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "dup3") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "kqueue1") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "paccept") {
    pcmd("if (mask_) {")
    pcmd("  PRE_READ(mask_, sizeof(__sanitizer_sigset_t));")
    pcmd("}")
  } else if (syscall == "linkat") {
    pcmd("const char *name1 = (const char *)name1_;")
    pcmd("const char *name2 = (const char *)name2_;")
    pcmd("if (name1) {")
    pcmd("  PRE_READ(name1, __sanitizer::internal_strlen(name1) + 1);")
    pcmd("}")
    pcmd("if (name2) {")
    pcmd("  PRE_READ(name2, __sanitizer::internal_strlen(name2) + 1);")
    pcmd("}")
  } else if (syscall == "renameat") {
    pcmd("const char *from = (const char *)from_;")
    pcmd("const char *to = (const char *)to_;")
    pcmd("if (from) {")
    pcmd("  PRE_READ(from, __sanitizer::internal_strlen(from) + 1);")
    pcmd("}")
    pcmd("if (to) {")
    pcmd("  PRE_READ(to, __sanitizer::internal_strlen(to) + 1);")
    pcmd("}")
  } else if (syscall == "mkfifoat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "mknodat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "mkdirat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "faccessat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "fchmodat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "fchownat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "fexecve") {
    pcmd("char **argp = (char **)argp_;")
    pcmd("char **envp = (char **)envp_;")
    pcmd("if (argp && argp[0]) {")
    pcmd("  char *a = argp[0];")
    pcmd("  while (a++) {")
    pcmd("    PRE_READ(a, __sanitizer::internal_strlen(a) + 1);")
    pcmd("  }")
    pcmd("}")
    pcmd("if (envp && envp[0]) {")
    pcmd("  char *e = envp[0];")
    pcmd("  while (e++) {")
    pcmd("    PRE_READ(e, __sanitizer::internal_strlen(e) + 1);")
    pcmd("  }")
    pcmd("}")
  } else if (syscall == "fstatat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "utimensat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
    pcmd("if (tptr_) {")
    pcmd("  PRE_READ(tptr_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "openat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "readlinkat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "symlinkat") {
    pcmd("const char *path1 = (const char *)path1_;")
    pcmd("const char *path2 = (const char *)path2_;")
    pcmd("if (path1) {")
    pcmd("  PRE_READ(path1, __sanitizer::internal_strlen(path1) + 1);")
    pcmd("}")
    pcmd("if (path2) {")
    pcmd("  PRE_READ(path2, __sanitizer::internal_strlen(path2) + 1);")
    pcmd("}")
  } else if (syscall == "unlinkat") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "futimens") {
    pcmd("struct __sanitizer_timespec **tptr = (struct __sanitizer_timespec **)tptr_;")
    pcmd("if (tptr) {")
    pcmd("  PRE_READ(tptr[0], struct_timespec_sz);")
    pcmd("  PRE_READ(tptr[1], struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "__quotactl") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "posix_spawn") {
    pcmd("const char *path = (const char *)path_;")
    pcmd("if (path) {")
    pcmd("  PRE_READ(path, __sanitizer::internal_strlen(path) + 1);")
    pcmd("}")
  } else if (syscall == "recvmmsg") {
    pcmd("if (timeout_) {")
    pcmd("  PRE_READ(timeout_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "sendmmsg") {
    pcmd("struct __sanitizer_mmsghdr *mmsg = (struct __sanitizer_mmsghdr *)mmsg_;")
    pcmd("unsigned int vlen = (vlen_ > 1024 ? 1024 : vlen_);");
    pcmd("if (mmsg) {")
    pcmd("  PRE_READ(mmsg, sizeof(struct __sanitizer_mmsghdr) * vlen);")
    pcmd("}")
  } else if (syscall == "clock_nanosleep") {
    pcmd("if (rqtp_) {")
    pcmd("  PRE_READ(rqtp_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "___lwp_park60") {
    pcmd("if (ts_) {")
    pcmd("  PRE_READ(ts_, struct_timespec_sz);")
    pcmd("}")
  } else if (syscall == "posix_fallocate") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "fdiscard") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "wait6") {
    pcmd("/* Nothing to do */")
  } else if (syscall == "clock_getcpuclockid2") {
    pcmd("/* Nothing to do */")
  } else {
    print "Unrecognized syscall: " syscall
    abnormal_exit = 1
    exit 1
  }
}
