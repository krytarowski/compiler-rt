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
}

END {
  # Handle abnormal exit
  if (rv) {
    exit(rv)
  }
  print "hello world" > output
  fflush(output)
  close(output)
  system("cat " output " | " clangformat " > " output ".tmp")
  system("mv " output ".tmp " output)
}

function usage()
{
  print "Usage: " script_name " syscalls.master"
  rv=1
  exit 1
}
