#!/usr/bin/awk -f

#===-- generate_netbsd_ioctls.awk ------------------------------------------===#
#
#                     The LLVM Compiler Infrastructure
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
#
# This file is a generator of:
#  - include/sanitizer/sanitizer_netbsd_interceptors_ioctl.inc
#
# This script reads public headers from a NetBSD host.
#
#===------------------------------------------------------------------------===#

BEGIN {
  # harcode the script name
  script_name = "generate_netbsd_ioctls.awk"
  outputinc = "../lib/sanitizer_common/sanitizer_netbsd_interceptors_ioctl.inc"

  # assert that we are in the directory with scripts
  in_utils = system("test -f " script_name " && exit 1 || exit 0")
  if (in_utils == 0) {
    usage()
  }

  # assert 0 argument passed
  if (ARGC != 1) {
    usage()
  }

  # accept overloading CLANGFORMAT from environment
  clangformat = "clang-format"
  if ("CLANGFORMAT" in ENVIRON) {
    clangformat = ENVIRON["CLANGFORMAT"]
  }

  # accept overloading ROOTDIR from environment
  rootdir = "/usr/include/"
  if ("ROOTDIR" in ENVIRON) {
    rootdir = ENVIRON["ROOTDIR"]
  }

  # hardcode list of headers with ioctl(2) entries
  ARGV[1] = rootdir "soundcard.h"

  ioctl_table_max = 0
}

NR == 1 {
  print
}

END {
  # empty files?
  if (NR < 1 && !abnormal_exit) {
    usage()
  }

  # Handle abnormal exit
  if (abnormal_exit) {
    exit(abnormal_exit)
  }

  # Generate sanitizer_netbsd_ioctls.inc

  # open pipe
  cmd = clangformat " > " outputinc

  pcmd("//===-- sanitizer_common_interceptors_ioctl.inc -----------------*- C++ -*-===//")
  pcmd("//")
  pcmd("//                     The LLVM Compiler Infrastructure")
  pcmd("//")
  pcmd("// This file is distributed under the University of Illinois Open Source")
  pcmd("// License. See LICENSE.TXT for details.")
  pcmd("//")
  pcmd("//===----------------------------------------------------------------------===//")
  pcmd("//")
  pcmd("// Ioctl handling in common sanitizer interceptors.")
  pcmd("//===----------------------------------------------------------------------===//")
  pcmd("")
  pcmd("#include \"sanitizer_flags.h\"")
  pcmd("")
  pcmd("struct ioctl_desc {")
  pcmd("  unsigned req;")
  pcmd("  // FIXME: support read+write arguments. Currently READWRITE and WRITE do the")
  pcmd("  // same thing.")
  pcmd("  // XXX: The declarations below may use WRITE instead of READWRITE, unless")
  pcmd("  // explicitly noted.")
  pcmd("  enum {")
  pcmd("    NONE,")
  pcmd("    READ,")
  pcmd("    WRITE,")
  pcmd("    READWRITE,")
  pcmd("    CUSTOM")
  pcmd("  } type : 3;")
  pcmd("  unsigned size : 29;")
  pcmd("  const char* name;")
  pcmd("};")
  pcmd("")
  pcmd("const unsigned ioctl_table_max = " ioctl_table_max ";")
  pcmd("static ioctl_desc ioctl_table[ioctl_table_max];")
  pcmd("static unsigned ioctl_table_size = 0;")
  pcmd("")
  pcmd("// This can not be declared as a global, because references to struct_*_sz")
  pcmd("// require a global initializer. And this table must be available before global")
  pcmd("// initializers are run.")
  pcmd("static void ioctl_table_fill() {")
  pcmd("#define _(rq, tp, sz)                                    \")
  pcmd("  if (IOCTL_##rq != IOCTL_NOT_PRESENT) {                 \")
  pcmd("    CHECK(ioctl_table_size < ioctl_table_max);           \")
  pcmd("    ioctl_table[ioctl_table_size].req = IOCTL_##rq;      \")
  pcmd("    ioctl_table[ioctl_table_size].type = ioctl_desc::tp; \")
  pcmd("    ioctl_table[ioctl_table_size].size = sz;             \")
  pcmd("    ioctl_table[ioctl_table_size].name = #rq;            \")
  pcmd("    ++ioctl_table_size;                                  \")
  pcmd("  }")
  pcmd("")



  pcmd("#undef _")
  pcmd("}")
  pcmd("")
  pcmd("static bool ioctl_initialized = false;")
  pcmd("")
  pcmd("struct ioctl_desc_compare {")
  pcmd("  bool operator()(const ioctl_desc& left, const ioctl_desc& right) const {")
  pcmd("    return left.req < right.req;")
  pcmd("  }")
  pcmd("};")
  pcmd("")
  pcmd("static void ioctl_init() {")
  pcmd("  ioctl_table_fill();")
  pcmd("  InternalSort(&ioctl_table, ioctl_table_size, ioctl_desc_compare());")
  pcmd("")
  pcmd("  bool bad = false;")
  pcmd("  for (unsigned i = 0; i < ioctl_table_size - 1; ++i) {")
  pcmd("    if (ioctl_table[i].req >= ioctl_table[i + 1].req) {")
  pcmd("      Printf("Duplicate or unsorted ioctl request id %x >= %x (%s vs %s)\n",")
  pcmd("             ioctl_table[i].req, ioctl_table[i + 1].req, ioctl_table[i].name,")
  pcmd("             ioctl_table[i + 1].name);")
  pcmd("      bad = true;")
  pcmd("    }")
  pcmd("  }")
  pcmd("")
  pcmd("  if (bad) Die();")
  pcmd("")
  pcmd("  ioctl_initialized = true;")
  pcmd("}")
  pcmd("")
  pcmd("static const ioctl_desc *ioctl_table_lookup(unsigned req) {")
  pcmd("  int left = 0;")
  pcmd("  int right = ioctl_table_size;")
  pcmd("  while (left < right) {")
  pcmd("    int mid = (left + right) / 2;")
  pcmd("    if (ioctl_table[mid].req < req)")
  pcmd("      left = mid + 1;")
  pcmd("    else")
  pcmd("      right = mid;")
  pcmd("  }")
  pcmd("  if (left == right && ioctl_table[left].req == req)")
  pcmd("    return ioctl_table + left;")
  pcmd("  else")
  pcmd("    return nullptr;")
  pcmd("}")
  pcmd("")
  pcmd("static bool ioctl_decode(unsigned req, ioctl_desc *desc) {")
  pcmd("  CHECK(desc);")
  pcmd("  desc->req = req;")
  pcmd("  desc->name = \"<DECODED_IOCTL>\";")
  pcmd("  desc->size = IOC_SIZE(req);")
  pcmd("  // Sanity check.")
  pcmd("  if (desc->size > 0xFFFF) return false;")
  pcmd("  unsigned dir = IOC_DIR(req);")
  pcmd("  switch (dir) {")
  pcmd("    case IOC_NONE:")
  pcmd("      desc->type = ioctl_desc::NONE;")
  pcmd("      break;")
  pcmd("    case IOC_READ | IOC_WRITE:")
  pcmd("      desc->type = ioctl_desc::READWRITE;")
  pcmd("      break;")
  pcmd("    case IOC_READ:")
  pcmd("      desc->type = ioctl_desc::WRITE;")
  pcmd("      break;")
  pcmd("    case IOC_WRITE:")
  pcmd("      desc->type = ioctl_desc::READ;")
  pcmd("      break;")
  pcmd("    default:")
  pcmd("      return false;")
  pcmd("  }")
  pcmd("  // Size can be 0 iff type is NONE.")
  pcmd("  if ((desc->type == IOC_NONE) != (desc->size == 0)) return false;")
  pcmd("  // Sanity check.")
  pcmd("  if (IOC_TYPE(req) == 0) return false;")
  pcmd("  return true;")
  pcmd("}")
  pcmd("")
  pcmd("static const ioctl_desc *ioctl_lookup(unsigned req) {")
  pcmd("  req = ioctl_request_fixup(req);")
  pcmd("  const ioctl_desc *desc = ioctl_table_lookup(req);")
  pcmd("  if (desc) return desc;")
  pcmd("")
  pcmd("  // Try stripping access size from the request id.")
  pcmd("  desc = ioctl_table_lookup(req & ~(IOC_SIZEMASK << IOC_SIZESHIFT));")
  pcmd("  // Sanity check: requests that encode access size are either read or write and")
  pcmd("  // have size of 0 in the table.")
  pcmd("  if (desc && desc->size == 0 &&")
  pcmd("      (desc->type == ioctl_desc::READWRITE || desc->type == ioctl_desc::WRITE ||")
  pcmd("       desc->type == ioctl_desc::READ))")
  pcmd("    return desc;")
  pcmd("  return nullptr;")
  pcmd("}")
  pcmd("")
  pcmd("static void ioctl_common_pre(void *ctx, const ioctl_desc *desc, int d,")
  pcmd("                             unsigned request, void *arg) {")
  pcmd("  if (desc->type == ioctl_desc::READ || desc->type == ioctl_desc::READWRITE) {")
  pcmd("    unsigned size = desc->size ? desc->size : IOC_SIZE(request);")
  pcmd("    COMMON_INTERCEPTOR_READ_RANGE(ctx, arg, size);")
  pcmd("  }")
  pcmd("  if (desc->type != ioctl_desc::CUSTOM)")
  pcmd("    return;")
  pcmd("  if (request == IOCTL_SIOCGIFCONF) {")
  pcmd("    struct __sanitizer_ifconf *ifc = (__sanitizer_ifconf *)arg;")
  pcmd("    COMMON_INTERCEPTOR_READ_RANGE(ctx, (char*)&ifc->ifc_len,")
  pcmd("                                  sizeof(ifc->ifc_len));")
  pcmd("  }")
  pcmd("}")
  pcmd("")
  pcmd("static void ioctl_common_post(void *ctx, const ioctl_desc *desc, int res, int d,")
  pcmd("                              unsigned request, void *arg) {")
  pcmd("  if (desc->type == ioctl_desc::WRITE || desc->type == ioctl_desc::READWRITE) {")
  pcmd("    // FIXME: add verbose output")
  pcmd("    unsigned size = desc->size ? desc->size : IOC_SIZE(request);")
  pcmd("    COMMON_INTERCEPTOR_WRITE_RANGE(ctx, arg, size);")
  pcmd("  }")
  pcmd("  if (desc->type != ioctl_desc::CUSTOM)")
  pcmd("    return;")
  pcmd("  if (request == IOCTL_SIOCGIFCONF) {")
  pcmd("    struct __sanitizer_ifconf *ifc = (__sanitizer_ifconf *)arg;")
  pcmd("    COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ifc->ifc_ifcu.ifcu_req, ifc->ifc_len);")
  pcmd("  }")
  pcmd("}")

  close(cmd)
}

function usage()
{
  print "Usage: " script_name
  abnormal_exit = 1
  exit 1
}

function pcmd(string)
{
  print string | cmd
}
