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
  # List generated manually with the following script:
  #   for w in `find /usr/include/ -type f -name '*.h' -exec echo {} \;`; \
  #   do awk '/[^a-zA-Z0-9_]_IO[W]*[R]*[ ]*\(/ && $2 ~ /^[A-Z_]+$/ {got=1} END{if(got) {print ARGV[1]}}' $w; \
  #   done|awk '{print "  ARGV[ARGC++] = rootdir \"" substr($0, 14) "\""}'

  ARGV[ARGC++] = rootdir "altq/altq_afmap.h"
  ARGV[ARGC++] = rootdir "altq/altq.h"
  ARGV[ARGC++] = rootdir "altq/altq_blue.h"
  ARGV[ARGC++] = rootdir "altq/altq_cbq.h"
  ARGV[ARGC++] = rootdir "altq/altq_cdnr.h"
  ARGV[ARGC++] = rootdir "altq/altq_fifoq.h"
  ARGV[ARGC++] = rootdir "altq/altq_hfsc.h"
  ARGV[ARGC++] = rootdir "altq/altq_jobs.h"
  ARGV[ARGC++] = rootdir "altq/altq_priq.h"
  ARGV[ARGC++] = rootdir "altq/altq_red.h"
  ARGV[ARGC++] = rootdir "altq/altq_rio.h"
  ARGV[ARGC++] = rootdir "altq/altq_wfq.h"
  ARGV[ARGC++] = rootdir "crypto/cryptodev.h"
  ARGV[ARGC++] = rootdir "dev/apm/apmio.h"
  ARGV[ARGC++] = rootdir "dev/dm/netbsd-dm.h"
  ARGV[ARGC++] = rootdir "dev/dmover/dmover_io.h"
  ARGV[ARGC++] = rootdir "dev/dtv/dtvio_demux.h"
  ARGV[ARGC++] = rootdir "dev/dtv/dtvio_frontend.h"
  ARGV[ARGC++] = rootdir "dev/filemon/filemon.h"
  ARGV[ARGC++] = rootdir "dev/hdaudio/hdaudioio.h"
  ARGV[ARGC++] = rootdir "dev/hdmicec/hdmicecio.h"
  ARGV[ARGC++] = rootdir "dev/hpc/hpcfbio.h"
  ARGV[ARGC++] = rootdir "dev/i2o/iopio.h"
  ARGV[ARGC++] = rootdir "dev/ic/athioctl.h"
  ARGV[ARGC++] = rootdir "dev/ic/bt8xx.h"
  ARGV[ARGC++] = rootdir "dev/ic/hd44780var.h"
  ARGV[ARGC++] = rootdir "dev/ic/icp_ioctl.h"
  ARGV[ARGC++] = rootdir "dev/ic/isp_ioctl.h"
  ARGV[ARGC++] = rootdir "dev/ic/mlxio.h"
  ARGV[ARGC++] = rootdir "dev/ic/nvmeio.h"
  ARGV[ARGC++] = rootdir "dev/ir/irdaio.h"
  ARGV[ARGC++] = rootdir "dev/isa/satlinkio.h"
  ARGV[ARGC++] = rootdir "dev/isa/isvio.h"
  ARGV[ARGC++] = rootdir "dev/isa/wtreg.h"
  ARGV[ARGC++] = rootdir "dev/iscsi/iscsi_ioctl.h"
  ARGV[ARGC++] = rootdir "dev/ofw/openfirmio.h"
  ARGV[ARGC++] = rootdir "dev/pci/amrio.h"
  ARGV[ARGC++] = rootdir "dev/pci/mlyio.h"
  ARGV[ARGC++] = rootdir "dev/pci/pciio.h"
  ARGV[ARGC++] = rootdir "dev/pci/tweio.h"
  ARGV[ARGC++] = rootdir "dev/pcmcia/if_cnwioctl.h"
  ARGV[ARGC++] = rootdir "dev/pcmcia/if_rayreg.h"
  ARGV[ARGC++] = rootdir "dev/raidframe/raidframeio.h"
  ARGV[ARGC++] = rootdir "dev/sbus/mbppio.h"
  ARGV[ARGC++] = rootdir "dev/scsipi/ses.h"
  ARGV[ARGC++] = rootdir "dev/sun/disklabel.h"
  ARGV[ARGC++] = rootdir "dev/sun/fbio.h"
  ARGV[ARGC++] = rootdir "dev/sun/kbio.h"
  ARGV[ARGC++] = rootdir "dev/sun/vuid_event.h"
  ARGV[ARGC++] = rootdir "dev/tc/sticio.h"
  ARGV[ARGC++] = rootdir "dev/usb/ukyopon.h"
  ARGV[ARGC++] = rootdir "dev/usb/urio.h"
  ARGV[ARGC++] = rootdir "dev/usb/usb.h"
  ARGV[ARGC++] = rootdir "dev/usb/utoppy.h"
  ARGV[ARGC++] = rootdir "dev/vme/xio.h"
  ARGV[ARGC++] = rootdir "dev/wscons/wsdisplay_usl_io.h"
  ARGV[ARGC++] = rootdir "dev/wscons/wsconsio.h"
  ARGV[ARGC++] = rootdir "dev/biovar.h"
  ARGV[ARGC++] = rootdir "dev/md.h"
  ARGV[ARGC++] = rootdir "dev/ccdvar.h"
  ARGV[ARGC++] = rootdir "dev/cgdvar.h"
  ARGV[ARGC++] = rootdir "dev/fssvar.h"
  ARGV[ARGC++] = rootdir "dev/bluetooth/btdev.h"
  ARGV[ARGC++] = rootdir "dev/bluetooth/btsco.h"
  ARGV[ARGC++] = rootdir "dev/kttcpio.h"
  ARGV[ARGC++] = rootdir "dev/lockstat.h"
  ARGV[ARGC++] = rootdir "dev/vndvar.h"
  ARGV[ARGC++] = rootdir "dev/spkrio.h"
  ARGV[ARGC++] = rootdir "net/bpf.h"
  ARGV[ARGC++] = rootdir "net/if_atm.h"
  ARGV[ARGC++] = rootdir "net/if_gre.h"
  ARGV[ARGC++] = rootdir "net/if_ppp.h"
  ARGV[ARGC++] = rootdir "net/npf.h"
  ARGV[ARGC++] = rootdir "net/if_pppoe.h"
  ARGV[ARGC++] = rootdir "net/if_sppp.h"
  ARGV[ARGC++] = rootdir "net/if_srt.h"
  ARGV[ARGC++] = rootdir "net/if_tap.h"
  ARGV[ARGC++] = rootdir "net/if_tun.h"
  ARGV[ARGC++] = rootdir "net/pfvar.h"
  ARGV[ARGC++] = rootdir "net/slip.h"
  ARGV[ARGC++] = rootdir "netbt/hci.h"
  ARGV[ARGC++] = rootdir "netinet/ip_nat.h"
  ARGV[ARGC++] = rootdir "netinet/ip_proxy.h"
  ARGV[ARGC++] = rootdir "netinet6/in6_var.h"
  ARGV[ARGC++] = rootdir "netnatm/natm.h"
  ARGV[ARGC++] = rootdir "netsmb/smb_dev.h"
  ARGV[ARGC++] = rootdir "sys/agpio.h"
  ARGV[ARGC++] = rootdir "sys/audioio.h"
  ARGV[ARGC++] = rootdir "sys/ataio.h"
  ARGV[ARGC++] = rootdir "sys/cdio.h"
  ARGV[ARGC++] = rootdir "sys/chio.h"
  ARGV[ARGC++] = rootdir "sys/clockctl.h"
  ARGV[ARGC++] = rootdir "sys/cpuio.h"
  ARGV[ARGC++] = rootdir "sys/dkio.h"
  ARGV[ARGC++] = rootdir "sys/drvctlio.h"
  ARGV[ARGC++] = rootdir "sys/dvdio.h"
  ARGV[ARGC++] = rootdir "sys/envsys.h"
  ARGV[ARGC++] = rootdir "sys/event.h"
  ARGV[ARGC++] = rootdir "sys/fdio.h"
  ARGV[ARGC++] = rootdir "sys/filio.h"
  ARGV[ARGC++] = rootdir "sys/gpio.h"
  ARGV[ARGC++] = rootdir "sys/ioctl.h"
  ARGV[ARGC++] = rootdir "sys/ioctl_compat.h"
  ARGV[ARGC++] = rootdir "sys/joystick.h"
  ARGV[ARGC++] = rootdir "sys/ksyms.h"
  ARGV[ARGC++] = rootdir "sys/lua.h"
  ARGV[ARGC++] = rootdir "sys/midiio.h"
  ARGV[ARGC++] = rootdir "sys/mtio.h"
  ARGV[ARGC++] = rootdir "sys/power.h"
  ARGV[ARGC++] = rootdir "sys/radioio.h"
  ARGV[ARGC++] = rootdir "sys/rndio.h"
  ARGV[ARGC++] = rootdir "sys/scanio.h"
  ARGV[ARGC++] = rootdir "sys/scsiio.h"
  ARGV[ARGC++] = rootdir "sys/sockio.h"
  ARGV[ARGC++] = rootdir "sys/timepps.h"
  ARGV[ARGC++] = rootdir "sys/ttycom.h"
  ARGV[ARGC++] = rootdir "sys/verified_exec.h"
  ARGV[ARGC++] = rootdir "sys/videoio.h"
  ARGV[ARGC++] = rootdir "sys/wdog.h"
  ARGV[ARGC++] = rootdir "soundcard.h"
  ARGV[ARGC++] = rootdir "xen/xenio.h"

  ioctl_table_max = 0
}

# Scan RCS ID
FNR == 1 {
  while (!match($0, /NetBSD: [a-z0-9_-]+.h/)) {
    print "mijam: " FILENAME
    next
  }
  fname[ioctl_table_max] = substr($0, RSTART + 8, RLENGTH - 8)
}

# _IO
/[^a-zA-Z0-9_]_IO[W]*[R]*[ ]*\(/ && $2 ~ /^[A-Z_]+$/ {
  ioctl_name[ioctl_table_max] = $2

  split($3, a, "(")
  a3 = a[1]
  if (a3 ~ /_IO[ ]*$/) {
    ioctl_mode[ioctl_table_max] = "NONE"
  } else if (a3 ~ /_IOR[ ]*$/) {
    ioctl_mode[ioctl_table_max] = "READ"
  } else if (a3 ~ /_IOW[ ]*$/) {
    ioctl_mode[ioctl_table_max] = "WRITE"
  } else if (a3 ~ /_IOWR[ ]*$/) {
    ioctl_mode[ioctl_table_max] = "READWRITE"
  } else {
    print "Unknown mode, cannot parse: '" $3 "'"
  }

  n = split($0, a, ",")
  if (n == 3) {
    gsub(/^[ ]+/, "", a[3])
    gsub(/\)$/, "", a[3])
    ioctl_type[ioctl_table_max] = a[3]
  }

  ioctl_table_max++
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
  pcmd("#define _(rq, tp, sz)                                    \\")
  pcmd("  if (IOCTL_##rq != IOCTL_NOT_PRESENT) {                 \\")
  pcmd("    CHECK(ioctl_table_size < ioctl_table_max);           \\")
  pcmd("    ioctl_table[ioctl_table_size].req = IOCTL_##rq;      \\")
  pcmd("    ioctl_table[ioctl_table_size].type = ioctl_desc::tp; \\")
  pcmd("    ioctl_table[ioctl_table_size].size = sz;             \\")
  pcmd("    ioctl_table[ioctl_table_size].name = #rq;            \\")
  pcmd("    ++ioctl_table_size;                                  \\")
  pcmd("  }")
  pcmd("")

  for (i = 0; i < ioctl_table_max; i++) {
    if (i in fname) {
      pcmd("  /* Entries from file: " fname[i] " */")
    }

    pcmd("  _(" ioctl_name[i] ", " ioctl_mode[i] ");")
  }

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
  pcmd("      Printf(\"Duplicate or unsorted ioctl request id %x >= %x (%s vs %s)\\n\",")
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
