//===-- sanitizer_common_interceptors_ioctl.inc -----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Ioctl handling in common sanitizer interceptors.
//===----------------------------------------------------------------------===//

#include "sanitizer_flags.h"

struct ioctl_desc {
  unsigned req;
  // FIXME: support read+write arguments. Currently READWRITE and WRITE do the
  // same thing.
  // XXX: The declarations below may use WRITE instead of READWRITE, unless
  // explicitly noted.
  enum { NONE, READ, WRITE, READWRITE, CUSTOM } type : 3;
  unsigned size : 29;
  const char *name;
};

const unsigned ioctl_table_max = 42;
static ioctl_desc ioctl_table[ioctl_table_max];
static unsigned ioctl_table_size = 0;

// This can not be declared as a global, because references to struct_*_sz
// require a global initializer. And this table must be available before global
// initializers are run.
static void ioctl_table_fill() {
#define _(rq, tp, sz)                                                          \
  if (IOCTL_##rq != IOCTL_NOT_PRESENT) {                                       \
    CHECK(ioctl_table_size < ioctl_table_max);                                 \
    ioctl_table[ioctl_table_size].req = IOCTL_##rq;                            \
    ioctl_table[ioctl_table_size].type = ioctl_desc::tp;                       \
    ioctl_table[ioctl_table_size].size = sz;                                   \
    ioctl_table[ioctl_table_size].name = #rq;                                  \
    ++ioctl_table_size;                                                        \
  }

  /* Entries from file: soundcard.h */
  _(SNDCTL_DSP_RESET, );
  _(SNDCTL_DSP_SYNC, );
  _(SNDCTL_DSP_SPEED, READWRITE);
  _(SOUND_PCM_READ_RATE, );
  _(SNDCTL_DSP_STEREO, READWRITE);
  _(SNDCTL_DSP_GETBLKSIZE, READWRITE);
  _(SNDCTL_DSP_SETFMT, READWRITE);
  _(SOUND_PCM_READ_BITS, );
  _(SNDCTL_DSP_CHANNELS, READWRITE);
  _(SOUND_PCM_READ_CHANNELS, );
  _(SOUND_PCM_WRITE_FILTER, READWRITE);
  _(SOUND_PCM_READ_FILTER, );
  _(SNDCTL_DSP_POST, );
  _(SNDCTL_DSP_SUBDIVIDE, READWRITE);
  _(SNDCTL_DSP_SETFRAGMENT, READWRITE);
  _(SNDCTL_DSP_GETFMTS, );
  _(SNDCTL_DSP_GETOSPACE, );
  _(SNDCTL_DSP_GETISPACE, );
  _(SNDCTL_DSP_NONBLOCK, );
  _(SNDCTL_DSP_GETCAPS, );
  _(SNDCTL_DSP_GETTRIGGER, );
  _(SNDCTL_DSP_SETTRIGGER, );
  _(SNDCTL_DSP_GETIPTR, );
  _(SNDCTL_DSP_GETOPTR, );
  _(SNDCTL_DSP_MAPINBUF, );
  _(SNDCTL_DSP_MAPOUTBUF, );
  _(SNDCTL_DSP_SETSYNCRO, );
  _(SNDCTL_DSP_SETDUPLEX, );
  _(SNDCTL_DSP_PROFILE, );
  _(SNDCTL_DSP_GETODELAY, );
  _(SOUND_MIXER_INFO, READ);
  _(SOUND_OLD_MIXER_INFO, READ);
  _(OSS_GETVERSION, );
  _(SNDCTL_SYSINFO, );
  _(SNDCTL_AUDIOINFO, );
  _(SNDCTL_ENGINEINFO, );
  _(SNDCTL_DSP_GETPLAYVOL, );
  _(SNDCTL_DSP_SETPLAYVOL, );
  _(SNDCTL_DSP_GETRECVOL, );
  _(SNDCTL_DSP_SETRECVOL, );
  _(SNDCTL_DSP_SKIP, );
  _(SNDCTL_DSP_SILENCE, );
#undef _
}

static bool ioctl_initialized = false;

struct ioctl_desc_compare {
  bool operator()(const ioctl_desc &left, const ioctl_desc &right) const {
    return left.req < right.req;
  }
};

static void ioctl_init() {
  ioctl_table_fill();
  InternalSort(&ioctl_table, ioctl_table_size, ioctl_desc_compare());

  bool bad = false;
  for (unsigned i = 0; i < ioctl_table_size - 1; ++i) {
    if (ioctl_table[i].req >= ioctl_table[i + 1].req) {
      Printf("Duplicate or unsorted ioctl request id %x >= %x (%s vs %s)\n",
             ioctl_table[i].req, ioctl_table[i + 1].req, ioctl_table[i].name,
             ioctl_table[i + 1].name);
      bad = true;
    }
  }

  if (bad)
    Die();

  ioctl_initialized = true;
}

static const ioctl_desc *ioctl_table_lookup(unsigned req) {
  int left = 0;
  int right = ioctl_table_size;
  while (left < right) {
    int mid = (left + right) / 2;
    if (ioctl_table[mid].req < req)
      left = mid + 1;
    else
      right = mid;
  }
  if (left == right && ioctl_table[left].req == req)
    return ioctl_table + left;
  else
    return nullptr;
}

static bool ioctl_decode(unsigned req, ioctl_desc *desc) {
  CHECK(desc);
  desc->req = req;
  desc->name = "<DECODED_IOCTL>";
  desc->size = IOC_SIZE(req);
  // Sanity check.
  if (desc->size > 0xFFFF)
    return false;
  unsigned dir = IOC_DIR(req);
  switch (dir) {
  case IOC_NONE:
    desc->type = ioctl_desc::NONE;
    break;
  case IOC_READ | IOC_WRITE:
    desc->type = ioctl_desc::READWRITE;
    break;
  case IOC_READ:
    desc->type = ioctl_desc::WRITE;
    break;
  case IOC_WRITE:
    desc->type = ioctl_desc::READ;
    break;
  default:
    return false;
  }
  // Size can be 0 iff type is NONE.
  if ((desc->type == IOC_NONE) != (desc->size == 0))
    return false;
  // Sanity check.
  if (IOC_TYPE(req) == 0)
    return false;
  return true;
}

static const ioctl_desc *ioctl_lookup(unsigned req) {
  const ioctl_desc *desc = ioctl_table_lookup(req);
  if (desc)
    return desc;

  // Try stripping access size from the request id.
  desc = ioctl_table_lookup(req & ~(IOC_SIZEMASK << IOC_SIZESHIFT));
  // Sanity check: requests that encode access size are either read or write and
  // have size of 0 in the table.
  if (desc && desc->size == 0 &&
      (desc->type == ioctl_desc::READWRITE || desc->type == ioctl_desc::WRITE ||
       desc->type == ioctl_desc::READ))
    return desc;
  return nullptr;
}

static void ioctl_common_pre(void *ctx, const ioctl_desc *desc, int d,
                             unsigned request, void *arg) {
  if (desc->type == ioctl_desc::READ || desc->type == ioctl_desc::READWRITE) {
    unsigned size = desc->size ? desc->size : IOC_SIZE(request);
    COMMON_INTERCEPTOR_READ_RANGE(ctx, arg, size);
  }
  if (desc->type != ioctl_desc::CUSTOM)
    return;
  if (request == IOCTL_SIOCGIFCONF) {
    struct __sanitizer_ifconf *ifc = (__sanitizer_ifconf *)arg;
    COMMON_INTERCEPTOR_READ_RANGE(ctx, (char *)&ifc->ifc_len,
                                  sizeof(ifc->ifc_len));
  }
}

static void ioctl_common_post(void *ctx, const ioctl_desc *desc, int res, int d,
                              unsigned request, void *arg) {
  if (desc->type == ioctl_desc::WRITE || desc->type == ioctl_desc::READWRITE) {
    // FIXME: add verbose output
    unsigned size = desc->size ? desc->size : IOC_SIZE(request);
    COMMON_INTERCEPTOR_WRITE_RANGE(ctx, arg, size);
  }
  if (desc->type != ioctl_desc::CUSTOM)
    return;
  if (request == IOCTL_SIOCGIFCONF) {
    struct __sanitizer_ifconf *ifc = (__sanitizer_ifconf *)arg;
    COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ifc->ifc_ifcu.ifcu_req, ifc->ifc_len);
  }
}
