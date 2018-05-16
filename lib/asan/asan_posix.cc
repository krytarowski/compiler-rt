//===-- asan_posix.cc -----------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// Posix-specific details.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_POSIX

#include "asan_internal.h"
#include "asan_interceptors.h"
#include "asan_mapping.h"
#include "asan_report.h"
#include "asan_stack.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "sanitizer_common/sanitizer_procmaps.h"

#include <pthread.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

namespace __asan {

void AsanOnDeadlySignal(int signo, void *siginfo, void *context) {
  StartReportDeadlySignal();
  SignalContext sig(siginfo, context);
  ReportDeadlySignal(sig);
}

// ---------------------- TSD ---------------- {{{1

struct TsdKey {
  void *data;
  void (*dst)(void *value);
  TsdKey() : data(nullptr), dst(nullptr) {}
  ~TsdKey() {
    if (dst)
      dst(data);
  }
};

static thread_local TsdKey Tk;
static bool tsd_key_inited = false;
void AsanTSDInit(void (*destructor)(void *tsd)) {
  CHECK(!tsd_key_inited);
  tsd_key_inited = true;
  Tk.dst = destructor;
}

void *AsanTSDGet() {
  CHECK(tsd_key_inited);
  return Tk.data;
}

void AsanTSDSet(void *tsd) {
  CHECK(tsd_key_inited);
  Tk.data = tsd;
}

void PlatformTSDDtor(void *tsd) {
  AsanThread::TSDDtor(tsd);
}
}  // namespace __asan

#endif  // SANITIZER_POSIX
