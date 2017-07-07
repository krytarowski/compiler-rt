//===-- interception_linux.cc -----------------------------------*- C++ -*-===//
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
// Linux-specific interception methods.
//===----------------------------------------------------------------------===//

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
#include "interception.h"

#include <dlfcn.h>   // for dlsym() and dlvsym()

#ifdef __NetBSD__
static int mystrcmp(const char *s1, const char *s2) {
  while (*s1 == *s2++)
    if (*s1++ == 0) return (0);
  return (*(const unsigned char *)s1 - *(const unsigned char *)--s2);
}
#endif

namespace __interception {
bool GetRealFunctionAddress(const char *func_name, uptr *func_addr,
    uptr real, uptr wrapper) {
#ifdef __NetBSD__
  // XXX: Until I come up with something better to deal with renames.
  if (mystrcmp(func_name, "sigaction") == 0) func_name = "__sigaction14";
#endif
  *func_addr = (uptr)dlsym(RTLD_NEXT, func_name);
  return real == wrapper;
}

#if !defined(__ANDROID__)  // android does not have dlvsym
void *GetFuncAddrVer(const char *func_name, const char *ver) {
  return dlvsym(RTLD_NEXT, func_name, ver);
}
#endif  // !defined(__ANDROID__)

}  // namespace __interception

#endif  // __linux__ || __FreeBSD__ || __NetBSD__
