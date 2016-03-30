//===-- cfsan.cc ---------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of CacheFragSanitizer (cfsan), a cache fragmentation
// analysis tool.
//
// Main file (entry points) for the Cfsan run-time.
//===----------------------------------------------------------------------===//

#include "cfsan.h"
#include "cfsan_interface.h"
#include "cfsan_shadow.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"

namespace __cfsan {

bool CfsanIsInitialized;

static const char * const kCfsanOpsEnv = "CFSAN_OPTIONS";

// We shadow every byte of app memory with one shadow bit.
// We live with races in accessing each shadow byte.
typedef unsigned char byte;

ALWAYS_INLINE USED
void processMemAccess(uptr PC, uptr Addr, int SizeLog, bool IsWrite) {
  VPrintf(4, "in cfsan::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, 1 << SizeLog);
  // We expect common accesses to be inlined so we go for simplicity here:
  processRangeAccess(PC, Addr, 1 << SizeLog, IsWrite);
}

ALWAYS_INLINE USED
void processUnalignedAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  VPrintf(4, "in cfsan::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, Size);
  processRangeAccess(PC, Addr, Size, IsWrite);
}

void processRangeAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  VPrintf(3, "in cfsan::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, Size);
  int i = 0;
  byte *Shadow = (byte *)appToShadow(Addr);
  int Mod = Addr % 8;
  byte Mask;
  // First, write the top bits of the first shadow byte
  if (Mod != 0) {
    if (Mod + Size >= 8)
      Mask = (byte)-1 << Mod;
    else
      Mask = ((1U << Size) - 1) << Mod;
    *Shadow |= Mask;
    Addr += (8 - Mod);
    i += (8 - Mod);
    ++Shadow;
    CHECK((byte *)appToShadow(Addr) == Shadow);
  }
  // Now write entire shadow words
  while (i + 32 < Size) {
    *(int *)Shadow = -1;
    Addr += 32;
    i += 32;
    Shadow += 4;
  }
  // Now write entire shadow bytes
  CHECK((byte *)appToShadow(Addr) == Shadow);
  while (i + 8 < Size) {
    *Shadow = (byte)-1;
    Addr += 8;
    i += 8;
    ++Shadow;
  }
  // Finally, write the low bits of the last shadow byte
  CHECK((byte *)appToShadow(Addr) == Shadow);
  if (i < Size) {
    Mask = (1U << (Size - i)) - 1;
    *Shadow |= Mask;
  }
}

static void initializeShadow() {
  uptr AppStart, AppEnd;
  for (int i = 0; getAppRegion(i, &AppStart, &AppEnd); i++) {
    uptr ShStart = appToShadow(AppStart);
    uptr ShEnd = appToShadow(AppEnd-1)+1; // Do not pass end itself!
    VPrintf(1, "Shadow #%d: %zx-%zx (%zuGB)\n", i, ShStart, ShEnd,
            (ShEnd - ShStart) >> 30);

    uptr Map = (uptr)MmapFixedNoReserve(ShStart, ShEnd - ShStart, "shadow");
    if (Map != ShStart) {
      Printf("FATAL: CacheFragSanitizer failed to map its shadow memory.\n");
      Die();
    }

    if (common_flags()->no_huge_pages_for_shadow)
      NoHugePagesInRegion(ShStart, ShEnd - ShStart);
    if (common_flags()->use_madv_dontdump)
      DontDumpShadowMemory(ShStart, ShEnd - ShStart);

    // TODO(bruening): call MmapNoAccess() on in-between regions

    // Sanity checks for the shadow mapping
    CHECK(isAppMem(AppStart));
    CHECK(!isAppMem(AppStart-1));
    CHECK(isAppMem(AppEnd-1));
    CHECK(!isAppMem(AppEnd));
    CHECK(!isShadowMem(AppStart));
    CHECK(!isShadowMem(AppEnd-1));
    CHECK(isShadowMem(appToShadow(AppStart)));
    CHECK(isShadowMem(appToShadow(AppEnd-1)));
    CHECK(!isShadowMem(appToShadow(appToShadow(AppStart))));
    CHECK(!isShadowMem(appToShadow(appToShadow(AppEnd-1))));
  }
}

static void initializeFlags() {
  // Once we add our own flags we'll parse them here.
  // For now the common ones are sufficient.
  FlagParser parser;
  RegisterCommonFlags(&parser);
  parser.ParseString(GetEnv(kCfsanOpsEnv));
  SetVerbosity(common_flags()->verbosity);
  if (Verbosity())
    ReportUnrecognizedFlags();
  if (common_flags()->help)
    parser.PrintFlagDescriptions();
  __sanitizer_set_report_path(common_flags()->log_path);
}

void initializeLibrary() {
  // We assume there is only one thread during init.
  if (CfsanIsInitialized)
    return;
  CfsanIsInitialized = true;
  SanitizerToolName = "CacheFragSanitizer";
  initializeFlags();
  VPrintf(1, "in cfsan::%s\n", __FUNCTION__);
  initializeInterceptors();
  initializeShadow();
}

int finalizeLibrary() {
  VPrintf(1, "in cfsan::%s\n", __FUNCTION__);
  // FIXME NYI: we need to add sampling + callstack gathering and have a
  // strategy for how to generate a final report.
  Report("%s is not finished: nothing yet to report\n", SanitizerToolName);
  return 0;
}

} // namespace __cfsan
