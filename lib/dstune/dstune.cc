//===-- dstune.cc ---------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DeadStoreTuner (dstune), a dead store detector.
//
// Main file (entry points) for the Dstune run-time.
//===----------------------------------------------------------------------===//

#include "dstune.h"
#include "dstune_interface.h"
#include "dstune_shadow.h"
#include "sanitizer_common/sanitizer_addrhashmap.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_placement_new.h"

namespace __dstune {

bool DstuneIsInitialized;

// States for our shadow memory:
enum {
  ModeRead = 0,
  ModeWrittenOnce = 1,
  ModeWrittenAgain = 2,
};

// We shadow every byte of app memory with a shadow byte holding:
struct ShadowByte {
  // We don't get packing if we mix types so we cannot use an
  // enum type.
  unsigned char /* Mode* enum */ Mode:2;
  unsigned char /* bool */ ContextRequested:1;
};

// When we find a WAW we create an entry in a hashtable, keyed by
// app address.  This is the payload of our hashtable:
struct WriteAfterWrite {
  u64 Count;
  uptr FirstPC;
  uptr SecondPC;
  // FIXME: add first + second callstacks
};

typedef AddrHashMap<WriteAfterWrite, 31051> WriteAfterWriteHashMap;

// We use a pointer to avoid a static constructor
static WriteAfterWriteHashMap *WAWHashMap;

static void processWAWInstance(uptr PC, uptr Addr, ShadowByte &Shadow) {
  WriteAfterWriteHashMap::Handle h(WAWHashMap, Addr,
                                   /* remove */ false,
                                   /* create */ false);
  if (h.exists()) {
    CHECK(!h.created());
    h->Count++;
    // FIXME: what is LLVM method for cross-platform int64 format code?
    VPrintf(3, "WAW repeat %p: count %llu\n", Addr, h->Count);
  } else {
    WriteAfterWriteHashMap::Handle h(WAWHashMap, Addr);
    CHECK(h.created());
    h->Count = 1;
    h->FirstPC = 0;
    h->SecondPC = PC;
    Shadow.ContextRequested = 1;
    VPrintf(2, "New WAW instance PC=%p %p\n", PC, Addr);
  }
}

static void setWAWFirstPC(uptr PC, uptr Addr) {
  WriteAfterWriteHashMap::Handle h(WAWHashMap, Addr,
                                   /* remove */ false,
                                   /* create */ false);
  if (h.exists()) {
    CHECK(!h.created());
    h->FirstPC = PC;
  }
}

UNUSED static void removeWAWData(uptr Addr) {
  WriteAfterWriteHashMap::Handle h(WAWHashMap, Addr, /* remove */ true);
  CHECK(h.exists());
}

ALWAYS_INLINE USED
void processMemAccess(uptr PC, uptr Addr, int SizeLog, bool IsWrite) {
  VPrintf(3, "in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, 1 << SizeLog);
  // FIXME: optimize and inline into the instrumentation
  processRangeAccess(PC, Addr, 1 << SizeLog, IsWrite);
}

ALWAYS_INLINE USED
void processUnalignedAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  VPrintf(3, "in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, Size);
  processRangeAccess(PC, Addr, Size, IsWrite);
}

void processRangeAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  VPrintf(3, "in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, Size);
  // FIXME: optimize
  ShadowByte *Shadow = (ShadowByte *)appToShadow(Addr);
  for (int i = 0; i < Size; i++) {
    if (!IsWrite)
      Shadow->Mode = ModeRead;
    else if (Shadow->Mode == ModeRead) {
      Shadow->Mode = ModeWrittenOnce;
      if (Shadow->ContextRequested) {
        setWAWFirstPC(PC, Addr);
        Shadow->ContextRequested = 0;
      }
    } else {
      if (Shadow->Mode == ModeWrittenOnce)
        Shadow->Mode = ModeWrittenAgain;
      processWAWInstance(PC, Addr, *Shadow);
    }
    Addr++;
    Shadow++;
  }
}

static void initializeShadow() {
  static char HashMem[sizeof(WriteAfterWriteHashMap)];
  WAWHashMap = new((void *)&HashMem) WriteAfterWriteHashMap();

  uptr AppStart, AppEnd;
  for (int i = 0; getAppRegion(i, &AppStart, &AppEnd); i++) {
    uptr ShStart = appToShadow(AppStart);
    uptr ShEnd = appToShadow(AppEnd-1)+1; // Do not pass end itself!
    VPrintf(1, "Shadow #%d: %zx-%zx (%zuGB)\n", i, ShStart, ShEnd,
            (ShEnd - ShStart) >> 30);

    uptr Map = (uptr)MmapFixedNoReserve(ShStart, ShEnd - ShStart, "shadow");
    if (Map != ShStart) {
      Printf("FATAL: DeadStoreTuner failed to map its shadow memory.\n");
      Die();
    }

    // FIXME: should we call NoHugePagesInRegion() like other sanitizers?

    // FIXME: put under a flag (common_flags()->use_madv_dontdump)
    DontDumpShadowMemory(ShStart, ShEnd - ShStart);

    // FIXME: should we call MmapNoAccess() on in-between regions?

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
  CHECK(sizeof(ShadowByte) == 1);
}

void initializeLibrary() {
  // We assume there is only one thread during init.
  if (DstuneIsInitialized)
    return;
  DstuneIsInitialized = true;
  SanitizerToolName = "DeadStoreTuner";
  // FIXME: runtime flags: share with sanitizers?
  SetVerbosity(3); //NOCHECKIN
  VPrintf(1, "in dstune::%s\n", __FUNCTION__);
  initializeInterceptors();
  initializeShadow();
}

int finalizeLibrary() {
  VPrintf(1, "in dstune::%s\n", __FUNCTION__);
  return 0;
}

}  // namespace __dstune
