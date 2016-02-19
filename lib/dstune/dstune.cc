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
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_placement_new.h"

namespace __dstune {

bool DstuneIsInitialized;

static const char * const kDstuneOpsEnv = "DSTUNE_OPTIONS";

// States for our shadow memory:
enum {
  ModeRead = 0,
  ModeWrittenOnce = 1,
  ModeWrittenAgain = 2,
};

#define SHADOW_COUNTER_BITS 5

// We shadow every byte of app memory with a shadow byte.
// We live with races in accessing each shadow byte.
struct ShadowByte {
  // We don't get packing if we mix types so we cannot use an
  // enum type.
  unsigned char /* Mode* enum */ Mode:2;
  unsigned char /* bool */ ContextRequested:1;
  unsigned char Counter:SHADOW_COUNTER_BITS;
};

static const int kShadowCounterMax = (1 << SHADOW_COUNTER_BITS) - 1;

// When we find a WAW we create an entry in a hashtable, keyed by
// app address.  This is the payload of our hashtable:
struct WriteAfterWrite {
  u64 Count;
  uptr FirstPC;
  uptr SecondPC;
  // FIXME: add first + second callstacks
};

// FIXME: the AddrHashMap table has no resizing of the main hashed table
// to maintain a reasonable load balance across varying amounts of data
// (it only grows the "add cells" conflict list).
// We should measure the cost and improve or replace it if necessary.
typedef AddrHashMap<WriteAfterWrite, 31051000> WriteAfterWriteHashMap;

// We use a pointer to avoid a static constructor
static WriteAfterWriteHashMap *WAWHashMap;

static void processWAWInstance(uptr PC, uptr Addr, ShadowByte &Shadow) {
  // We filter out the low-count WAW instances with this in-shadow counter.
  // FIXME: this can cause us to completely miss WAW instances that use
  // different data addresses each time.  This is a downside to the
  // data-oriented approach.
  if (Shadow.Counter != kShadowCounterMax) {
    Shadow.Counter++;
    return;
  }
  WriteAfterWriteHashMap::Handle h(WAWHashMap, Addr,
                                   /* remove */ false,
                                   /* create */ false);
  if (h.exists()) {
    // FIXME: handle the same data address being involved in multiple
    // WAW instances with different first and/or second PC's.
    // Keep a list of PC's instead of just one.
    CHECK(!h.created());
    h->Count++;
    // FIXME: what is LLVM method for cross-platform int64 format code?
    VPrintf(4, "WAW repeat %p: count %llu\n", Addr, h->Count);
    // FIXME: once Count crosses some threshold, set a bit requesting
    // callstacks.  Uniquify and store the callstacks from each such periodic
    // walk, each with their own counter.
  } else {
    WriteAfterWriteHashMap::Handle h(WAWHashMap, Addr);
    CHECK(h.created());
    h->Count = kShadowCounterMax + 1;
    h->FirstPC = 0;
    h->SecondPC = PC;
    Shadow.ContextRequested = 1;
    VPrintf(3, "New WAW instance PC=%p %p\n", PC, Addr);
  }
}

static void setWAWFirstPC(uptr PC, uptr Addr) {
  WriteAfterWriteHashMap::Handle h(WAWHashMap, Addr,
                                   /* remove */ false,
                                   /* create */ false);
  if (h.exists()) {
    CHECK(!h.created());
    //NOCHECKIN we only have read access to the data
    //  We need to add a lookup routine that holds the write lock.
    //  Ditto for h->Count++ above.
    h->FirstPC = PC;
  }
}

UNUSED static void removeWAWData(uptr Addr) {
  WriteAfterWriteHashMap::Handle h(WAWHashMap, Addr, /* remove */ true);
  CHECK(h.exists());
}

ALWAYS_INLINE USED
void processMemAccess(uptr PC, uptr Addr, int SizeLog, bool IsWrite) {
  VPrintf(4, "in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, 1 << SizeLog);
  // FIXME: optimize and inline into the instrumentation
  processRangeAccess(PC, Addr, 1 << SizeLog, IsWrite);
}

ALWAYS_INLINE USED
void processUnalignedAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  VPrintf(4, "in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
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

static void initializeFlags() {
  // Once we add our own flags we'll parse them here.
  // For now the common ones are sufficient.
  FlagParser parser;
  RegisterCommonFlags(&parser);
  parser.ParseString(GetEnv(kDstuneOpsEnv));
  SetVerbosity(common_flags()->verbosity);
  if (Verbosity())
    ReportUnrecognizedFlags();
  if (common_flags()->help)
    parser.PrintFlagDescriptions();
  __sanitizer_set_report_path(common_flags()->log_path);
}

void initializeLibrary() {
  // We assume there is only one thread during init.
  if (DstuneIsInitialized)
    return;
  DstuneIsInitialized = true;
  SanitizerToolName = "DeadStoreTuner";
  initializeFlags();
  VPrintf(1, "in dstune::%s\n", __FUNCTION__);
  initializeInterceptors();
  initializeShadow();
}

int finalizeLibrary() {
  VPrintf(1, "in dstune::%s\n", __FUNCTION__);
  if (WAWHashMap->size() > 0) {
    Report("%d write-after-write instances found:\n", WAWHashMap->size());
    int i = 0;
    for (auto iter = WAWHashMap->begin();
         iter != WAWHashMap->end();
         ++iter, ++i) {
      WriteAfterWrite *WAW = (WriteAfterWrite *) (*iter).value;
      // FIXME: what is LLVM method for cross-platform int64 format code?
      // XXX: FirstPC may be NULL if there was no read after our request
      Report(" #%d: write to %p by %p and %p %lldx\n", i, (uptr)(*iter).addr,
             WAW->FirstPC, WAW->SecondPC, WAW->Count);
    }
  }

  return 0;
}

}  // namespace __dstune
