//===-- cfsan_shadow.h -----------------------------------------*- C++ -*-===//
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
// Shadow memory mappings for the cfsan run-time.
//===----------------------------------------------------------------------===//

#if !defined(__LP64__) && !defined(_WIN64)
# error "Only 64-bit is supported"
#endif

namespace __cfsan {

#if defined(__x86_64__)
// Linux/FreeBSD x86_64
//
// Application memory falls into these 4 regions (ignoring the corner case
// of PIE with a non-zero PT_LOAD base):
//
// [0x00000000'00000000, 0x00000100'00000000) non-PIE + heap
// [0x00005500'00000000, 0x00005700'00000000) PIE
// [0x00007f00'00000000, 0x00008000'00000000) libraries + stack
// [0xffffffff'ff600000, 0xffffffff'ff601000] vsyscall
//
// Our shadow memory is scaled from a 1:1 mapping.
// We follow Umbra's lead and use this formula:
//
//   shadow(app) = (app & 0x00000fff'ffffffff) + 0x00001200'00000000)
//
// (Do not pass in the open-ended end value.)
// The resulting shadow memory regions for a 0 scaling are:
//
// [0x00001200'00000000, 0x00001300'00000000)
// [0x00001700'00000000, 0x00001900'00000000)
// [0x00002100'00000000, 0x00002200'00000000)
// [0x000021ff'ff600000, 0x000021ff'ff601000]
//
// We also want to ensure that a wild access into the shadow regions
// will not corrupt our own shadow memory.
// shadow(shadow) ends up disjoint from shadow(app):
//
// [0x00001400'00000000, 0x00001500'00000000)
// [0x00001900'00000000, 0x00001b00'00000000)
// [0x00001300'00000000, 0x00001400'00000000]
// [0x000013ff'ff600000, 0x000013ff'ff601000]

// While an array seems simpler, we'll get faster code with constants
// that need no data load.
struct Mapping {
  static const uptr kApp1Start     = 0x0000000000000000ull;
  static const uptr kApp1End       = 0x0000010000000000ull;
  static const uptr kApp2Start     = 0x0000550000000000ull;
  static const uptr kApp2End       = 0x0000570000000000ull;
  static const uptr kApp3Start     = 0x00007f0000000000ull;
  static const uptr kApp3End       = 0x0000800000000000ull;
  static const uptr kApp4Start     = 0xffffffffff600000ull;
  static const uptr kApp4End       = 0xffffffffff601000ull;
  // We scale by 3 for an 8B:1B or 1B:1b mapping.
  static const uptr kShadowScale   = 3;
  static const uptr kShadowMask    = 0x00000fffffffffffull;
  static const uptr kShadowOffs    = 0x0000120000000000ull;
};
#else
// We'll want to use templatized functions over the Mapping once
// we support more platforms.
# error Platform not supported
#endif

static inline
bool getAppRegion(int i, uptr *Start, uptr *End) {
  switch (i) {
  default:
    return false;
  case 0:
    *Start = Mapping::kApp1Start;
    *End = Mapping::kApp1End;
    return true;
  case 1:
    *Start = Mapping::kApp2Start;
    *End = Mapping::kApp2End;
    return true;
  case 2:
    *Start = Mapping::kApp3Start;
    *End = Mapping::kApp3End;
    return true;
  case 3:
    *Start = Mapping::kApp4Start;
    *End = Mapping::kApp4End;
    return true;
  }
}

ALWAYS_INLINE
bool isAppMem(uptr Mem) {
#ifdef __x86_64__
  return ((/*always true: Mem >= Mapping::kApp1Start &&*/ Mem < Mapping::kApp1End) ||
          (Mem >= Mapping::kApp2Start && Mem < Mapping::kApp2End) ||
          (Mem >= Mapping::kApp3Start && Mem < Mapping::kApp3End) ||
          (Mem >= Mapping::kApp4Start && Mem < Mapping::kApp4End));
#else
# error Platform not supported
#endif
}

ALWAYS_INLINE
uptr appToShadow(uptr App) {
  DCHECK(IsAppMem(x));
  return (((App & Mapping::kShadowMask) +
           (Mapping::kShadowOffs << Mapping::kShadowScale))
          >> Mapping::kShadowScale);
}

ALWAYS_INLINE
bool isShadowMem(uptr Mem) {
  // We assume this is only really used for debugging and so there's
  // no need to hardcode the mapping results.
#ifdef __x86_64__
  return ((Mem >= appToShadow(Mapping::kApp1Start) &&
           Mem <= appToShadow(Mapping::kApp1End-1)) ||
          (Mem >= appToShadow(Mapping::kApp2Start) &&
           Mem <= appToShadow(Mapping::kApp2End-1)) ||
          (Mem >= appToShadow(Mapping::kApp3Start) &&
           Mem <= appToShadow(Mapping::kApp3End-1)) ||
          (Mem >= appToShadow(Mapping::kApp4Start) &&
           Mem <= appToShadow(Mapping::kApp4End-1)));
#else
# error Platform not supported
#endif
}

} // namespace __cfsan
