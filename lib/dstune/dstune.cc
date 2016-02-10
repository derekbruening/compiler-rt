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

#include "dstune_interface.h"
#include "dstune.h"
#include "sanitizer_common/sanitizer_common.h"

namespace __dstune {

void Initialize() {
  // We assume there is only one thread during init.
  static bool IsInitialized = false;
  if (IsInitialized)
    return;
  IsInitialized = true;
  Printf("in dstune::%s\n", __FUNCTION__);
}

int Finalize() {
  // FIXME: need to intercept exit and call this
  Printf("in dstune::%s\n", __FUNCTION__);
  return 0;
}

ALWAYS_INLINE USED
void MemoryAccess(uptr PC, uptr Addr, int SizeLog, bool IsWrite) {
  Printf("in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, 1 << SizeLog);
}

ALWAYS_INLINE USED
void UnalignedMemoryAccess(uptr PC, uptr Addr, int Size, bool IsWrite) {
  Printf("in dstune::%s %p: %c %p %d\n", __FUNCTION__, PC,
         IsWrite ? 'w' : 'r', Addr, Size);
}

}  // namespace __dstune
