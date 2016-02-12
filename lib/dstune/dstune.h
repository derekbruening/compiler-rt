//===-- dstune_rtl.h ----------------------------------------------*- C++ -*-===//
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
// Main internal dstune header file.
//
// Ground rules:
//   - C++ run-time should not be used (static CTORs, RTTI, exceptions, static
//     function-scope locals)
//   - All functions/classes/etc reside in namespace __dstune, except for those
//     declared in dstune_interface.h.
//   - Platform-specific files should be used instead of ifdefs (*).
//   - No system headers included in header files (*).
//   - Platform specific headres included only into platform-specific files (*).
//
//  (*) Except when inlining is critical for performance.
//===----------------------------------------------------------------------===//

#ifndef DSTUNE_H
#define DSTUNE_H

#include "sanitizer_common/sanitizer_common.h"

#define CALLERPC ((uptr)__builtin_return_address(0))

namespace __dstune {

extern bool DstuneIsInitialized;

const int kSizeLog1 = 0;
const int kSizeLog2 = 1;
const int kSizeLog4 = 2;
const int kSizeLog8 = 3;

void initializeLibrary();
int finalizeLibrary();
void processMemAccess(uptr PC, uptr Addr, int SizeLog, bool IsWrite);
void processUnalignedAccess(uptr PC, uptr Addr, int Size, bool IsWrite);
void processRangeAccess(uptr PC, uptr Addr, int Size, bool IsWrite);

void initializeInterceptors();

}  // namespace __dstune

#endif  // DSTUNE_H
