//===-- cfsan_rtl.cc -------------------------------------------------------===//
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
// Interception routines for the cfsan run-time.
//===----------------------------------------------------------------------===//

#include "cfsan.h"
#include "cfsan_shadow.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "sanitizer_common/sanitizer_stacktrace.h"
#include "interception/interception.h"
#include <errno.h>

using namespace __cfsan;  // NOLINT

#define CUR_PC() (StackTrace::GetCurrentPc())

const int MAP_FIXED = 0x10; // from /usr/include/sys/mman.h

//===----------------------------------------------------------------------===//
// Interception via sanitizer common interceptors
//===----------------------------------------------------------------------===//

// Get the per-platform defines for what is possible to intercept
#include "sanitizer_common/sanitizer_platform_interceptors.h"

// TODO(bruening): tsan disables several interceptors (getpwent, etc.) claiming
// that interception is a perf hit: should we do the same?

// We have no need to intercept:
#undef SANITIZER_INTERCEPT_TLS_GET_ADDR

// TODO(bruening): the common realpath interceptor assumes malloc is
// intercepted!  We should try to parametrize that, though we'll
// intercept malloc soon ourselves and can then remove this undef.
#undef SANITIZER_INTERCEPT_REALPATH

#define COMMON_INTERCEPTOR_NOTHING_IS_INITIALIZED \
  (!CfsanIsInitialized)

#define COMMON_INTERCEPT_FUNCTION(name) INTERCEPT_FUNCTION(name)

#define COMMON_INTERCEPTOR_ENTER(ctx, func, ...)                   \
  do {                                                             \
    if (UNLIKELY(!COMMON_INTERCEPTOR_NOTHING_IS_INITIALIZED)) {    \
      return REAL(func)(__VA_ARGS__);                              \
    }                                                              \
    (void)ctx;                                                     \
  } while (false)

#define COMMON_INTERCEPTOR_ENTER_NOIGNORE(ctx, func, ...)          \
  COMMON_INTERCEPTOR_ENTER(ctx, func, __VA_ARGS__)

#define COMMON_INTERCEPTOR_WRITE_RANGE(ctx, ptr, size)             \
  processRangeAccess(CUR_PC(), (uptr)ptr, size, true)

#define COMMON_INTERCEPTOR_READ_RANGE(ctx, ptr, size)              \
  processRangeAccess(CUR_PC(), (uptr)ptr, size, false)

// This is only called if the app explicitly calls exit(), not on
// a normal exit.
#define COMMON_INTERCEPTOR_ON_EXIT(ctx)         \
  finalizeLibrary()

#define COMMON_INTERCEPTOR_FILE_OPEN(ctx, file, path) {}
#define COMMON_INTERCEPTOR_FILE_CLOSE(ctx, file) {}
#define COMMON_INTERCEPTOR_LIBRARY_LOADED(filename, handle) {}
#define COMMON_INTERCEPTOR_LIBRARY_UNLOADED() {}
#define COMMON_INTERCEPTOR_ACQUIRE(ctx, u) {}
#define COMMON_INTERCEPTOR_RELEASE(ctx, u) {}
#define COMMON_INTERCEPTOR_DIR_ACQUIRE(ctx, path) {}
#define COMMON_INTERCEPTOR_FD_ACQUIRE(ctx, fd) {}
#define COMMON_INTERCEPTOR_FD_RELEASE(ctx, fd) {}
#define COMMON_INTERCEPTOR_FD_ACCESS(ctx, fd) {}
#define COMMON_INTERCEPTOR_FD_SOCKET_ACCEPT(ctx, fd, newfd) {}
#define COMMON_INTERCEPTOR_SET_THREAD_NAME(ctx, name) {}
#define COMMON_INTERCEPTOR_SET_PTHREAD_NAME(ctx, thread, name) {}
#define COMMON_INTERCEPTOR_BLOCK_REAL(name) REAL(name)
#define COMMON_INTERCEPTOR_MUTEX_LOCK(ctx, m) {}
#define COMMON_INTERCEPTOR_MUTEX_UNLOCK(ctx, m) {}
#define COMMON_INTERCEPTOR_MUTEX_REPAIR(ctx, m) {}
#define COMMON_INTERCEPTOR_HANDLE_RECVMSG(ctx, msg) {}
#define COMMON_INTERCEPTOR_USER_CALLBACK_START() {}
#define COMMON_INTERCEPTOR_USER_CALLBACK_END() {}

#include "sanitizer_common/sanitizer_common_interceptors.inc"

//===----------------------------------------------------------------------===//
// Syscall interception
//===----------------------------------------------------------------------===//

// We want the caller's PC b/c unlike the other function interceptors these
// are separate pre and post functions called around the app's syscall().

#define COMMON_SYSCALL_PRE_READ_RANGE(ptr, size) \
  processRangeAccess(CALLERPC, (uptr)ptr, size, false)

#define COMMON_SYSCALL_PRE_WRITE_RANGE(ptr, size) {}

#define COMMON_SYSCALL_POST_READ_RANGE(ptr, size) {}

// The actual amount written is in post, not pre.
#define COMMON_SYSCALL_POST_WRITE_RANGE(ptr, size) \
  processRangeAccess(CALLERPC, (uptr)ptr, size, true)

#define COMMON_SYSCALL_ACQUIRE(addr) {}
#define COMMON_SYSCALL_RELEASE(addr) { (void)addr; }
#define COMMON_SYSCALL_FD_CLOSE(fd)  {}
#define COMMON_SYSCALL_FD_ACQUIRE(fd) {}
#define COMMON_SYSCALL_FD_RELEASE(fd) {}
#define COMMON_SYSCALL_PRE_FORK() {}
#define COMMON_SYSCALL_POST_FORK(res) {}

#include "sanitizer_common/sanitizer_common_syscalls.inc"

//===----------------------------------------------------------------------===//
// Custom interceptors
//===----------------------------------------------------------------------===//

// TODO(bruening): move more of these to the common interception pool as they
// are shared with tsan and asan.
// While our other files match LLVM style, here we match sanitizer style as we
// expect to move these to the common pool.

INTERCEPTOR(char*, strcpy, char *dst, const char *src) {  // NOLINT
  uptr srclen = internal_strlen(src);
  processRangeAccess(CUR_PC(), (uptr)dst, srclen + 1, true);
  processRangeAccess(CUR_PC(), (uptr)src, srclen + 1, false);
  return REAL(strcpy)(dst, src);  // NOLINT
}

INTERCEPTOR(char*, strncpy, char *dst, char *src, uptr n) {
  uptr srclen = internal_strnlen(src, n);
  processRangeAccess(CUR_PC(), (uptr)dst, n, true);
  processRangeAccess(CUR_PC(), (uptr)src,
                    srclen + 1 > n ? n : srclen + 1, false);
  return REAL(strncpy)(dst, src, n);
}

#if SANITIZER_LINUX && !SANITIZER_ANDROID
INTERCEPTOR(int, __xstat, int version, const char *path, void *buf) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(__xstat)(version, path, buf);
}
# define CFSAN_MAYBE_INTERCEPT___XSTAT INTERCEPT_FUNCTION(__xstat)
#else
# define CFSAN_MAYBE_INTERCEPT___XSTAT
#endif

INTERCEPTOR(int, stat, const char *path, void *buf) {
#if SANITIZER_FREEBSD || SANITIZER_MAC || SANITIZER_ANDROID
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(stat)(path, buf);
#else
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(__xstat)(0, path, buf);
#endif
}

#if SANITIZER_LINUX && !SANITIZER_ANDROID
INTERCEPTOR(int, __xstat64, int version, const char *path, void *buf) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(__xstat64)(version, path, buf);
}
# define CFSAN_MAYBE_INTERCEPT___XSTAT64 INTERCEPT_FUNCTION(__xstat64)
#else
# define CFSAN_MAYBE_INTERCEPT___XSTAT64
#endif

#if SANITIZER_LINUX && !SANITIZER_ANDROID
INTERCEPTOR(int, stat64, const char *path, void *buf) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(__xstat64)(0, path, buf);
}
# define CFSAN_MAYBE_INTERCEPT_STAT64 INTERCEPT_FUNCTION(stat64)
#else
# define CFSAN_MAYBE_INTERCEPT_STAT64
#endif

#if SANITIZER_LINUX && !SANITIZER_ANDROID
INTERCEPTOR(int, __lxstat, int version, const char *path, void *buf) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(__lxstat)(version, path, buf);
}
# define CFSAN_MAYBE_INTERCEPT___LXSTAT INTERCEPT_FUNCTION(__lxstat)
#else
# define CFSAN_MAYBE_INTERCEPT___LXSTAT
#endif

INTERCEPTOR(int, lstat, const char *path, void *buf) {
#if SANITIZER_FREEBSD || SANITIZER_MAC || SANITIZER_ANDROID
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(lstat)(path, buf);
#else
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(__lxstat)(0, path, buf);
#endif
}

#if SANITIZER_LINUX && !SANITIZER_ANDROID
INTERCEPTOR(int, __lxstat64, int version, const char *path, void *buf) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(__lxstat64)(version, path, buf);
}
# define CFSAN_MAYBE_INTERCEPT___LXSTAT64 INTERCEPT_FUNCTION(__lxstat64)
#else
# define CFSAN_MAYBE_INTERCEPT___LXSTAT64
#endif

#if SANITIZER_LINUX && !SANITIZER_ANDROID
INTERCEPTOR(int, lstat64, const char *path, void *buf) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(__lxstat64)(0, path, buf);
}
# define CFSAN_MAYBE_INTERCEPT_LSTAT64 INTERCEPT_FUNCTION(lstat64)
#else
# define CFSAN_MAYBE_INTERCEPT_LSTAT64
#endif

INTERCEPTOR(int, open, const char *name, int flags, int mode) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), name, 0);
  return REAL(open)(name, flags, mode);
}

#if SANITIZER_LINUX
INTERCEPTOR(int, open64, const char *name, int flags, int mode) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), name, 0);
  return REAL(open64)(name, flags, mode);
}
# define CFSAN_MAYBE_INTERCEPT_OPEN64 INTERCEPT_FUNCTION(open64)
#else
# define CFSAN_MAYBE_INTERCEPT_OPEN64
#endif

INTERCEPTOR(int, creat, const char *name, int mode) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), name, 0);
  return REAL(creat)(name, mode);
}

#if SANITIZER_LINUX
INTERCEPTOR(int, creat64, const char *name, int mode) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), name, 0);
  return REAL(creat64)(name, mode);
}
# define CFSAN_MAYBE_INTERCEPT_CREAT64 INTERCEPT_FUNCTION(creat64)
#else
# define CFSAN_MAYBE_INTERCEPT_CREAT64
#endif

INTERCEPTOR(int, unlink, char *path) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(unlink)(path);
}

INTERCEPTOR(uptr, fread, void *ptr, uptr size, uptr nmemb, void *f) {
  processRangeAccess(CUR_PC(), (uptr)ptr, size * nmemb, true);
  return REAL(fread)(ptr, size, nmemb, f);
}

INTERCEPTOR(uptr, fwrite, const void *p, uptr size, uptr nmemb, void *f) {
  processRangeAccess(CUR_PC(), (uptr)p, size * nmemb, false);
  return REAL(fwrite)(p, size, nmemb, f);
}

INTERCEPTOR(int, puts, const char *s) {
  processRangeAccess(CUR_PC(), (uptr)s, internal_strlen(s), false);
  return REAL(puts)(s);
}

INTERCEPTOR(int, rmdir, char *path) {
  COMMON_INTERCEPTOR_READ_STRING(CUR_PC(), path, 0);
  return REAL(rmdir)(path);
}

// TODO(bruening): share with all sanitizers
static bool fix_mmap_addr(void **addr, SIZE_T sz, int flags) {
  if (*addr) {
    if (!isAppMem((uptr)*addr) || !isAppMem((uptr)*addr + sz - 1)) {
      if (flags & MAP_FIXED) {
        errno = EINVAL;
        return false;
      } else {
        *addr = 0;
      }
    }
  }
  return true;
}

INTERCEPTOR(void *, mmap, void *addr, SIZE_T sz, int prot, int flags,
                 int fd, OFF_T off) {
  if (!fix_mmap_addr(&addr, sz, flags))
    return (void *)-1;
  return REAL(mmap)(addr, sz, prot, flags, fd, off);
}

#if SANITIZER_LINUX
INTERCEPTOR(void *, mmap64, void *addr, SIZE_T sz, int prot, int flags,
                 int fd, OFF64_T off) {
  if (!fix_mmap_addr(&addr, sz, flags))
    return (void *)-1;
  return REAL(mmap64)(addr, sz, prot, flags, fd, off);
}
# define CFSAN_MAYBE_INTERCEPT_MMAP64 INTERCEPT_FUNCTION(mmap64)
#else
# define CFSAN_MAYBE_INTERCEPT_MMAP64
#endif

// See comment below.
extern "C" {
  extern void __cxa_atexit(void (*function)(void));
}

namespace __cfsan {

void initializeInterceptors() {
  InitializeCommonInterceptors();

  INTERCEPT_FUNCTION(strcpy);  // NOLINT
  INTERCEPT_FUNCTION(strncpy);

  INTERCEPT_FUNCTION(stat);
  CFSAN_MAYBE_INTERCEPT___XSTAT;
  CFSAN_MAYBE_INTERCEPT_STAT64;
  CFSAN_MAYBE_INTERCEPT___XSTAT64;
  INTERCEPT_FUNCTION(lstat);
  CFSAN_MAYBE_INTERCEPT___LXSTAT;
  CFSAN_MAYBE_INTERCEPT_LSTAT64;
  CFSAN_MAYBE_INTERCEPT___LXSTAT64;
  INTERCEPT_FUNCTION(open);
  CFSAN_MAYBE_INTERCEPT_OPEN64;
  INTERCEPT_FUNCTION(creat);
  CFSAN_MAYBE_INTERCEPT_CREAT64;
  INTERCEPT_FUNCTION(unlink);
  INTERCEPT_FUNCTION(fread);
  INTERCEPT_FUNCTION(fwrite);
  INTERCEPT_FUNCTION(puts);
  INTERCEPT_FUNCTION(rmdir);

  INTERCEPT_FUNCTION(mmap);
  CFSAN_MAYBE_INTERCEPT_MMAP64;

  // Intercepting _exit or exit via COMMON_INTERCEPTOR_ON_EXIT only
  // finalizes on an explicit exit call by the app.  To handle a normal
  // exit we register an atexit handler.
  ::__cxa_atexit((void (*)())finalizeLibrary);

  // TODO(bruening): we should intercept calloc() and other memory allocation
  // routines that zero memory and update our shadow memory appropriately.

  // TODO(bruening): intercept routines that other sanitizers intercept that
  // are not in the common pool or here yet, ideally by adding to the common
  // pool.  E.g., wcslen, bcopy.
  
  // TODO(bruening): there are many more libc routines that read or write data
  // structures that no sanitizer is intercepting: sigaction, strtol, etc.
}

} // namespace __cfsan
