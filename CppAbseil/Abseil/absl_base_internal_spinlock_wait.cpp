// Copyright 2017 The Abseil Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The OS-specific header included below must provide two calls:
// AbslInternalSpinLockDelay() and AbslInternalSpinLockWake().
// See spinlock_wait.h for the specs.

#include <atomic>
#include <cstdint>

#include "absl_base_internal_spinlock_wait.hpp"

#if defined(_WIN32)

// MARK: - BEGIN absl_base_internal_spinlock_win32.inc
// Copyright 2017 The Abseil Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a Win32-specific part of spinlock_wait.cc

#include <windows.h>
#include <atomic>
#include <CppAbseil/absl_base_internal_scheduling_mode.hpp>

extern "C" {

void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockDelay)(
    std::atomic<uint32_t>* /* lock_word */, uint32_t /* value */, int loop,
    absl::base_internal::SchedulingMode /* mode */) {
  if (loop == 0) {
  } else if (loop == 1) {
    Sleep(0);
  } else {
    // SpinLockSuggestedDelayNS() always returns a positive integer, so this
    // static_cast is safe.
    Sleep(static_cast<DWORD>(
        absl::base_internal::SpinLockSuggestedDelayNS(loop) / 1000000));
  }
}

void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockWake)(
    std::atomic<uint32_t>* /* lock_word */, bool /* all */) {}

}  // extern "C"


// MARK: - END absl_base_internal_spinlock_win32.inc

#elif defined(__linux__)

// MARK: - BEGIN absl_base_internal_spinlock_linux.inc
// Copyright 2018 The Abseil Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a Linux-specific part of spinlock_wait.cc

#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <climits>
#include <cstdint>
#include <ctime>

#include <CppAbseil/absl_base_attributes.hpp>
#include <CppAbseil/absl_base_internal_errno_saver.hpp>

// The SpinLock lockword is `std::atomic<uint32_t>`. Here we assert that
// `std::atomic<uint32_t>` is bitwise equivalent of the `int` expected
// by SYS_futex. We also assume that reads/writes done to the lockword
// by SYS_futex have rational semantics with regard to the
// std::atomic<> API. C++ provides no guarantees of these assumptions,
// but they are believed to hold in practice.
static_assert(sizeof(std::atomic<uint32_t>) == sizeof(int),
              "SpinLock lockword has the wrong size for a futex");

// Some Android headers are missing these definitions even though they
// support these futex operations.
#ifdef __BIONIC__
#ifndef SYS_futex
#define SYS_futex __NR_futex
#endif
#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG 128
#endif
#endif

#if defined(__NR_futex_time64) && !defined(SYS_futex_time64)
#define SYS_futex_time64 __NR_futex_time64
#endif

#if defined(SYS_futex_time64) && !defined(SYS_futex)
#define SYS_futex SYS_futex_time64
#endif

extern "C" {

ABSL_ATTRIBUTE_WEAK void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockDelay)(
    std::atomic<uint32_t> *w, uint32_t value, int,
    absl::base_internal::SchedulingMode) {
  absl::base_internal::ErrnoSaver errno_saver;
  syscall(SYS_futex, w, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, value, nullptr);
}

ABSL_ATTRIBUTE_WEAK void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockWake)(
    std::atomic<uint32_t> *w, bool all) {
  syscall(SYS_futex, w, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, all ? INT_MAX : 1, 0);
}

}  // extern "C"


// MARK: - END absl_base_internal_spinlock_linux.inc

#elif defined(__akaros__)

// MARK: - BEGIN absl_base_internal_spinlock_akaros.inc
// Copyright 2017 The Abseil Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is an Akaros-specific part of spinlock_wait.cc

#include <atomic>

#include <CppAbseil/absl_base_internal_scheduling_mode.hpp>

extern "C" {

ABSL_ATTRIBUTE_WEAK void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockDelay)(
    std::atomic<uint32_t>* /* lock_word */, uint32_t /* value */,
    int /* loop */, absl::base_internal::SchedulingMode /* mode */) {
  // In Akaros, one must take care not to call anything that could cause a
  // malloc(), a blocking system call, or a uthread_yield() while holding a
  // spinlock. Our callers assume will not call into libraries or other
  // arbitrary code.
}

ABSL_ATTRIBUTE_WEAK void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockWake)(
    std::atomic<uint32_t>* /* lock_word */, bool /* all */) {}

}  // extern "C"


// MARK: - END absl_base_internal_spinlock_akaros.inc

#else

// MARK: - BEGIN absl_base_internal_spinlock_posix.inc
// Copyright 2017 The Abseil Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file is a Posix-specific part of spinlock_wait.cc

#include <sched.h>

#include <atomic>
#include <ctime>

#include <CppAbseil/absl_base_internal_errno_saver.hpp>
#include <CppAbseil/absl_base_internal_scheduling_mode.hpp>
#include <CppAbseil/absl_base_port.hpp>

extern "C" {

ABSL_ATTRIBUTE_WEAK void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockDelay)(
    std::atomic<uint32_t>* /* lock_word */, uint32_t /* value */, int loop,
    absl::base_internal::SchedulingMode /* mode */) {
  absl::base_internal::ErrnoSaver errno_saver;
  if (loop == 0) {
  } else if (loop == 1) {
    sched_yield();
  } else {
    struct timespec tm;
    tm.tv_sec = 0;
    tm.tv_nsec = absl::base_internal::SpinLockSuggestedDelayNS(loop);
    nanosleep(&tm, nullptr);
  }
}

ABSL_ATTRIBUTE_WEAK void ABSL_INTERNAL_C_SYMBOL(AbslInternalSpinLockWake)(
    std::atomic<uint32_t>* /* lock_word */, bool /* all */) {}

}  // extern "C"


// MARK: - END absl_base_internal_spinlock_posix.inc

#endif

namespace absl {
ABSL_NAMESPACE_BEGIN
namespace base_internal {

// See spinlock_wait.h for spec.
uint32_t SpinLockWait(std::atomic<uint32_t> *w, int n,
                      const SpinLockWaitTransition trans[],
                      base_internal::SchedulingMode scheduling_mode) {
  int loop = 0;
  for (;;) {
    uint32_t v = w->load(std::memory_order_acquire);
    int i;
    for (i = 0; i != n && v != trans[i].from; i++) {
    }
    if (i == n) {
      SpinLockDelay(w, v, ++loop, scheduling_mode);  // no matching transition
    } else if (trans[i].to == v ||                   // null transition
               w->compare_exchange_strong(v, trans[i].to,
                                          std::memory_order_acquire,
                                          std::memory_order_relaxed)) {
      if (trans[i].done) return v;
    }
  }
}

static std::atomic<uint64_t> delay_rand;

// Return a suggested delay in nanoseconds for iteration number "loop"
int SpinLockSuggestedDelayNS(int loop) {
  // Weak pseudo-random number generator to get some spread between threads
  // when many are spinning.
  uint64_t r = delay_rand.load(std::memory_order_relaxed);
  r = 0x5deece66dLL * r + 0xb;   // numbers from nrand48()
  delay_rand.store(r, std::memory_order_relaxed);

  if (loop < 0 || loop > 32) {   // limit loop to 0..32
    loop = 32;
  }
  const int kMinDelay = 128 << 10;  // 128us
  // Double delay every 8 iterations, up to 16x (2ms).
  int delay = kMinDelay << (loop / 8);
  // Randomize in delay..2*delay range, for resulting 128us..4ms range.
  return delay | ((delay - 1) & static_cast<int>(r));
}

}  // namespace base_internal
ABSL_NAMESPACE_END
}  // namespace absl

