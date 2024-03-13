// Copyright 2022 The Abseil Authors.
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

#include "absl_log_initialize.hpp"

#include "absl_base_config.hpp"
#include "absl_log_internal_globals.hpp"
#include "absl_time_time.hpp"

namespace absl {
ABSL_NAMESPACE_BEGIN

void InitializeLog() {
  // This comes first since it is used by RAW_LOG.
  absl::log_internal::SetTimeZone(absl::LocalTimeZone());

  // Note that initialization is complete, so logs can now be sent to their
  // proper destinations rather than stderr.
  log_internal::SetInitialized();
}

ABSL_NAMESPACE_END
}  // namespace absl

