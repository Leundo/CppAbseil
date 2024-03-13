//
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

#include "absl_log_log_entry.hpp"

#include "absl_base_config.hpp"

namespace absl {
ABSL_NAMESPACE_BEGIN

#ifdef ABSL_INTERNAL_NEED_REDUNDANT_CONSTEXPR_DECL
constexpr int LogEntry::kNoVerbosityLevel;
constexpr int LogEntry::kNoVerboseLevel;
#endif

ABSL_NAMESPACE_END
}  // namespace absl
