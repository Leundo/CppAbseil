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

#include "absl_log_die_if_null.hpp"

#include "absl_base_config.hpp"
#include "absl_log_log.hpp"
#include "absl_strings_str_cat.hpp"

namespace absl {
ABSL_NAMESPACE_BEGIN
namespace log_internal {

void DieBecauseNull(const char* file, int line, const char* exprtext) {
  LOG(FATAL).AtLocation(file, line)
      << absl::StrCat("Check failed: '", exprtext, "' Must be non-null");
}

}  // namespace log_internal
ABSL_NAMESPACE_END
}  // namespace absl

