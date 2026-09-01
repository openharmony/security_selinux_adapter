/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SECURITY_SELINUX_ADAPTER_PARSE_HAP_RESTORECON_INT_H
#define SECURITY_SELINUX_ADAPTER_PARSE_HAP_RESTORECON_INT_H

#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

namespace Selinux {
/*
 * Parse a whole-token decimal integer from hap_restorecon CLI text
 * (-R stop-reason, -t run-time, -r recurse flags).
 * Reject empty, overflow, leftover junk such as "200abc", signs, hex, and floats.
 */
inline bool ParseHapRestoreconInt(std::string_view text, int &out)
{
    if (text.empty()) {
        return false;
    }
    int value = 0;
    auto result = std::from_chars(text.data(), text.data() + text.size(), value, 10);
    if (result.ec != std::errc() || result.ptr != text.data() + text.size()) {
        return false;
    }
    out = value;
    return true;
}

inline bool ParseHapRestoreconInt(const char *text, int &out)
{
    if (text == nullptr) {
        return false;
    }
    return ParseHapRestoreconInt(std::string_view(text), out);
}

inline bool ParseHapRestoreconUInt(std::string_view text, unsigned int &out)
{
    if (text.empty()) {
        return false;
    }
    unsigned int value = 0;
    auto result = std::from_chars(text.data(), text.data() + text.size(), value, 10);
    if (result.ec != std::errc() || result.ptr != text.data() + text.size()) {
        return false;
    }
    out = value;
    return true;
}

inline bool ParseHapRestoreconUInt(const std::string &text, unsigned int &out)
{
    return ParseHapRestoreconUInt(std::string_view(text), out);
}
} // namespace Selinux
#endif // SECURITY_SELINUX_ADAPTER_PARSE_HAP_RESTORECON_INT_H
