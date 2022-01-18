/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef SELINUX_ERROE_H
#define SELINUX_ERROE_H

namespace Selinux {
enum Errno {
    SELINUX_SUCC,
    SELINUX_ARG_INVALID,
    SELINUX_TYPE_SET_ERR,
    SELINUX_TYPE_INVALID,
    SELINUX_KEY_NOT_FOUND,
    SELINUX_CONTEXTS_NOT_FOUND,
    SELINUX_CONTEXTS_LOAD_ERR,
    SELINUX_PTR_NULL,
    SELINUX_PATH_INVAILD,
    SELINUX_FILE_INVAILD,
    SELINUX_FILE_ERR,
    SELINUX_FTS_ELOOP,
    SELINUX_SETCON_ERR,
    SELINUX_GETCON_ERR,
};
} // namespace Selinux

#endif // SELINUX_ERROE_H
