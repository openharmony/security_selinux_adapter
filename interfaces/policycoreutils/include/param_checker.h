/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef PARAM_CHECKER_H
#define PARAM_CHECKER_H

#pragma once

#include <sys/socket.h>
#include "selinux_parameter.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

/**
 * @brief set selinux log, only be called by init
 */
void SetInitSelinuxLog(void);

/**
 * @brief for write particular paraName, check permission
 *
 * @param paraName the name of param
 * @param destContext the context of paraName
 * @param info contains sockfd, pid, uid, gid info
 * @return 0 for success, or an error code
 */
int SetParamCheck(const char *paraName, const char *destContext, const SrcInfo *info);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // PARAM_CHECKER_H
