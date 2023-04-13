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

#ifndef SELINUX_PARAMETER_H
#define SELINUX_PARAMETER_H

#pragma once

#include <sys/socket.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct ParameterNode {
    const char *paraName;
    const char *paraContext;
    int index;
} ParameterNode;

typedef struct ParamContextsList {
    struct ParameterNode info;
    struct ParamContextsList *next;
} ParamContextsList;

typedef struct SrcInfo {
    int sockFd;
    struct ucred uc;
} SrcInfo;

/**
 * @brief init param selinux
 *
 * @param isInit is init process
 */
int InitParamSelinux(int isInit);

/**
 * @brief get param context list, for context-named files generate
 * free with DestroyParamList
 *
 * @return head of param context list
 */
ParamContextsList *GetParamList(void);

/**
 * @brief destroy param list get from GetParamList
 *
 * @param list the head of contexts list
 */
void DestroyParamList(ParamContextsList **list);

/**
 * @brief for a particular paraName, get its context
 *
 * @param paraName the name of param
 *
 * @return context for given paraName
 */
const char *GetParamLabel(const char *paraName);
/**
 * @brief for a particular paraName, get its context index
 *
 * @param paraName the name of param
 *
 * @return context index for given paraName
 */
int GetParamLabelIndex(const char *paraName);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif // SELINUX_PARAMETER_H
