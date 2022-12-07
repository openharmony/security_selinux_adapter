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

#ifndef CONTEXTS_TRIE_H
#define CONTEXTS_TRIE_H

#pragma once

#include <stdbool.h>
#include "selinux_map.h"
#include "selinux_parameter.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif // __cplusplus

int LoadParameterContextsToSharedMem(void);
bool ReadParamFromSharedMem(ParamContextsTrie **trieRoot, ParamContextsList **listHead);
const char* SearchFromParamTrie(ParamContextsTrie *root, const char *paraName);
int GetLabelIndex(ParamContextsTrie *root, const char *paraName);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif // __cplusplus
#endif // CONTEXTS_TRIE_H
