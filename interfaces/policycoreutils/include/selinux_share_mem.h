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

#ifndef SELINUX_PARAM_H
#define SELINUX_PARAM_H

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif // __cplusplus

typedef struct SharedMem {
    uint8_t paramNameSize;
    uint8_t paramLabelSize;
    char data[0];
} SharedMem;

void *InitSharedMem(const char *fileName, uint32_t spaceSize, bool readOnly);
void WriteSharedMem(char *sharedMem, const char *data, uint32_t length);
char *ReadSharedMem(char *sharedMem, uint32_t length);
void UnmapSharedMem(char *sharedMem, uint32_t dataSize);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif // __cplusplus
#endif // SELINUX_PARAM_H
