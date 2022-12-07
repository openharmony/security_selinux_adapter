/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SELINUX_MAP
#define SELINUX_MAP

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif // __cplusplus

typedef struct HashNode {
    struct HashNode *next;
} HashNode;

typedef struct {
    HashNode *buckets[0];
} HashTab;

typedef struct {
    const char *prefixLabel;
    const char *matchLabel;
    uint32_t labeled;
    int32_t index;
    HashTab *handle;
} ParamContextsTrie;

#define PREFIX_LABELED (1)
#define MATCH_LABELED (2)
#define UNLABELED (0)

typedef struct ParamHashNode {
    HashNode hashNode;
    ParamContextsTrie *childPtr;
    uint32_t nameLen;
    char* name;
} ParamHashNode;

#define HASHMAP_ENTRY(ptr, type, member) ((type *)((char *)(ptr)-offsetof(type, member)))

int32_t HashMapCreate(HashTab **handle);
void HashMapDestroy(HashTab *handle);
int32_t HashMapAdd(HashTab *handle, HashNode *hashNode);
void HashMapRemove(HashTab *handle, const char *key);
HashNode *HashMapGet(HashTab *handle, const char *key, uint32_t len);
HashNode *HashMapFind(HashTab *handle, int hashCode, const char *key);
#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif // __cplusplus
#endif