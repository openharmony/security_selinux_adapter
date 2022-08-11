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
#include "selinux_map.h"
#include <stdlib.h>
#include <string.h>

static const int32_t g_maxBucket = 32;

static int GenerateHashCode(const char *key)
{
    int code = 0;
    for (size_t i = 0; i < strlen(key); i++) {
        code += key[i] - 'A';
    }
    return code;
}

static int GroupNodeNodeCompare(const HashNode *node1, const HashNode *node2)
{
    ParamHashNode *groupNode1 = HASHMAP_ENTRY(node1, ParamHashNode, hashNode);
    ParamHashNode *groupNode2 = HASHMAP_ENTRY(node2, ParamHashNode, hashNode);
    return strcmp(groupNode1->name, groupNode2->name);
}

static int GroupNodeKeyCompare(const HashNode *node1, const char *key)
{
    ParamHashNode *groupNode1 = HASHMAP_ENTRY(node1, ParamHashNode, hashNode);
    return strcmp(groupNode1->name, key);
}

static int GroupNodeGetKeyHashCode(const char *key)
{
    return GenerateHashCode(key);
}

static int GroupNodeGetNodeHashCode(const HashNode *node)
{
    ParamHashNode *groupNode = HASHMAP_ENTRY(node, ParamHashNode, hashNode);
    return GenerateHashCode(groupNode->name);
}

static void GroupNodeFree(const HashNode *node)
{
    ParamHashNode *groupNode = HASHMAP_ENTRY(node, ParamHashNode, hashNode);
    free(groupNode);
}

int32_t HashMapCreate(HashTab **handle)
{
    if (handle == NULL) {
        return -1;
    }

    HashTab *tab = (HashTab *)calloc(1, sizeof(HashTab) + sizeof(HashNode *) * g_maxBucket);
    if (tab == NULL) {
        return -1;
    }
    *handle = tab;
    return 0;
}

static HashNode *GetHashNodeByNode(HashNode *root, const HashNode *nodeKey)
{
    while (root != NULL) {
        int ret = GroupNodeNodeCompare(root, nodeKey);
        if (ret == 0) {
            return root;
        }
        root = root->next;
    }
    return NULL;
}

static HashNode *GetHashNodeByKey(HashNode *root, const char *key)
{
    while (root != NULL) {
        int ret = GroupNodeKeyCompare(root, key);
        if (ret == 0) {
            return root;
        }
        root = root->next;
    }
    return NULL;
}

int32_t HashMapAdd(HashTab *handle, HashNode *node)
{
    if (handle == NULL || !(node != NULL && node->next == NULL)) {
        return -1;
    }
    int hashCode = GroupNodeGetNodeHashCode(node);
    hashCode = (hashCode < 0) ? -hashCode : hashCode;
    hashCode = hashCode % g_maxBucket;

    // check key exist
    HashNode *tmp = GetHashNodeByNode(handle->buckets[hashCode], node);
    if (tmp != NULL) {
        return -1;
    }
    node->next = handle->buckets[hashCode];
    handle->buckets[hashCode] = node;
    return 0;
}

void HashMapRemove(HashTab *handle, const char *key)
{
    if (handle == NULL || key == NULL) {
        return;
    }
    int hashCode = GroupNodeGetKeyHashCode(key);
    hashCode = (hashCode < 0) ? -hashCode : hashCode;
    hashCode = hashCode % g_maxBucket;

    HashNode *node = handle->buckets[hashCode];
    HashNode *preNode = node;
    while (node != NULL) {
        int ret = GroupNodeKeyCompare(node, key);
        if (ret == 0) {
            if (node == handle->buckets[hashCode]) {
                handle->buckets[hashCode] = node->next;
            } else {
                preNode->next = node->next;
            }
            return;
        }
        preNode = node;
        node = node->next;
    }
}

HashNode *HashMapGet(HashTab *handle, const char *key)
{
    if (handle == NULL || key == NULL) {
        return NULL;
    }
    int hashCode = GroupNodeGetKeyHashCode(key);
    hashCode = (hashCode < 0) ? -hashCode : hashCode;
    hashCode = hashCode % g_maxBucket;

    return GetHashNodeByKey(handle->buckets[hashCode], key);
}

static void HashListFree(HashNode *root)
{
    if (root == NULL) {
        return;
    }
    HashNode *node = root;
    while (node != NULL) {
        HashNode *next = node->next;
        GroupNodeFree(node);
        node = next;
    }
}

void HashMapDestroy(HashTab *handle)
{
    if (handle == NULL) {
        return;
    }
    for (int i = 0; i < g_maxBucket; i++) {
        HashListFree(handle->buckets[i]);
    }
    free(handle);
}

HashNode *HashMapFind(HashTab *handle, int hashCode, const char *key)
{
    if (handle == NULL || key == NULL) {
        return NULL;
    }
    return GetHashNodeByKey(handle->buckets[hashCode], key);
}