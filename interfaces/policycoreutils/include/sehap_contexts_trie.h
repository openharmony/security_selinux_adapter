/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SEHAP_CONTEXTS_TRIE_H
#define SEHAP_CONTEXTS_TRIE_H

#include <string>
#include <unordered_map>

typedef struct NodeTypeInfo {
    bool isEnd = false;
    std::string domain;
    std::string type;
} NodeTypeInfo;

class SehapContextsTrie {
public:
    SehapContextsTrie() {};
    ~SehapContextsTrie() {};

    bool Insert(const std::string &paraName, const std::string &domain, const std::string &type);
    std::string Search(const std::string &paraName, bool isDomain);
    void Clear();

    NodeTypeInfo prefixInfo;
    NodeTypeInfo matchedInfo;

private:
    std::vector<std::string> SplitString(const std::string &paraName);
    SehapContextsTrie* FindChild(const std::string &element);
    std::unordered_map<std::string, SehapContextsTrie *> children;
};
#endif // SEHAP_CONTEXTS_TRIE_H
