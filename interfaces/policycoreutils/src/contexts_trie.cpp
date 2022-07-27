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

#include "contexts_trie.h"

#include <deque>
#include <new>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {
static const char *DEFAULT_CONTEXT = "u:object_r:default_param:s0";
} // namespace

static std::vector<std::string> StringSplit(std::string paraName, std::string split = ".")
{
    size_t pos;
    std::vector<std::string> result;
    while ((pos = paraName.find(split)) != std::string::npos) {
        std::string element = paraName.substr(0, pos);
        if (!element.empty()) {
            result.push_back(element);
        }
        paraName.erase(0, pos + split.length());
    }
    if (!paraName.empty()) {
        result.push_back(paraName);
    }
    return result;
}

static std::string GetFirstElement(std::string &paraName, std::string split = ".")
{
    size_t pos;
    if ((pos = paraName.find(split)) != std::string::npos) {
        std::string element = paraName.substr(0, pos);
        paraName.erase(0, pos + split.length());
        if (!element.empty()) {
            return element;
        }
    }
    std::string result = paraName;
    paraName = "";
    return result;
}

ParamContextsTrie *ParamContextsTrie::FindChild(std::string element)
{
    ParamContextsTrie *root = this;
    auto iter = root->childen.find(element);
    if (iter != root->childen.end()) {
        return iter->second;
    }
    return nullptr;
}

bool ParamContextsTrie::Insert(const std::string &paramPrefix, const std::string &contexts)
{
    ParamContextsTrie *root = this;
    std::vector<std::string> elements = StringSplit(paramPrefix);
    for (const auto &element : elements) {
        if (root->childen[element] == nullptr) {
            root->childen[element] = new (std::nothrow) ParamContextsTrie();
            if (root->childen[element] == nullptr) {
                return false;
            }
        }
        root = root->childen[element];
    }
    if (paramPrefix.back() == '.') {
        root->prefixLabel = strdup(contexts.c_str());
    } else {
        root->matchLabel = strdup(contexts.c_str());
    }
    return true;
}

const char *ParamContextsTrie::Search(const std::string &paraName)
{
    ParamContextsTrie *root = this;
    std::string tmpString = paraName;
    std::string element = GetFirstElement(tmpString);
    const char *updataCurLabel = nullptr;
    while (!element.empty()) {
        auto child = root->FindChild(element);
        if (child == nullptr) {
            if (root->prefixLabel) {
                return root->prefixLabel;
            } else if (updataCurLabel) {
                return updataCurLabel;
            } else {
                return DEFAULT_CONTEXT;
            }
        }
        if (root->prefixLabel)
            updataCurLabel = root->prefixLabel;
        root = child;
        element = GetFirstElement(tmpString);
    }

    if (root->matchLabel) {
        return root->matchLabel;
    } else if (updataCurLabel) {
        return updataCurLabel;
    } else {
        return DEFAULT_CONTEXT;
    }
}

void ParamContextsTrie::Clear()
{
    ParamContextsTrie *root = this;
    std::deque<ParamContextsTrie *> nodeDeque;
    for (auto child : root->childen) {
        nodeDeque.emplace_back(child.second);
    }
    while (!nodeDeque.empty()) {
        root = nodeDeque.front();
        nodeDeque.pop_front();
        if (root != nullptr) {
            if (root->prefixLabel) {
                free(root->prefixLabel);
            }
            if (root->matchLabel) {
                free(root->matchLabel);
            }
            for (auto child : root->childen) {
                nodeDeque.emplace_back(child.second);
            }
            delete root;
        }
    }
}
