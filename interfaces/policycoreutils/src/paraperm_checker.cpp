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

#include "paraperm_checker.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <regex>
#include <securec.h>
#include <selinux_internal.h>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include "callbacks.h"
#include "selinux_error.h"
#include "selinux_klog.h"

using namespace Selinux;

namespace {
static const std::string PARAMETER_CONTEXTS_FILE = "/system/etc/selinux/targeted/contexts/parameter_contexts";
static const std::string TYPE_PREFIX = "u:object_r:";
static pthread_once_t FC_ONCE = PTHREAD_ONCE_INIT;
static std::unordered_map<std::string, struct ParameterInfo> paraInfo;
static const int CONTEXTS_LENGTH_MIN = 16; // sizeof("x u:object_r:x:s0")
} // namespace

struct AuditMsg {
    const ucred *ucred;
    const char *name;
};

static int SelinuxAuditCallback(void *data, security_class_t, char *buf, size_t len)
{
    if (data == nullptr || buf == nullptr) {
        return -1;
    }
    auto *msg = reinterpret_cast<AuditMsg *>(data);
    if (!msg || !msg->name || !msg->ucred) {
        selinux_log(SELINUX_ERROR, "Selinux audit msg invalid argument\n");
        return -1;
    }
    if (snprintf_s(buf, len, len - 1, "parameter=%s pid=%d uid=%d gid=%d", msg->name, msg->ucred->pid, msg->ucred->uid,
                   msg->ucred->gid) <= 0) {
        return -1;
    }
    return 0;
}

static void SelinuxSetCallback()
{
    union selinux_callback cb;
    cb.func_log = SelinuKLog;
    selinux_set_callback(SELINUX_CB_LOG, cb);
    cb.func_audit = SelinuxAuditCallback;
    selinux_set_callback(SELINUX_CB_AUDIT, cb);
}

static int CheckParaNameValid(const char *paraName)
{
    if (paraName == nullptr) {
        return -SELINUX_PTR_NULL;
    }
    std::string para = paraName;
    if (para.empty() || para[0] == '.' || para[para.size() - 1] == '.' || para.find("..") != std::string::npos) {
        return -SELINUX_ARG_INVALID;
    }
    std::regex paraReg("^[a-zA-Z0-9_\\-@:](([\\.]{0,1})[a-zA-Z0-9_\\-@:])*");
    if (std::regex_match(para, paraReg)) {
        return SELINUX_SUCC;
    }
    return -SELINUX_ARG_INVALID;
}

static bool CouldSkip(const std::string &line)
{
    if (line.size() < CONTEXTS_LENGTH_MIN) {
        return true;
    }
    int i = 0;
    while (isspace(line[i++]))
        ;
    if (line[i] == '#') {
        return true;
    }
    if (line.find(TYPE_PREFIX) == line.npos) {
        return true;
    }
    return false;
}

static bool StartWith(const std::string &dst, const std::string &prefix)
{
    return dst.compare(0, prefix.size(), prefix) == 0;
}

static struct ParameterInfo DecodeString(const std::string &line)
{
    std::stringstream input(line);
    struct ParameterInfo contextBuff = {"", ""};
    std::string name;
    if (input >> name) {
        contextBuff.paraName = name;
    }
    std::string context;
    if (input >> context) {
        if (StartWith(context, TYPE_PREFIX)) {
            contextBuff.paraContext = context;
        }
    }
    return contextBuff;
}

static bool ParameterContextsLoad()
{
    // load parameter_contexts file
    std::ifstream contextsFile(PARAMETER_CONTEXTS_FILE);
    if (contextsFile) {
        int lineNum = 0;
        std::string line;
        while (getline(contextsFile, line)) {
            lineNum++;
            if (CouldSkip(line))
                continue;
            struct ParameterInfo tmpContext = DecodeString(line);
            if (!tmpContext.paraContext.empty() && !tmpContext.paraName.empty()) {
                paraInfo.emplace(tmpContext.paraName, tmpContext);
            } else {
                selinux_log(SELINUX_ERROR, "parameter_contexts read fail in line %d\n", lineNum);
            }
        }
    } else {
        selinux_log(SELINUX_ERROR, "Load parameter_contexts fail, no such file: %s\n", PARAMETER_CONTEXTS_FILE.c_str());
        return false;
    }
    selinux_log(SELINUX_INFO, "Load parameter_contexts succes: %s\n", PARAMETER_CONTEXTS_FILE.c_str());
    contextsFile.close();
    return true;
}

static int CheckPerm(const std::string &paraName, const char *srcContext, const char *destContext, const ucred &uc)
{
    if (srcContext == nullptr || destContext == nullptr) {
        selinux_log(SELINUX_INFO, "context empty!\n");
        return -SELINUX_PTR_NULL;
    }
    selinux_log(SELINUX_INFO, "srcContext[%s] is setting param[%s] destContext[%s]\n", srcContext, paraName.c_str(),
                destContext);
    AuditMsg msg;
    msg.name = paraName.c_str();
    msg.ucred = &uc;
    int res = selinux_check_access(srcContext, destContext, "parameter_service", "set", &msg);
    return res == 0 ? SELINUX_SUCC : -SELINUX_PERMISSION_DENY;
}

void SetSelinuxLogCallback()
{
    __selinux_once(FC_ONCE, SelinuxSetCallback);
    return;
}

void DestroyParamList(ParameterInfoList **list)
{
    if (list == nullptr) {
        return;
    }
    ParameterInfoList *tmpNode;
    ParameterInfoList *listHead = *list;
    while (listHead != nullptr) {
        tmpNode = listHead->next;
        free(listHead->info.paraName);
        listHead->info.paraName = nullptr;
        free(listHead->info.paraContext);
        listHead->info.paraContext = nullptr;
        free(listHead);
        listHead = tmpNode;
    }
    *list = nullptr;
    return;
}

ParameterInfoList *GetParamList()
{
    // GetParamList for hash map
    ParameterInfoList *ptrParaInfo = nullptr;
    if (paraInfo.empty()) {
        if (!ParameterContextsLoad()) {
            return nullptr;
        }
    }

    ptrParaInfo = (ParameterInfoList *)malloc(sizeof(ParameterInfoList));
    if (ptrParaInfo == nullptr) {
        return nullptr;
    }
    ParameterInfoList *head = ptrParaInfo;
    for (auto info : paraInfo) {
        ParameterInfoList *node = (ParameterInfoList *)malloc(sizeof(ParameterInfoList));
        if (node == nullptr) {
            DestroyParamList(&ptrParaInfo);
            return nullptr;
        }
        struct ParameterNode contextBuff = {nullptr, nullptr};
        contextBuff.paraName = strdup(info.second.paraName.c_str());
        contextBuff.paraContext = strdup(info.second.paraContext.c_str());
        node->info = contextBuff;
        node->next = nullptr;
        head->next = node;
        head = head->next;
    }
    selinux_log(SELINUX_INFO, "Get contexts list for hash map succes\n");
    head = ptrParaInfo->next;
    free(ptrParaInfo);
    ptrParaInfo = nullptr;
    return head;
}

int GetParamLabel(const char *paraName, const char **context)
{
    if (paraName == nullptr || context == nullptr) {
        return -SELINUX_PTR_NULL;
    }

    int ret = CheckParaNameValid(paraName);
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "paraName invalid!\n");
        return ret;
    }

    if (paraInfo.empty()) {
        if (!ParameterContextsLoad()) {
            return -SELINUX_CONTEXTS_LOAD_ERR;
        }
    }
    std::string name(paraName);
    auto pos = name.find_last_of(".");
    while (pos != std::string::npos) {
        auto iter = paraInfo.find(name);
        if (iter != paraInfo.end()) {
            *context = iter->second.paraContext.c_str();
            selinux_log(SELINUX_INFO, "find context: %s\n", *context);
            return SELINUX_SUCC;
        }
        name = name.substr(0, pos + 1);
        pos = name.substr(0, pos).find_last_of(".");
    }
    auto iter = paraInfo.find(name);
    if (iter != paraInfo.end()) {
        *context = iter->second.paraContext.c_str();
        selinux_log(SELINUX_INFO, "find context: %s\n", *context);
        return SELINUX_SUCC;
    }
    return -SELINUX_KEY_NOT_FOUND;
}

int ReadParamCheck(const char *paraName)
{
    int ret = CheckParaNameValid(paraName);
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "paraName invalid!\n");
        return ret;
    }

    char *srcContext = nullptr;
    int rc = getcon(&srcContext);
    if (rc < 0) {
        selinux_log(SELINUX_ERROR, "getcon failed!\n");
        return -SELINUX_GETCON_ERR;
    }

    AuditMsg msg;
    msg.name = paraName;
    ucred uc = {.pid = getpid(), .uid = getuid(), .gid = getgid()};
    msg.ucred = &uc;
    const char *destContext = nullptr;
    if (GetParamLabel(paraName, &destContext) != 0) {
        destContext = "u:object_r:default_para:s0";
    }
    if (srcContext == nullptr || destContext == nullptr) {
        freecon(srcContext);
        return -SELINUX_PTR_NULL;
    }
    selinux_log(SELINUX_INFO, "srcContext[%s] is reading param[%s] destContext[%s]\n", srcContext, paraName,
                destContext);
    int res = selinux_check_access(srcContext, destContext, "file", "read", &msg);
    freecon(srcContext);
    return res == 0 ? SELINUX_SUCC : -SELINUX_PERMISSION_DENY;
}

int SetParamCheck(const char *paraName, struct ucred *uc)
{
    if (paraName == nullptr || uc == nullptr) {
        return -SELINUX_PTR_NULL;
    }

    int ret = CheckParaNameValid(paraName);
    if (ret != 0) {
        selinux_log(SELINUX_ERROR, "paraName invalid!\n");
        return ret;
    }

    char *srcContext = nullptr;

    int rc = getpidcon(uc->pid, &srcContext);
    if (rc < 0) {
        selinux_log(SELINUX_ERROR, "getpidcon failed!\n");
        return -SELINUX_GETCON_ERR;
    }
    const char *destContext = nullptr;
    if (GetParamLabel(paraName, &destContext) != 0) {
        destContext = "u:object_r:default_para:s0";
    }
    int res = CheckPerm(std::string(paraName), srcContext, destContext, *uc);
    freecon(srcContext);
    return res;
}
