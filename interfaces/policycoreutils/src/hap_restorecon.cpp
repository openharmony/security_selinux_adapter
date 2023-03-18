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

#include "hap_restorecon.h"

#include <cctype>
#include <cerrno>
#include <climits>
#include <clocale>
#include <cstdlib>
#include <fstream>
#include <istream>
#include <regex>
#include <sstream>
#include <streambuf>
#include <string>
#include <sys/stat.h>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <include/fts.h>
#include <pthread.h>
#include "selinux/context.h"
#include "selinux/selinux.h"

#include "callbacks.h"
#include <selinux_internal.h>
#include "selinux_error.h"
#include "selinux_log.h"

using namespace Selinux;

namespace {
static const std::string SEHAP_CONTEXTS_FILE = "/system/etc/selinux/targeted/contexts/sehap_contexts";
static const std::string APL_PREFIX = "apl=";
static const std::string NAME_PREFIX = "name=";
static const std::string DOMAIN_PREFIX = "domain=";
static const std::string TYPE_PREFIX = "type=";
static const char *DEFAULT_CONTEXT = "u:object_r:unlabeled:s0";
static const int CONTEXTS_LENGTH_MIN = 20; // sizeof("apl=x domain= type=")
static const int CONTEXTS_LENGTH_MAX = 1024;
static pthread_once_t FC_ONCE = PTHREAD_ONCE_INIT;
static std::unordered_map<std::string, struct SehapInfo> sehapContextsBuff;
} // namespace

static void SelinuxSetCallback()
{
    SetSelinuxHilogLevel(SELINUX_HILOG_ERROR);
    union selinux_callback cb;
    cb.func_log = SelinuxHilog;
    selinux_set_callback(SELINUX_CB_LOG, cb);
}

static bool CouldSkip(const std::string &line)
{
    if (line.size() <= CONTEXTS_LENGTH_MIN || line.size() > CONTEXTS_LENGTH_MAX) {
        return true;
    }
    int i = 0;
    while (isspace(line[i])) {
        i++;
    }
    if (line[i] == '#') {
        return true;
    }
    if (line.find(APL_PREFIX) == line.npos) {
        return true;
    }
    return false;
}

static struct SehapInfo DecodeString(std::string &line)
{
    std::stringstream input(line);
    std::string tmp;
    struct SehapInfo contextBuff;
    bool aplVisit = false;
    bool nameVisit = false;
    bool domainVisit = false;
    bool typeVisit = false;

    while (input >> tmp) {
        if (!aplVisit && (tmp.find(APL_PREFIX) != tmp.npos)) {
            contextBuff.apl = tmp.substr(tmp.find(APL_PREFIX) + APL_PREFIX.size());
            aplVisit = true;
        } else if (!nameVisit && (tmp.find(NAME_PREFIX) != tmp.npos)) {
            contextBuff.name = tmp.substr(tmp.find(NAME_PREFIX) + NAME_PREFIX.size());
            nameVisit = true;
        } else if (!domainVisit && (tmp.find(DOMAIN_PREFIX) != tmp.npos)) {
            contextBuff.domain = tmp.substr(tmp.find(DOMAIN_PREFIX) + DOMAIN_PREFIX.size());
            domainVisit = true;
        } else if (!typeVisit && (tmp.find(TYPE_PREFIX) != tmp.npos)) {
            contextBuff.type = tmp.substr(tmp.find(TYPE_PREFIX) + TYPE_PREFIX.size());
            typeVisit = true;
        }
    }

    return contextBuff;
}

static bool CheckPath(const std::string &path)
{
    std::regex pathPrefix1("^/data/app/el[1-4]/[0-9]+/(base|database)/.*");
    std::regex pathPrefix2("^/data/accounts/account_0/appdata/.*");
    if (std::regex_match(path, pathPrefix1) || std::regex_match(path, pathPrefix2)) {
        return true;
    }
    return false;
}

static bool CheckApl(const std::string &apl)
{
    if (apl == "system_core" || apl == "system_basic" || apl == "normal") {
        return true;
    }
    return false;
}

static void HapContextsClear()
{
    if (!sehapContextsBuff.empty()) {
        sehapContextsBuff.clear();
    }
}

static bool HapContextsLoad()
{
    // load sehap_contexts file
    std::ifstream contextsFile(SEHAP_CONTEXTS_FILE);
    if (contextsFile) {
        HapContextsClear();
        int lineNum = 0;
        std::string line;
        while (getline(contextsFile, line)) {
            lineNum++;
            if (CouldSkip(line)) {
                continue;
            }
            struct SehapInfo tmpInfo = DecodeString(line);
            if (!tmpInfo.apl.empty()) {
                sehapContextsBuff.emplace(tmpInfo.apl + tmpInfo.name, tmpInfo);
            } else {
                selinux_log(SELINUX_INFO, "hap_contexts read fail in line %d\n", lineNum);
            }
        }
    } else {
        selinux_log(SELINUX_ERROR, "Load hap_contexts fail, no such file: %s\n", SEHAP_CONTEXTS_FILE.c_str());
        return false;
    }
    selinux_log(SELINUX_INFO, "Load hap_contexts succes: %s\n", SEHAP_CONTEXTS_FILE.c_str());
    contextsFile.close();
    return true;
}

HapContext::HapContext()
{
    __selinux_once(FC_ONCE, SelinuxSetCallback);
}

HapContext::~HapContext() {}

int HapContext::TypeSet(std::unordered_map<std::string, SehapInfo>::iterator &iter, bool isDomain, context_t con)
{
    std::string type = "";
    if (isDomain) {
        type = iter->second.domain;
    } else {
        type = iter->second.type;
    }
    if (type.size() == 0) {
        selinux_log(SELINUX_ERROR, "type is empty in contexts file");
        return -SELINUX_ARG_INVALID;
    }
    if (context_type_set(con, type.c_str())) {
        selinux_log(SELINUX_ERROR, "%s %s\n", GetErrStr(SELINUX_SET_CONTEXT_TYPE_ERROR), type.c_str());
        return -SELINUX_SET_CONTEXT_TYPE_ERROR;
    }
    return SELINUX_SUCC;
}

int HapContext::HapContextsLookup(bool isDomain, const std::string &apl, const std::string &packageName, context_t con)
{
    if (sehapContextsBuff.empty()) {
        if (!HapContextsLoad()) {
            return -SELINUX_CONTEXTS_FILE_LOAD_ERROR;
        }
    }

    auto iter = sehapContextsBuff.find(std::string(apl) + std::string(packageName));
    if (iter != sehapContextsBuff.end()) {
        return TypeSet(iter, isDomain, con);
    } else {
        iter = sehapContextsBuff.find(std::string(apl));
        if (iter != sehapContextsBuff.end()) {
            return TypeSet(iter, isDomain, con);
        }
    }
    return -SELINUX_KEY_NOT_FOUND;
}

int HapContext::HapLabelLookup(const std::string &apl, const std::string &packageName, char **secontextPtr)
{
    if (apl.empty()) {
        return -SELINUX_ARG_INVALID;
    }
    *secontextPtr = strdup(DEFAULT_CONTEXT);
    char *secontext = *secontextPtr;
    context_t con = context_new(secontext);
    if (con == nullptr) {
        return -SELINUX_PTR_NULL;
    }

    int res = HapContextsLookup(false, apl, packageName, con);
    if (res < 0) {
        context_free(con);
        return res;
    }

    secontext = context_str(con);
    if (secontext == nullptr) {
        context_free(con);
        return -SELINUX_PTR_NULL;
    }

    // if new contexts is same as old
    if (!strcmp(secontext, *secontextPtr)) {
        context_free(con);
        return SELINUX_SUCC;
    }

    // check whether the context is valid
    if (security_check_context(secontext) < 0) {
        context_free(con);
        selinux_log(SELINUX_ERROR, "context: %s, %s\n", secontext, GetErrStr(SELINUX_CHECK_CONTEXT_ERROR));
        return -SELINUX_CHECK_CONTEXT_ERROR;
    }

    freecon(*secontextPtr);
    *secontextPtr = strdup(secontext);
    if (!(*secontextPtr)) {
        context_free(con);
        return -SELINUX_PTR_NULL;
    }

    context_free(con);
    return SELINUX_SUCC;
}

int HapContext::RestoreconSb(const std::string &pathname, const struct stat *sb, const std::string &apl,
                             const std::string &packageName)
{
    char *secontext = nullptr;
    char *oldSecontext = nullptr;

    if (lgetfilecon(pathname.c_str(), &oldSecontext) < 0) {
        freecon(secontext);
        freecon(oldSecontext);
        return -SELINUX_GET_CONTEXT_ERROR;
    }

    int res = HapLabelLookup(apl, packageName, &secontext);
    if (res < 0) {
        freecon(secontext);
        freecon(oldSecontext);
        return res;
    }

    if (strcmp(oldSecontext, secontext)) {
        if (lsetfilecon(pathname.c_str(), secontext) < 0) {
            freecon(secontext);
            freecon(oldSecontext);
            return -SELINUX_SET_CONTEXT_ERROR;
        }
    }

    freecon(secontext);
    freecon(oldSecontext);
    return SELINUX_SUCC;
}

int HapContext::HapFileRestorecon(std::vector<std::string> &pathNameOrig, const std::string &apl,
                                  const std::string &packageName, unsigned int flags)
{
    if (apl.empty() || pathNameOrig.empty() || !CheckApl(apl)) {
        return -SELINUX_ARG_INVALID;
    }
    bool failFlag = false;
    for (auto pathname : pathNameOrig) {
        int res = HapFileRestorecon(pathname.c_str(), apl, packageName, flags);
        if (res != SELINUX_SUCC) {
            failFlag = true;
            selinux_log(SELINUX_ERROR, "HapFileRestorecon fail for path: %s, errorNo: %d", pathname.c_str(), res);
        }
    }
    return failFlag ? -SELINUX_RESTORECON_ERROR : SELINUX_SUCC;
}

int HapContext::HapFileRestorecon(const std::string &pathNameOrig, const std::string &apl,
                                  const std::string &packageName, unsigned int flags)
{
    if (apl.empty() || pathNameOrig.empty() || !CheckApl(apl)) {
        return -SELINUX_ARG_INVALID;
    }
    if (is_selinux_enabled() < 1) {
        selinux_log(SELINUX_INFO, "Selinux not enbaled");
        return SELINUX_SUCC;
    }

    struct stat sb;
    char realPath[PATH_MAX];
    if (realpath(pathNameOrig.c_str(), realPath) == nullptr) {
        return -SELINUX_PATH_INVAILD;
    }

    if (!CheckPath(std::string(realPath))) {
        return -SELINUX_PATH_INVAILD;
    }

    bool recurse = (flags & SELINUX_HAP_RESTORECON_RECURSE) ? true : false;
    if (!recurse) {
        if (lstat(realPath, &sb) < 0) {
            return -SELINUX_STAT_INVAILD;
        }

        int res = RestoreconSb(realPath, &sb, apl, packageName);
        if (res < 0) {
            selinux_log(SELINUX_ERROR, "RestoreconSb failed");
        }
        return res;
    }

    char *paths[2] = {NULL, NULL};
    paths[0] = static_cast<char *>(realPath);
    int ftsFlags = FTS_PHYSICAL | FTS_NOCHDIR;
    FTS *fts = fts_open(paths, ftsFlags, NULL);
    if (fts == nullptr) {
        selinux_log(SELINUX_ERROR, "%s on %s: %s\n", GetErrStr(SELINUX_FTS_OPEN_ERROR), paths[0], strerror(errno));
        return -SELINUX_FTS_OPEN_ERROR;
    }

    FTSENT *ftsent = nullptr;
    int error = 0;
    while ((ftsent = fts_read(fts)) != NULL) {
        switch (ftsent->fts_info) {
            case FTS_DC:
                selinux_log(SELINUX_ERROR, "%s on %s\n", GetErrStr(SELINUX_FTS_ELOOP), ftsent->fts_path);
                (void)fts_close(fts);
                return -SELINUX_FTS_ELOOP;
            case FTS_DP:
                continue;
            case FTS_DNR:
                selinux_log(SELINUX_ERROR, "Read error on %s, errorno: %s\n", ftsent->fts_path, strerror(errno));
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_ERR:
                selinux_log(SELINUX_ERROR, "Error on %s, errorno: %s\n", ftsent->fts_path, strerror(errno));
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_NS:
                selinux_log(SELINUX_ERROR, "stat error on %s, errorno: %s\n", ftsent->fts_path, strerror(errno));
                fts_set(fts, ftsent, FTS_SKIP);
                continue;
            case FTS_D:
            default:
                error += RestoreconSb(ftsent->fts_path, ftsent->fts_statp, apl, packageName);
                break;
        }
    }
    (void)fts_close(fts);
    return error;
}

int HapContext::HapDomainSetcontext(const std::string &apl, const std::string &packageName)
{
    if (apl.empty() || !CheckApl(apl)) {
        return -SELINUX_ARG_INVALID;
    }

    if (is_selinux_enabled() < 1) {
        selinux_log(SELINUX_INFO, "Selinux not enbaled");
        return SELINUX_SUCC;
    }

    char *typeContext = nullptr;
    if (getcon(&typeContext)) {
        return -SELINUX_GET_CONTEXT_ERROR;
    }

    context_t con = nullptr;
    con = context_new(typeContext);
    if (con == nullptr) {
        return -SELINUX_PTR_NULL;
    }
    char *oldTypeContext = typeContext;

    int res = HapContextsLookup(true, apl, packageName, con);
    if (res < 0) {
        freecon(oldTypeContext);
        context_free(con);
        return res;
    }

    typeContext = context_str(con);
    if (typeContext == nullptr) {
        freecon(oldTypeContext);
        context_free(con);
        return -SELINUX_PTR_NULL;
    }

    selinux_log(SELINUX_INFO, "Hap type for %s is changing from %s to %s\n", packageName.c_str(), oldTypeContext,
                typeContext);

    if (security_check_context(typeContext) < 0) {
        freecon(oldTypeContext);
        context_free(con);
        selinux_log(SELINUX_ERROR, "context: %s, %s\n", typeContext, GetErrStr(SELINUX_CHECK_CONTEXT_ERROR));
        return -SELINUX_CHECK_CONTEXT_ERROR;
    }

    if (strcmp(typeContext, oldTypeContext)) {
        if (setcon(typeContext) < 0) {
            freecon(oldTypeContext);
            context_free(con);
            return -SELINUX_SET_CONTEXT_ERROR;
        }
    }
    selinux_log(SELINUX_INFO, "Hap setcon finish for %s\n", packageName.c_str());

    freecon(oldTypeContext);
    context_free(con);
    return SELINUX_SUCC;
}
