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

#include <unistd.h>
#include "src/callbacks.h"
#include "src/label_internal.h"
#include "policycoreutils.h"
#include "selinux/restorecon.h"

static pthread_once_t g_fcOnce = PTHREAD_ONCE_INIT;
static struct selabel_handle *g_fcHandle = NULL;
static const char SYSTEM_FILE_CONTEXTS[] = "/system/etc/selinux/targeted/contexts/file_contexts";
static const char VENDOR_FILE_CONTEXTS[] = "/vendor/etc/selinux/targeted/contexts/file_contexts";
#define MAX_OPT_NUM 3 // system + vendor + digest

typedef struct selinux_opt SelinuxOptions;

static void SetFileContextsHandle(void)
{
    if (g_fcHandle != NULL) {
        selinux_log(SELINUX_ERROR, "File_contexts handle already set\n");
        return;
    }

    SelinuxOptions options[MAX_OPT_NUM] = {0};

    unsigned int index = 0;
    if (access(SYSTEM_FILE_CONTEXTS, R_OK) == 0) {
        SelinuxOptions systemOption = {SELABEL_OPT_PATH, SYSTEM_FILE_CONTEXTS};
        options[index++] = systemOption;
    }
    if (access(VENDOR_FILE_CONTEXTS, R_OK) == 0) {
        SelinuxOptions vendorOption = {SELABEL_OPT_PATH, VENDOR_FILE_CONTEXTS};
        options[index++] = vendorOption;
    }

    // default option of selabel_open
    SelinuxOptions digestOption = {SELABEL_OPT_DIGEST, (char *)1};
    options[index++] = digestOption;

    g_fcHandle = selabel_open(SELABEL_CTX_FILE, options, index);
    if (g_fcHandle == NULL) {
        selinux_log(SELINUX_ERROR, "File_contexts handle open fail\n");
        return;
    }

    selinux_restorecon_set_sehandle(g_fcHandle);
}

static int RestoreconCommon(const char *path, unsigned int flag)
{
    __selinux_once(g_fcOnce, SetFileContextsHandle);
    if (g_fcHandle == NULL) {
        selinux_log(SELINUX_ERROR, "File_contexts handle is null\n");
        return -1;
    }
    return selinux_restorecon(path, flag);
}

int Restorecon(const char *path)
{
    return RestoreconCommon(path, SELINUX_RESTORECON_REALPATH);
}

int RestoreconRecurse(const char *path)
{
    return RestoreconCommon(path, SELINUX_RESTORECON_REALPATH | SELINUX_RESTORECON_RECURSE);
}
