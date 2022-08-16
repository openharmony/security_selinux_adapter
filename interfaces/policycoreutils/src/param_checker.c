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

#include "param_checker.h"
#include <fcntl.h>
#include <selinux_internal.h>
#include <unistd.h>
#include "callbacks.h"
#include "errno.h"
#include "selinux_error.h"
#include "selinux_klog.h"

static pthread_once_t SET_LOG_ONCE = PTHREAD_ONCE_INIT;
#define BUF_SIZE 512

typedef struct AuditMsg {
    const struct ucred *ucred;
    const char *name;
} AuditMsg;

static int GetProcessNameFromPid(pid_t pid, char *processName)
{
    char filename[BUF_SIZE];
    char buff[BUF_SIZE];

    if (snprintf(filename, BUF_SIZE, "/proc/%d/status", pid) <= 0) {
        return -1;
    }
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(buff, BUF_SIZE - 1, fp) != NULL) {
        if (strstr(buff, "Name:") != NULL) {
            if (sscanf(buff, "%*s %s", processName) == EOF) {
                return -1;
            }
            return 0;
        }
    }
    (void)fclose(fp);
    return -1;
}

static int SelinuxAuditCallback(void *data, security_class_t cls, char *buf, size_t len)
{
    if (data == NULL || buf == NULL) {
        return -1;
    }
    AuditMsg *msg = (AuditMsg *)data;
    if (!msg->name || !msg->ucred) {
        selinux_log(SELINUX_ERROR, "Selinux audit msg invalid argument\n");
        return -1;
    }
    char processName[BUF_SIZE];
    if (GetProcessNameFromPid(msg->ucred->pid, processName) != 0) {
        (void)snprintf(processName, BUF_SIZE, "unknown process");
    }
    if (snprintf(buf, len, "process=\"%s\" parameter=%s pid=%d uid=%d gid=%d", processName, msg->name, msg->ucred->pid,
                 msg->ucred->uid, msg->ucred->gid) <= 0) {
        return -1;
    }
    return 0;
}

static void SelinuxSetCallback(void)
{
    SetSelinuxKmsgLevel(SELINUX_KERROR);
    union selinux_callback cb;
    cb.func_log = SelinuxKmsg;
    selinux_set_callback(SELINUX_CB_LOG, cb);
    cb.func_audit = SelinuxAuditCallback;
    selinux_set_callback(SELINUX_CB_AUDIT, cb);
}

static int CheckPerm(const char *paraName, const char *srcContext, const char *destContext, const struct ucred uc)
{
    if (paraName == NULL || srcContext == NULL || destContext == NULL) {
        selinux_log(SELINUX_ERROR, "context empty!\n");
        return -SELINUX_PTR_NULL;
    }
    selinux_log(SELINUX_INFO, "srcContext[%s] is setting param[%s] destContext[%s]\n", srcContext, paraName,
                destContext);
    AuditMsg msg;
    msg.name = paraName;
    msg.ucred = &uc;
    int res = selinux_check_access(srcContext, destContext, "parameter_service", "set", &msg);
    return res == 0 ? SELINUX_SUCC : -SELINUX_PERMISSION_DENY;
}

void SetInitSelinuxLog(void)
{
    if (getpid() == 1) {
        __selinux_once(SET_LOG_ONCE, SelinuxSetCallback);
    }
}

int SetParamCheck(const char *paraName, const char *destContext, const struct ucred *uc)
{
    if (paraName == NULL || destContext == NULL || uc == NULL) {
        selinux_log(SELINUX_ERROR, "input param is null!\n");
        return -SELINUX_PTR_NULL;
    }

    char *srcContext = NULL;
    int rc = getpidcon(uc->pid, &srcContext);
    if (rc < 0) {
        selinux_log(SELINUX_ERROR, "getpidcon failed: %s\n", strerror(errno));
        return -SELINUX_GET_CONTEXT_ERROR;
    }

    int res = CheckPerm(paraName, srcContext, destContext, *uc);
    freecon(srcContext);
    return res;
}
