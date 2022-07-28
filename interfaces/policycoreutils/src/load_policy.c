/* Copyright (c) 2021-2022 北京万里红科技有限公司
 *
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <selinux/selinux.h>
#include <policycoreutils.h>
#include "selinux_klog.h"

int LoadPolicy(void)
{
    // set selinux log callback
    SetSelinuxKmsgLevel(SELINUX_KERROR);
    union selinux_callback cb;
    cb.func_log = SelinuxKmsg;
    selinux_set_callback(SELINUX_CB_LOG, cb);

    int enforce = 0;
    int ret = selinux_init_load_policy(&enforce);
    if (ret && enforce > 0) {
        fprintf(stderr, "Can't load policy and enforcing mode requested:  %s\n", strerror(errno));
        return -1;
    }
    return 1;
}
