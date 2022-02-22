/* Copyright (c) 2021 北京万里红科技有限公司
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
#include <selinux/selinux.h>
#include <sepol/sepol.h>
#include <string.h>

int LoadPolicy(void)
{
    int ret, enforce = 0;

    if ((ret = selinux_init_load_policy(&enforce))) {
        if (enforce > 0) {
            fprintf(stderr,
                    "Can't load policy and enforcing mode requested:  %s\n",
                    strerror(errno));
            return -1;
        }
    }

    if ((ret = selinux_mkload_policy(0)) < 0) {
        fprintf(stderr, "Can't load policy:  %s\n", strerror(errno));
        return -1;
    }

    return 1;
}
