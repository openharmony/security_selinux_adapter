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

#include "hap_restorecon.h"

#include <unistd.h>

int main(int argc, char **argv)
{
    int res;
    HapContext test;
    std::cout << "test 1: invalid path not with /data/app" << std::endl;
    res = test.HapFileRestorecon("/data/data/com.hap.selftest", "system_core", "com.hap.selftest",
                                 SELINUX_HAP_RESTORECON_RECURSE);
    std::cout << "res: " << res << std::endl;

    std::cout << "test 2: single path" << std::endl;
    res = test.HapFileRestorecon("/data/app/com.hap.selftest", "system_core", "com.hap.selftest",
                                 SELINUX_HAP_RESTORECON_RECURSE);
    std::cout << "res: " << res << std::endl;

    std::cout << "test 3: single path no recurse" << std::endl;
    res = test.HapFileRestorecon("/data/app/com.hap.selftest1", "system_core", "com.hap.selftest1", 0);
    std::cout << "res: " << res << std::endl;

    std::cout << "test 4: multi path" << std::endl;
    std::vector<std::string> tmp;
    tmp.emplace_back("/data/app/test1");
    tmp.emplace_back("/data/app/test2");
    tmp.emplace_back("/data/app/test3");

    res = test.HapFileRestorecon(tmp, "system_core", "com.hap.selftest", SELINUX_HAP_RESTORECON_RECURSE);
    std::cout << "res: " << res << std::endl;

    std::cout << "test 5" << std::endl;
    res = test.HapDomainSetcontext("system_core", "com.hap.selftest");
    std::cout << "res: " << res << std::endl;

    while(1);
    return 0;
}