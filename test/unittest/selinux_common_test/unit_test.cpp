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

#include "unit_test.h"
#include <thread>
#include <selinux/selinux.h>
#include "selinux_error.h"
#include "test_common.h"

using namespace testing::ext;
using namespace OHOS::Security::SelinuxUnitTest;
using namespace Selinux;

void SelinuxUnitTest::SetUpTestCase() {}

void SelinuxUnitTest::TearDownTestCase() {}

void SelinuxUnitTest::SetUp() {}

void SelinuxUnitTest::TearDown() {}

/**
 * @tc.name: MlsTest001
 * @tc.desc: test mls.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, MlsTest001, TestSize.Level1)
{
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    const char *contextC10 = "u:r:normal_hap:s0:c10";
    if (pid == 0) {
        const char *contextS0 = "u:r:normal_hap:s0";
        const char *contextC1023 = "u:r:normal_hap:s0:c1023";
        const char *contextC1025 = "u:r:normal_hap:s0:c1025";
        char *test = nullptr;
        int ret = security_check_context(contextS0);
        EXPECT_EQ(SELINUX_SUCC, ret);

        ret = security_check_context(contextC10);
        EXPECT_EQ(SELINUX_SUCC, ret);

        ret = security_check_context(contextC1023);
        EXPECT_EQ(SELINUX_SUCC, ret);

        ret = security_check_context(contextC1025);
        EXPECT_NE(SELINUX_SUCC, ret);

        ret = setcon(contextC10);
        ASSERT_EQ(SELINUX_SUCC, ret);
        getcon(&test);
        EXPECT_EQ(0, strcmp(test, contextC10));
        usleep(20000); // 20000 : sleep 20ms
        freecon(test);
        exit(0);
    } else {
        usleep(10000); // 10000 : sleep 10ms
        char *test1 = nullptr;
        getpidcon(pid, &test1);
        EXPECT_EQ(0, strcmp(test1, contextC10));
        freecon(test1);
    }
}
