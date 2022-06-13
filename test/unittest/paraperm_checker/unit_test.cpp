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

#include "unit_test.h"
#include <selinux/selinux.h>
#include "selinux_error.h"
#include "selinux_parameter.h"
#include "test_common.h"

using namespace testing::ext;
using namespace OHOS::Security::SelinuxUnitTest;
using namespace Selinux;
const static std::string PARAM_CONTEXTS_FILE = "/system/etc/selinux/targeted/contexts/parameter_contexts";
const static std::string DEFAULT_CONTEXT = "u:object_r:default_param:s0";
const static std::string TEST_PARA_NAME = "test.para";
const static std::string TEST_NOT_EXIST_PARA_NAME = "unittest.not.exist";
const static std::string TEST_PARA_CONTEXT = "u:object_r:testpara:s0";
const static std::string DEFAULT_PARA_CONTEXT = "u:object_r:default_param:s0";

const static std::vector<std::string> TEST_INVALID_PARA = {{".test"}, {"test."}, {"test..test"}, {""}, {"test+test"}};

static void GenerateTestFile()
{
    ASSERT_EQ(true, CopyFile(PARAM_CONTEXTS_FILE, PARAM_CONTEXTS_FILE + "_bk"));
    std::vector<std::string> paramInfo = {"test.para                           u:object_r:testpara:s0"};
    ASSERT_EQ(true, WriteFile(PARAM_CONTEXTS_FILE, paramInfo));
}

static void RemoveTestFile()
{
    ASSERT_EQ(0, RenameFile(PARAM_CONTEXTS_FILE + "_bk", PARAM_CONTEXTS_FILE));
}

void SelinuxUnitTest::SetUpTestCase()
{
    // make test case clean
    GenerateTestFile();
    InitParamSelinux();
}

void SelinuxUnitTest::TearDownTestCase()
{
    RemoveTestFile();
}

void SelinuxUnitTest::SetUp() {}

void SelinuxUnitTest::TearDown() {}

void SelinuxUnitTest::CreateDataFile() const {}

/**
 * @tc.name: GetParamList001
 * @tc.desc: GetParamList test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, GetParamList001, TestSize.Level1)
{
    ParamContextsList *buff = nullptr;
    buff = GetParamList();
    ASSERT_NE(nullptr, buff);
    ParamContextsList *head = buff;
    bool find = false;
    while (buff != nullptr) {
        if (std::string(buff->info.paraName) == TEST_PARA_NAME &&
            std::string(buff->info.paraContext) == TEST_PARA_CONTEXT) {
            find = true;
            buff = buff->next;
            continue;
        }
        ASSERT_EQ(SELINUX_SUCC, security_check_context(buff->info.paraContext));
        buff = buff->next;
    }
    ASSERT_EQ(true, find);

    DestroyParamList(&head);
    ASSERT_EQ(nullptr, head);
}

/**
 * @tc.name: DestroyParamList001
 * @tc.desc: DestroyParamList input invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, DestroyParamList001, TestSize.Level1)
{
    DestroyParamList(nullptr);
}

/**
 * @tc.name: GetParamLabel001
 * @tc.desc: GetParamLabel input invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, GetParamLabel001, TestSize.Level1)
{
    ASSERT_EQ(DEFAULT_CONTEXT, GetParamLabel(nullptr));

    for (auto para : TEST_INVALID_PARA) {
        ASSERT_EQ(DEFAULT_CONTEXT, GetParamLabel(para.c_str()));
    }

    ASSERT_EQ(DEFAULT_CONTEXT, GetParamLabel(TEST_NOT_EXIST_PARA_NAME.c_str()));
}

/**
 * @tc.name: GetParamLabel002
 * @tc.desc: GetParamLabel func test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, GetParamLabel002, TestSize.Level1)
{
    ASSERT_EQ(TEST_PARA_CONTEXT, GetParamLabel(TEST_PARA_NAME.c_str()));
}

/**
 * @tc.name: ReadParamCheck001
 * @tc.desc: ReadParamCheck input invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, ReadParamCheck001, TestSize.Level1)
{
    ASSERT_EQ(-SELINUX_PTR_NULL, ReadParamCheck(nullptr));

    ASSERT_EQ(SELINUX_SUCC, ReadParamCheck(TEST_NOT_EXIST_PARA_NAME.c_str()));

    std::string cmd = "dmesg | grep 'avc:  denied  { read } for parameter=" + TEST_NOT_EXIST_PARA_NAME +
                      " pid=" + std::to_string(getpid()) + "' | grep 'tcontext=" + DEFAULT_PARA_CONTEXT +
                      " tclass=file'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find(TEST_NOT_EXIST_PARA_NAME) != std::string::npos);

    for (auto para : TEST_INVALID_PARA) {
        ASSERT_EQ(SELINUX_SUCC, ReadParamCheck(para.c_str()));
    }
}

/**
 * @tc.name: ReadParamCheck002
 * @tc.desc: ReadParamCheck func test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, ReadParamCheck002, TestSize.Level1)
{
    ASSERT_EQ(SELINUX_SUCC, ReadParamCheck(TEST_PARA_NAME.c_str()));
    std::string cmd = "dmesg | grep 'avc:  denied  { read } for parameter=" + TEST_PARA_NAME +
                      " pid=" + std::to_string(getpid()) + "' | grep 'tcontext=" + TEST_PARA_CONTEXT + " tclass=file'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find(TEST_PARA_NAME) != std::string::npos);
}

/**
 * @tc.name: SetParamCheck001
 * @tc.desc: SetParamCheck input invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, SetParamCheck001, TestSize.Level1)
{
    struct ucred uc;
    uc.pid = getpid();
    uc.uid = getuid();
    uc.gid = getgid();
    ASSERT_EQ(-SELINUX_PTR_NULL, SetParamCheck(nullptr, &uc));

    ASSERT_EQ(-SELINUX_PTR_NULL, SetParamCheck(TEST_NOT_EXIST_PARA_NAME.c_str(), nullptr));

    ASSERT_EQ(SELINUX_SUCC, SetParamCheck(TEST_NOT_EXIST_PARA_NAME.c_str(), &uc));
    std::string cmd = "dmesg | grep 'avc:  denied  { set } for parameter=" + TEST_NOT_EXIST_PARA_NAME +
                      " pid=" + std::to_string(getpid()) + "' | grep 'tcontext=" + DEFAULT_PARA_CONTEXT +
                      " tclass=parameter_service'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find(TEST_NOT_EXIST_PARA_NAME) != std::string::npos);

    for (auto para : TEST_INVALID_PARA) {
        ASSERT_EQ(SELINUX_SUCC, SetParamCheck(para.c_str(), &uc));
    }
}

/**
 * @tc.name: SetParamCheck002
 * @tc.desc: SetParamCheck func test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDS
 */
HWTEST_F(SelinuxUnitTest, SetParamCheck002, TestSize.Level1)
{
    struct ucred uc;
    uc.pid = getpid();
    uc.uid = getuid();
    uc.gid = getgid();
    ASSERT_EQ(SELINUX_SUCC, SetParamCheck(TEST_PARA_NAME.c_str(), &uc));
    std::string cmd = "dmesg | grep 'avc:  denied  { set } for parameter=" + TEST_PARA_NAME +
                      " pid=" + std::to_string(getpid()) + "' | grep 'tcontext=" + TEST_PARA_CONTEXT +
                      " tclass=parameter_service'";
    std::string cmdRes = RunCommand(cmd);
    ASSERT_TRUE(cmdRes.find(TEST_PARA_NAME) != std::string::npos);
}
