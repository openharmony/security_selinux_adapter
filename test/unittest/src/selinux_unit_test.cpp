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

#include "selinux_unit_test.h"
#include <selinux/selinux.h>
#include <thread>
#include "selinux_error.h"

using namespace testing::ext;
using namespace OHOS::Security::Selinux;
using namespace Selinux;

const static std::string BASE_PATH = "/data/app/el1/0/base/";
const static std::string DATA_BASE_PATH = "/data/app/el1/0/database/";
const static std::string TEST_PATH = BASE_PATH + "com.ohos.selftest/";

const static std::string TEST_SUB_PATH_1 = TEST_PATH + "subpath1/";
const static std::string TEST_SUB_PATH_2 = TEST_PATH + "subpath2/";
const static std::string TEST_SUB_PATH_3 = TEST_PATH + "subpath3/";
const static std::string TEST_SUB_PATH_4 = TEST_PATH + "subpath4/";

const static std::string TEST_SUB_PATH_1_FILE_1 = TEST_SUB_PATH_1 + "file1.txt";
const static std::string TEST_SUB_PATH_1_FILE_2 = TEST_SUB_PATH_1 + "file2.txt";
const static std::string TEST_SUB_PATH_2_FILE_1 = TEST_SUB_PATH_2 + "file1.txt";
const static std::string TEST_SUB_PATH_2_FILE_2 = TEST_SUB_PATH_2 + "file2.txt";
const static std::string TEST_SUB_PATH_3_FILE_1 = TEST_SUB_PATH_3 + "file1.txt";
const static std::string TEST_SUB_PATH_3_FILE_2 = TEST_SUB_PATH_3 + "file2.txt";
const static std::string TEST_SUB_PATH_4_FILE_1 = TEST_SUB_PATH_4 + "file1.txt";
const static std::string TEST_SUB_PATH_4_FILE_2 = TEST_SUB_PATH_4 + "file2.txt";

const static std::string TEST_UNSIMPLIFY_PATH = TEST_SUB_PATH_3 + "//../subpath4/";
const static std::string TEST_UNSIMPLIFY_FILE = TEST_SUB_PATH_4 + "//../subpath3/file1.txt";

const static std::string INVALID_PATH = "/data/data/path";
const static std::string NOT_EXIST_PATH = BASE_PATH + "not_exsit_path";
const static std::string TEST_APL = "system_core";
const static std::string TEST_NAME = "com.hap.selftest";
const static std::string DEST_LABEL = "u:object_r:selftest_hap_data_file:s0";
const static std::string DEST_DOMAIN = "u:r:selftest:s0";

static const std::string SEHAP_CONTEXTS_FILE = "/system/etc/selinux/targeted/contexts/sehap_contexts";

static void RunSysCmd(const std::string &cmd)
{
    system(cmd.c_str());
}

static std::string RunCommand(const std::string &command)
{
    std::string result = "";
    FILE *file = popen(command.c_str(), "r");

    if (file != nullptr) {
        char commandResult[1024] = {0};
        while ((fgets(commandResult, sizeof(commandResult), file)) != nullptr) {
            result.append(commandResult);
        }
        pclose(file);
        file = nullptr;
    }
    return result;
}

void SelinuxUnitTest::SetUpTestCase()
{
    // make test case clean
}

void SelinuxUnitTest::TearDownTestCase() {}

void SelinuxUnitTest::SetUp()
{
    RunSysCmd("cp " + SEHAP_CONTEXTS_FILE + " " + SEHAP_CONTEXTS_FILE + "_bk");
    RunSysCmd("echo 'apl=system_core name=com.ohos.test domain= type=' >> " + SEHAP_CONTEXTS_FILE);
    RunSysCmd("echo 'apl=system_core name=com.hap.selftest domain=selftest type=selftest_hap_data_file' >> " +
              SEHAP_CONTEXTS_FILE);
}

void SelinuxUnitTest::TearDown()
{
    RunSysCmd("mv " + SEHAP_CONTEXTS_FILE + "_bk " + SEHAP_CONTEXTS_FILE);
}

void SelinuxUnitTest::CreateDataFile() const {}

/**
 * @tc.name: HapFileRestorecon001
 * @tc.desc: HapFileRestorecon input path invalid.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon001, TestSize.Level1)
{
    RunSysCmd("mkdir -p " + INVALID_PATH);

    int ret = test.HapFileRestorecon(INVALID_PATH, TEST_APL, TEST_NAME, 0);
    ASSERT_EQ(-SELINUX_PATH_INVAILD, ret);
    RunSysCmd("rm -r " + INVALID_PATH);

    if (access(NOT_EXIST_PATH.c_str(), F_OK) == 0) {
        RunSysCmd("rm -r " + NOT_EXIST_PATH);
    }

    ret = test.HapFileRestorecon(NOT_EXIST_PATH, TEST_APL, TEST_NAME, 0);
    ASSERT_EQ(-SELINUX_PATH_INVAILD, ret);
}

/**
 * @tc.name: HapFileRestorecon002
 * @tc.desc: HapFileRestorecon input para empty.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon002, TestSize.Level1)
{
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_1);

    int ret = test.HapFileRestorecon("", TEST_APL, TEST_NAME, 0);
    ASSERT_EQ(-SELINUX_PATH_INVAILD, ret);

    ret = test.HapFileRestorecon(TEST_SUB_PATH_1, "", TEST_NAME, 0);
    ASSERT_EQ(-SELINUX_ARG_INVALID, ret);

    ret = test.HapFileRestorecon(TEST_SUB_PATH_1, TEST_APL, "", 0);
    ASSERT_EQ(SELINUX_SUCC, ret);

    RunSysCmd("rm -r " + TEST_PATH);
}

/**
 * @tc.name: HapFileRestorecon003
 * @tc.desc: HapFileRestorecon type empty.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon003, TestSize.Level1)
{
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_1);
    // apl=system_core name=com.ohos.test domain= type=
    int ret = test.HapFileRestorecon(TEST_SUB_PATH_1, TEST_APL, "com.ohos.test", 0);
    ASSERT_EQ(-SELINUX_TYPE_INVALID, ret);

    RunSysCmd("rm -r " + TEST_PATH);
}

/**
 * @tc.name: HapFileRestorecon004
 * @tc.desc: HapFileRestorecon input single path no recurse.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon004, TestSize.Level1)
{
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_1);
    RunSysCmd("touch " + TEST_SUB_PATH_1_FILE_1); // this file should not be restorecon

    char *secontextOld = nullptr;
    getfilecon(TEST_SUB_PATH_1_FILE_1.c_str(), &secontextOld);

    int ret = test.HapFileRestorecon(TEST_SUB_PATH_1, TEST_APL, TEST_NAME, 0);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_1.c_str(), &secontext);
    ret = strcmp(secontextOld, secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    RunSysCmd("rm -r " + TEST_PATH);
}

/**
 * @tc.name: HapFileRestorecon005
 * @tc.desc: HapFileRestorecon input single path recurse.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon005, TestSize.Level1)
{
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_1);
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_2);
    RunSysCmd("touch " + TEST_SUB_PATH_1_FILE_1);
    RunSysCmd("touch " + TEST_SUB_PATH_1_FILE_2);
    RunSysCmd("touch " + TEST_SUB_PATH_2_FILE_1);
    RunSysCmd("touch " + TEST_SUB_PATH_2_FILE_2);

    int ret = test.HapFileRestorecon(TEST_PATH, TEST_APL, TEST_NAME, 1);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_2.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2_FILE_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2_FILE_2.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    RunSysCmd("rm -r " + TEST_PATH);
}

/**
 * @tc.name: HapFileRestorecon006
 * @tc.desc: HapFileRestorecon input single unsimplify path/file.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon006, TestSize.Level1)
{
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_3);
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_4);
    RunSysCmd("touch " + TEST_SUB_PATH_3_FILE_1);

    int ret = test.HapFileRestorecon(TEST_UNSIMPLIFY_PATH, TEST_APL, TEST_NAME, 0);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_4.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    ret = test.HapFileRestorecon(TEST_UNSIMPLIFY_FILE, TEST_APL, TEST_NAME, 0);
    ASSERT_EQ(SELINUX_SUCC, ret);

    secontext = nullptr;
    getfilecon(TEST_SUB_PATH_3_FILE_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    RunSysCmd("rm -r " + TEST_PATH);
}

/**
 * @tc.name: HapFileRestorecon007
 * @tc.desc: HapFileRestorecon input multi path/file no recurse.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon007, TestSize.Level1)
{
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_1);
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_2);
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_3);
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_4);
    RunSysCmd("touch " + TEST_SUB_PATH_1_FILE_1);
    RunSysCmd("touch " + TEST_SUB_PATH_1_FILE_2);
    RunSysCmd("touch " + TEST_SUB_PATH_2_FILE_1); // should not be restorecon
    RunSysCmd("touch " + TEST_SUB_PATH_3_FILE_1);

    char *secontextOld = nullptr;
    getfilecon(TEST_SUB_PATH_2_FILE_1.c_str(), &secontextOld);

    std::vector<std::string> tmp;
    tmp.emplace_back(TEST_SUB_PATH_1);
    tmp.emplace_back(TEST_SUB_PATH_2);
    tmp.emplace_back(TEST_SUB_PATH_1_FILE_1);
    tmp.emplace_back(TEST_SUB_PATH_1_FILE_2);
    tmp.emplace_back(TEST_UNSIMPLIFY_FILE);
    tmp.emplace_back(TEST_UNSIMPLIFY_PATH);

    int ret = test.HapFileRestorecon(tmp, TEST_APL, TEST_NAME, 0);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_2.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2_FILE_1.c_str(), &secontext); // this file should not be restorecon
    ret = strcmp(secontextOld, secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    freecon(secontextOld);
    secontext = nullptr;
    secontextOld = nullptr;

    getfilecon(TEST_SUB_PATH_3_FILE_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_4.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    RunSysCmd("rm -r " + TEST_PATH);
}

/**
 * @tc.name: HapFileRestorecon008
 * @tc.desc: HapFileRestorecon input multi path/file recurse.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon008, TestSize.Level1)
{
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_1);
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_2);
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_3);
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_4);
    RunSysCmd("touch " + TEST_SUB_PATH_1_FILE_1);
    RunSysCmd("touch " + TEST_SUB_PATH_1_FILE_2);
    RunSysCmd("touch " + TEST_SUB_PATH_2_FILE_1);
    RunSysCmd("touch " + TEST_SUB_PATH_2_FILE_2);
    RunSysCmd("touch " + TEST_SUB_PATH_3_FILE_1);
    RunSysCmd("touch " + TEST_SUB_PATH_3_FILE_2); // this file should not be restorecon
    RunSysCmd("touch " + TEST_SUB_PATH_4_FILE_1);
    RunSysCmd("touch " + TEST_SUB_PATH_4_FILE_2);

    std::vector<std::string> tmp;
    tmp.emplace_back(TEST_SUB_PATH_1);
    tmp.emplace_back(TEST_SUB_PATH_2);
    tmp.emplace_back(TEST_UNSIMPLIFY_FILE);
    tmp.emplace_back(TEST_UNSIMPLIFY_PATH);

    char *secontextOld = nullptr;
    getfilecon(TEST_SUB_PATH_3_FILE_2.c_str(), &secontextOld);

    int ret = test.HapFileRestorecon(tmp, TEST_APL, TEST_NAME, 1);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_4.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_1_FILE_2.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2_FILE_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_2_FILE_2.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_4_FILE_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_4_FILE_2.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_3_FILE_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    getfilecon(TEST_SUB_PATH_3_FILE_2.c_str(), &secontext);
    ret = strcmp(secontextOld, secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    freecon(secontextOld);
    secontext = nullptr;
    secontextOld = nullptr;

    RunSysCmd("rm -r " + TEST_PATH);
}

/**
 * @tc.name: HapFileRestorecon009
 * @tc.desc: HapFileRestorecon double.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapFileRestorecon009, TestSize.Level1)
{
    RunSysCmd("mkdir -p " + TEST_SUB_PATH_1);

    int ret = test.HapFileRestorecon(TEST_SUB_PATH_1, TEST_APL, TEST_NAME, 0);
    ASSERT_EQ(SELINUX_SUCC, ret);

    char *secontext = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontext);
    ret = strcmp(DEST_LABEL.c_str(), secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    secontext = nullptr;

    char *secontextOld = nullptr;
    getfilecon(TEST_SUB_PATH_1.c_str(), &secontextOld);

    ret = test.HapFileRestorecon(TEST_SUB_PATH_1, TEST_APL, TEST_NAME, 0); // double restorcon
    ASSERT_EQ(SELINUX_SUCC, ret);

    getfilecon(TEST_SUB_PATH_1.c_str(), &secontext);
    ret = strcmp(secontextOld, secontext);
    ASSERT_EQ(SELINUX_SUCC, ret);
    freecon(secontext);
    freecon(secontextOld);
    secontext = nullptr;
    secontextOld = nullptr;

    RunSysCmd("rm -r " + TEST_PATH);
}

/**
 * @tc.name: HapDomainSetcontext001
 * @tc.desc: HapDomainSetcontext input para empty.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapDomainSetcontext001, TestSize.Level1)
{
    int ret = test.HapDomainSetcontext("", TEST_NAME);
    ASSERT_EQ(-SELINUX_KEY_NOT_FOUND, ret);

    ret = test.HapDomainSetcontext(TEST_APL, "");
    ASSERT_EQ(SELINUX_SUCC, ret);
}

/**
 * @tc.name: HapDomainSetcontext002
 * @tc.desc: HapDomainSetcontext domain empty.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapDomainSetcontext002, TestSize.Level1)
{
    // apl=system_core name=com.ohos.test domain= type=
    int ret = test.HapDomainSetcontext(TEST_APL, "com.ohos.test");
    ASSERT_EQ(-SELINUX_TYPE_INVALID, ret);
}

/**
 * @tc.name: HapDomainSetcontext003
 * @tc.desc: HapDomainSetcontext domain function test.
 * @tc.type: FUNC
 * @tc.require:AR000GJSDQ
 */
HWTEST_F(SelinuxUnitTest, HapDomainSetcontext003, TestSize.Level1)
{
    pid_t pid = fork();
    ASSERT_TRUE(pid >= 0);
    if (pid < 0) {
        return;
    } else if (pid == 0) {
        int ret = test.HapDomainSetcontext(TEST_APL, TEST_NAME);
        ASSERT_EQ(SELINUX_SUCC, ret);
        sleep(1);
        exit(0);
    } else {
        std::string cmdRes = RunCommand("ps -efZ | grep selinux_unittest | grep -v grep");
        ASSERT_TRUE(cmdRes.find(DEST_DOMAIN) != std::string::npos);
    }
}
