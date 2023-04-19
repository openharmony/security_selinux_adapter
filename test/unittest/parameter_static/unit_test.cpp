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

#include <selinux/selinux.h>
#include <vector>
#include "contexts_trie.h"
#include "selinux_error.h"
#include "selinux_map.h"
#include "selinux_share_mem.h"
#include "test_common.h"

using namespace testing::ext;
using namespace OHOS::Security::SelinuxUnitTest;
using namespace Selinux;
const static std::string PARAMETER_CONTEXTS_FILE = "/system/etc/selinux/targeted/contexts/parameter_contexts";

void SelinuxUnitTest::SetUpTestCase()
{
    ASSERT_EQ(true, CopyFile(PARAMETER_CONTEXTS_FILE, PARAMETER_CONTEXTS_FILE + "_bk"));
    std::vector<std::string> sehapInfo = {
        "apl=system_core name=com.ohos.test domain= type=",
        "apl=system_core name=com.par.selftest domain=selftest type=selftest_par_data_file"};
    ASSERT_EQ(true, WriteFile(PARAMETER_CONTEXTS_FILE, sehapInfo));
}

static void RemoveTestFile()
{
    ASSERT_EQ(0, RenameFile(PARAMETER_CONTEXTS_FILE + "_bk", PARAMETER_CONTEXTS_FILE));
}

void SelinuxUnitTest::TearDownTestCase()
{
    RemoveTestFile();
    LoadParameterContextsToSharedMem();
}

void SelinuxUnitTest::SetUp() {}

void SelinuxUnitTest::TearDown() {}

/**
 * @tc.name: HashMapCreate001
 * @tc.desc: Test HashMapCreate parameter is not empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapCreate001, TestSize.Level1)
{
    ParamContextsTrie *root = static_cast<ParamContextsTrie *>(calloc(1, sizeof(ParamContextsTrie)));
    ASSERT_NE(nullptr, root);
    root->prefixLabel = "u:object_r:default_param:s0";
    root->matchLabel = "u:object_r:default_param:s0";
    root->index = 0;
    EXPECT_EQ(0, HashMapCreate(&root->handle));
    free(root);
}

/**
 * @tc.name: HashMapCreate002
 * @tc.desc: HashMapCreate type empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapCreate002, TestSize.Level1)
{
    ASSERT_EQ(-1, HashMapCreate(nullptr));
}

/**
 * @tc.name: HashMapDestroy001
 * @tc.desc: HashMapDestroy type empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapDestroy001, TestSize.Level1)
{
    HashTab *handle = nullptr;
    HashMapDestroy(handle);
    ASSERT_EQ(nullptr, handle);
}

/**
 * @tc.name: HashMapFind001
 * @tc.desc: Test HashMapFind.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, HashMapFind001, TestSize.Level1)
{
    HashTab *handle;
    ParamContextsTrie *root = static_cast<ParamContextsTrie *>(calloc(1, sizeof(ParamContextsTrie)));
    ASSERT_NE(nullptr, root);
    HashNode *rel = HashMapFind(handle, 0, "");
    EXPECT_EQ(NULL, rel);
    rel = HashMapFind(root->handle, 0, "test_key");
    EXPECT_EQ(NULL, rel);

    root->prefixLabel = "u:object_r:default_param:s0";
    root->matchLabel = "u:object_r:default_param:s0";
    root->index = 0;
    EXPECT_EQ(0, HashMapCreate(&root->handle));
    EXPECT_NE(nullptr, root->handle);
    rel = HashMapFind(root->handle, 0, "");
    EXPECT_EQ(NULL, rel);
    rel = HashMapFind(handle, 0, "test_key");
    EXPECT_EQ(NULL, rel);
    free(root);
}

/**
 * @tc.name: LoadParameterContextsToSharedMem001
 * @tc.desc: LoadParameterContextsToSharedMem input valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, LoadParameterContextsToSharedMem001, TestSize.Level1)
{
    std::string overLengthStr = "test";
    RunCommand("echo -n "" /system/etc/selinux/targeted/contexts/parameter_contexts");
    std::vector<std::string> sehapInfo = {
        "t u:o:t:s0",
        "test.test.test.         ",
        "test.test.test.         u:object_r:test_param:s0",
        "###############################################",
    };
    for (int i = 0; i < 20; i++) {
        overLengthStr += "testtesttesttesttesttesttesttesttesttesttesttesttesttesttest";
    }
    sehapInfo.emplace_back(overLengthStr);
    ASSERT_EQ(true, WriteFile(PARAMETER_CONTEXTS_FILE, sehapInfo));
    int result = LoadParameterContextsToSharedMem();
    ASSERT_EQ(0, result);
}

/**
 * @tc.name: LoadParameterContextsToSharedMem002
 * @tc.desc: LoadParameterContextsToSharedMem input invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, LoadParameterContextsToSharedMem002, TestSize.Level1)
{
    RunCommand("echo -n "" /system/etc/selinux/targeted/contexts/parameter_contexts");
    RenameFile(PARAMETER_CONTEXTS_FILE, PARAMETER_CONTEXTS_FILE + "bk1");

    int result = LoadParameterContextsToSharedMem();
    EXPECT_EQ(-SELINUX_CONTEXTS_FILE_LOAD_ERROR, result);
    RenameFile(PARAMETER_CONTEXTS_FILE + "bk1", PARAMETER_CONTEXTS_FILE);
}

/**
 * @tc.name: InitSharedMem001
 * @tc.desc: InitSharedMem input invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, InitSharedMem001, TestSize.Level1)
{
    EXPECT_EQ(NULL, InitSharedMem("", 0, 0));
    EXPECT_EQ(NULL, InitSharedMem("/dev/__parameters__/param_selinux", 0, 0));
    EXPECT_EQ(NULL, InitSharedMem("", 1024 * 80, 0));
    EXPECT_NE(NULL, InitSharedMem("invalid_path", 1024 * 80, 0));
    EXPECT_EQ(NULL, InitSharedMem("invalid_path11", 1024 * 80, 1));
}

/**
 * @tc.name: InitSharedMem002
 * @tc.desc: InitSharedMem input valid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, InitSharedMem002, TestSize.Level1)
{
    ASSERT_NE(NULL, InitSharedMem("/dev/__parameters__/param_selinux", 1024 * 80, 1));
    ASSERT_NE(NULL, InitSharedMem("/dev/__parameters__/param_selinux", 1024 * 80, 0));
    ASSERT_NE(NULL, InitSharedMem("/dev/__parameters__/param_selinux", 1, 0));
}

/**
 * @tc.name: ReadSharedMem001
 * @tc.desc: ReadSharedMem input invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SelinuxUnitTest, ReadSharedMem001, TestSize.Level1)
{
    char *sharedMem;
    EXPECT_EQ(NULL, ReadSharedMem(sharedMem, 1));
    EXPECT_EQ(NULL, ReadSharedMem("test", 0));
    ASSERT_NE(NULL, ReadSharedMem("test", 4));
}
