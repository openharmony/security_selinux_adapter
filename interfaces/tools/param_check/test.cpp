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

#include <cstdio>
#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <sys/time.h>
#include <unistd.h>
#include <vector>
#include "selinux_parameter.h"

const static long USEC_PER_SEC = 1000000L;
struct testInput {
    std::string pid;
    std::string paraName;
    bool read;
};

static void TestLoadList()
{
    struct timeval start, end, diff;
    std::string path = "/dev/__parameters__/";

    ParameterInfoList *buff = nullptr;
    gettimeofday(&start, nullptr);
    buff = GetParamList();
    if (buff == nullptr) {
        std::cout << "buff empty" << std::endl;
        return;
    }
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    int runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "GetParamList time use: " << runtime_us << std::endl;

    ParameterInfoList *head = buff;
    while (buff != nullptr) {
        if (security_check_context(buff->info.paraContext) < 0) {
            std::cout << "failed check context: " << buff->info.paraContext << std::endl;
            buff = buff->next;
            continue;
        }
        std::string name = path + std::string(buff->info.paraContext);
        FILE *fp = fopen(name.c_str(), "w");
        if (fp == nullptr) {
            std::cout << "failed: " << name << std::endl;
            buff = buff->next;
            continue;
        }
        (void)fclose(fp);
        if (setfilecon(name.c_str(), buff->info.paraContext) < 0) {
            std::cout << "setcon failed: " << name << std::endl;
        }
        buff = buff->next;
    }

    gettimeofday(&start, nullptr);
    DestroyParamList(&head);
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "DestroyParamList time use: " << runtime_us << std::endl;
}

static void TestGetContext(std::string &paraName)
{
    struct timeval start, end, diff;
    const char *context = nullptr;
    gettimeofday(&start, nullptr);
    int res = GetParamLabel(paraName.c_str(), &context);
    if (res == 0) {
        std::cout << "para " << paraName.c_str() << "'s context is " << context << std::endl;
    } else {
        std::cout << "para " << paraName.c_str() << "'s context get fail, err: " << res << std::endl;
    }
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    int runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "GetParamLabel time use: " << runtime_us << std::endl;
}

static void PrintUsage()
{
    std::cout << "Usage:" << std::endl;
    std::cout << "param_check -n abc.efg -r" << std::endl;
    std::cout << "param_check -p $(pidof init) -n abc.efg -w" << std::endl;
    std::cout << "param_check -g build_version" << std::endl;
    std::cout << "param_check -l" << std::endl;
    std::cout << "" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -h (--help)           show the help information.      [eg: param_check -h]" << std::endl;
    std::cout << " -p (--pid)            subject process pid.            [eg: -p 1]" << std::endl;
    std::cout << " -n (--paraName)       paraName.                       [eg: -n build_version]" << std::endl;
    std::cout << " -g (--getContext)     get context for paraName.       [eg: -g build_version]" << std::endl;
    std::cout << " -r (--read)           read para perm.                 [eg: -r]" << std::endl;
    std::cout << " -w (--write)          write para perm.                [eg: -w]" << std::endl;
    std::cout << " -l (--list)           load para list.                 [eg: -l]" << std::endl;
    std::cout << "" << std::endl;
}

static void SetOptions(int argc, char *argv[], const option *options, testInput &input)
{
    const char *command = argv[1];
    int index = 0;
    const char *optStr = "lhrwn:p:g:";
    int para = 0;
    while ((para = getopt_long(argc, argv, optStr, options, &index)) != -1) {
        switch (para) {
            case 'h': {
                PrintUsage();
                exit(0);
            }
            case 'p': {
                input.pid = optarg;
                break;
            }
            case 'n': {
                input.paraName = optarg;
                break;
            }
            case 'g': {
                std::string paraName = optarg;
                TestGetContext(paraName);
                exit(0);
            }
            case 'r': {
                input.read = true;
                break;
            }
            case 'w': {
                input.read = false;
                break;
            }
            case 'l': {
                TestLoadList();
                exit(0);
            }
            default:
                std::cout << "Try 'param_check -h' for more information." << std::endl;
                exit(-1);
        }
    }
}

int main(int argc, char *argv[])
{
    struct option options[] = {
        {"help", no_argument, nullptr, 'h'},
        {"pid", required_argument, nullptr, 'p'},
        {"paraName", required_argument, nullptr, 'n'},
        {"read", no_argument, nullptr, 'r'},
        {"write", no_argument, nullptr, 'w'},
        {"list", no_argument, nullptr, 'l'},
        {"getContext", required_argument, nullptr, 'g'},
        {nullptr, no_argument, nullptr, 0},
    };

    if (argc == 1) {
        PrintUsage();
        exit(0);
    }
    SetSelinuxLogCallback();
    testInput testCmd;
    SetOptions(argc, argv, options, testCmd);
    int res = 0;
    struct timeval start, end, diff;
    gettimeofday(&start, nullptr);
    if (testCmd.read) {
        res = ReadParamCheck(testCmd.paraName.c_str());
        std::cout << "ReadParamCheck res: " << res << std::endl;
    } else {
        struct ucred uc;
        uc.pid = atoi(testCmd.pid.c_str());
        uc.uid = 0;
        uc.gid = 0;
        res = SetParamCheck(testCmd.paraName.c_str(), &uc);
        std::cout << "SetParamCheck res: " << res << std::endl;
    }
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    int runtime_us = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "time use: " << runtime_us << std::endl;

    exit(0);
}
