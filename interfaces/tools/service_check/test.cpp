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

#include <getopt.h>
#include <iostream>
#include <unistd.h>
#include "service_checker.h"
#include "selinux_error.h"

using namespace Selinux;

static std::unique_ptr<ServiceChecker> g_service = nullptr;

struct testInput {
    char cmd = '\0';
    bool isHdf = false;
};

static void PrintUsage()
{
    std::cout << "Usage:" << std::endl;
    std::cout << "step 1:" << std::endl;
    std::cout << "service_check (-d) -a|-g|-r|-l" << std::endl;
    std::cout << "step 2:" << std::endl;
    std::cout << "input service name and press 'enter' to continue, or ctrl+C to end process" << std::endl;
    std::cout << "" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << " -h (--help)           show the help information.        [eg: service_check -h]" << std::endl;
    std::cout << "***********************optinal*************************************************" << std::endl;
    std::cout << " -d (--isHdf)          service or hdf_service.           [eg: service_check -d]" << std::endl;
    std::cout << "***********************requered: 1 in 4****************************************" << std::endl;
    std::cout << " -a (--add)            add service check.                [eg: service_check -a]" << std::endl;
    std::cout << " -g (--get)            get service check.                [eg: service_check -g]" << std::endl;
    std::cout << " -r (--get_remote)     get remote service check.         [eg: service_check -r]" << std::endl;
    std::cout << " -l (--list)           list service check.               [eg: service_check -l]" << std::endl;
    std::cout << "" << std::endl;
}

static void SetOptions(int argc, char *argv[], const option *options, testInput &input)
{
    int index = 0;
    const char *optStr = "dhlagr";
    int para = 0;
    while ((para = getopt_long(argc, argv, optStr, options, &index)) != -1) {
        switch (para) {
            case 'h': {
                PrintUsage();
                exit(0);
            }
            case 'd': {
                input.isHdf = true;
                break;
            }
            case 'a': {
                input.cmd = 'a';
                break;
            }
            case 'g': {
                input.cmd = 'g';
                break;
            }
            case 'r': {
                input.cmd = 'r';
                break;
            }
            case 'l': {
                input.cmd = 'l';
                break;
            }
            default:
                std::cout << "Try 'service_check -h' for more information." << std::endl;
                exit(-1);
        }
    }
}

int main(int argc, char *argv[])
{
    struct option options[] = {
        {"help", no_argument, nullptr, 'h'},  {"add", no_argument, nullptr, 'a'},
        {"get", no_argument, nullptr, 'g'},   {"get_remote", no_argument, nullptr, 'r'},
        {"isHdf", no_argument, nullptr, 'd'}, {"list", no_argument, nullptr, 'l'},
        {nullptr, no_argument, nullptr, 0},
    };

    if (argc == 1) {
        PrintUsage();
        exit(0);
    }

    testInput input;
    SetOptions(argc, argv, options, input);
    if (input.isHdf) {
        g_service = std::make_unique<ServiceChecker>(true);
    } else {
        g_service = std::make_unique<ServiceChecker>(false);
    }
    std::string serName;
    switch (input.cmd) {
        case 'a': {
            while (std::cin >> serName) {
                std::cout << GetErrStr(g_service->AddServiceCheck(getpid(), serName)) << std::endl;
            }
            exit(0);
        }
        case 'g': {
            while (std::cin >> serName) {
                std::cout << GetErrStr(g_service->GetServiceCheck(getpid(), serName)) << std::endl;
            }
            exit(0);
        }
        case 'r': {
            while (std::cin >> serName) {
                std::cout << GetErrStr(g_service->GetRemoteServiceCheck(getpid(), serName)) << std::endl;
            }
            exit(0);
        }
        case 'l': {
            std::cout << GetErrStr(g_service->ListServiceCheck(getpid())) << std::endl;
            exit(0);
        }
        default:
            exit(-1);
    }

    exit(0);
}
