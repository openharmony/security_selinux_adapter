#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2023 Huawei Device Co., Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import json
import os
import subprocess


def read_json_file(input_file):
    data = None
    try:
        with open(input_file, 'r') as input_f:
            data = json.load(input_f)
    except json.decoder.JSONDecodeError:
        print('The file \'{}\' format is incorrect.'.format(input_file))
        raise
    except:
        print('read file \'{}\' failed.'.format(input_file))
        raise
    return data


def read_file(input_file):
    lines = []
    with open(input_file, 'r') as fp:
        for line in fp.readlines():
            lines.append(line.strip())
    return lines

def run_command(in_cmd):
    cmdstr = " ".join(in_cmd)
    print(cmdstr)
    ret = subprocess.run(cmdstr, shell=True).returncode
    if ret != 0:
        raise Exception(ret)