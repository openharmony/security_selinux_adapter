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

import argparse
import os
import re


def read_file(input_file):
    lines = []
    with open(input_file, 'r') as fp:
        for line in fp.readlines():
            lines.append(line.strip())
    return lines


def check_regex_path(path):
    regex_set = set("")
    path_elements = path.split('/')
    second_dir_name = path_elements[2]

    # remove all escape
    replace_str = re.sub(r'\\[\$\(\)\*\+\.\[\]\?\\\^\{\}\|]', '', second_dir_name)

    # find special characters that have not been escaped
    return re.search(r'[\$\(\)\*\+\.\[\]\?\\\^\{\}\|]', replace_str)


def check_file_contexts(args, file_contexts, whitelist_path):
    whitelist = read_file(whitelist_path)
    whitelist_set = set()
    for it in whitelist:
        whitelist_set.add(it)

    line_index = 0
    err = False
    for line in file_contexts:
        line_index += 1
        if line.startswith("/data/"):
            path = line.split(None, 1)[0]
            if path in whitelist_set:
                continue
            if not check_regex_path(path):
                continue
            print("Regex is not allowed in the secondary directory under data,",
                "check '{}' failed in file {}:{}\n".format(path, args.file_contexts, line_index),
                "There are two solutions:\n",
                "1. Add '{}' to whitelist file '{}';\n".format(path, whitelist_path),
                "2. Modify '{}' to remove the regular expression\n".format(path))
            err = True
    if err:
        raise Exception(-1)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--file_contexts', help='the file_contexts file path', required=True)
    parser.add_argument(
        '--whitelist', help='the whitelist path', required=True)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    script_path = os.path.dirname(os.path.realpath(__file__))
    whitelist_path = os.path.join(script_path, args.whitelist)

    file_contexts = read_file(args.file_contexts)
    check_file_contexts(args, file_contexts, whitelist_path)
