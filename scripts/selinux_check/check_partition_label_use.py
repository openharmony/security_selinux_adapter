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
from collections import defaultdict


def read_file(input_file):
    lines = []
    with open(input_file, 'r') as fp:
        for line in fp.readlines():
            lines.append(line.strip())
    return lines


def check_file_contexts(args, file_contexts, whitelist_path, label_list):
    whitelist = read_file(whitelist_path)
    whitelist_map = defaultdict(list)
    for it in whitelist:
        split_str = it.split()
        if len(split_str) < 2:
            continue
        whitelist_map[split_str[1]].append(split_str[0])

    label_list_set = set()
    for it in label_list:
        label_list_set.add(it)

    line_index = 0
    err = False
    for line in file_contexts:
        line_index += 1
        elements = line.split()
        if len(elements) < 2:
            continue
        path = elements[0]
        label = elements[1]
        if label in label_list_set:
            if path in whitelist_map[label]:
                continue
            print("partition label is not allow to use,",
                  "check '{} {}' failed in file {}:{}\n".format(path, label, args.file_contexts, line_index),
                  "There are two solutions:\n",
                  "1. Add '{} {}' to whitelist file '{}';\n".format(path, label, whitelist_path),
                  "2. Change '{} {}' to avoid using label in {}\n".format(path, label, label_list))
            err = True
    if err:
        raise Exception(-1)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--file_contexts', help='the file_contexts file path', required=True)
    parser.add_argument(
        '--whitelist', help='the whitelist file path', required=True)
    parser.add_argument(
        '--config', help='the config file path', required=True)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    script_path = os.path.dirname(os.path.realpath(__file__))
    whitelist_path = os.path.join(script_path, args.whitelist)

    label_path = os.path.join(script_path, args.config)
    label_list = read_file(label_path)

    file_contexts = read_file(args.file_contexts)
    check_file_contexts(args, file_contexts, whitelist_path, label_list)
