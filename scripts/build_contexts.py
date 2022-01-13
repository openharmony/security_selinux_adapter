#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2021 Huawei Device Co., Ltd.
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

import os
import argparse

SCRIPT_PATH = os.path.abspath(os.path.dirname(__file__))
LOCAL_PATH = os.path.abspath(os.path.join(SCRIPT_PATH, "../"))
FILE_CONTEXTS_PATH = LOCAL_PATH + "/sepolicy"


def parse_args():
    """parse arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--dst-file', help='the file_contexts.bin dest path', required=True)
    parser.add_argument('--tool-path',
                        help='the sefcontext_compile bin path', required=True)
    args = parser.parse_args()
    return args


def run_command(in_cmd):
    """run commond in os.system.

    Raises:
        OSError: If the cmd return none zero.
    """
    cmdstr = " ".join(in_cmd)
    rc = os.system(cmdstr)
    if rc:
        raise Exception(rc)


def build_file_contexts_tmp(output_tmp, input_file_contexts_list):
    """build file_contexts_tmp from file_contexts."""
    build_tmp_cmd = ["m4",
                     "--fatal-warnings",
                     "-s", input_file_contexts_list, ">", output_tmp]
    run_command(build_tmp_cmd)


def build_file_contexts_bin(args, input_file_contexts_tmp):
    """build file_contexts.bin."""
    build_bin_cmd = [args.tool_path + "/sefcontext_compile",
                     "-o", args.dst_file,
                     input_file_contexts_tmp]
    run_command(build_bin_cmd)


def traverse_folder_in_type(search_dir, file_suffix):
    """for special folder search_dir, find all files endwith file_suffix."""
    policy_file_list = []
    for root, _, files in os.walk(search_dir):
        for each_file in files:
            if each_file.endswith(file_suffix):
                policy_file_list.append(os.path.join(root, each_file))
    policy_file_list.sort()
    return " ".join(str(x) for x in policy_file_list)


def combine_file_contexts(file_contexts_list, combined_file_contexts):
    """combine all file_contexts."""
    cat_cmd = ["cat",
               file_contexts_list,
               ">", combined_file_contexts + "_tmp"]
    run_command(cat_cmd)

    grep_cmd = ["grep -v ^#",
                combined_file_contexts + "_tmp",
                "| grep -v ^$",
                ">", combined_file_contexts]
    run_command(grep_cmd)


def main(args):
    """build file_contexts.bin form all file_contexts files."""
    output_path = os.path.abspath(os.path.dirname(args.dst_file))

    file_contexts_list = traverse_folder_in_type(
        FILE_CONTEXTS_PATH, "file_contexts")

    combined_file_contexts = output_path + "/file_contexts"
    combine_file_contexts(file_contexts_list, combined_file_contexts)

    file_contexts_tmp = output_path + "/file_contexts.tmp"
    build_file_contexts_tmp(file_contexts_tmp, combined_file_contexts)

    build_file_contexts_bin(args, file_contexts_tmp)


if __name__ == "__main__":
    input_args = parse_args()
    main(input_args)
