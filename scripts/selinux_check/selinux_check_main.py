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
import json
import os
import subprocess


def read_json_file(input_file):
    data = None
    try:
        with open(input_file, 'r') as input_f:
            data = json.load(input_f)
    except json.decoder.JSONDecodeError:
        print("The file '{}' format is incorrect.".format(input_file))
        raise
    except:
        print("read file '{}' failed.".format(input_file))
        raise
    return data


def get_request_args(args, request):
    arg_list = request.split()
    request_args = []
    for arg in arg_list:
        if arg == "--file_contexts":
            request_args.append(arg)
            request_args.append(os.path.join(args.output_path, "file_contexts"))
    return request_args


def run_command(in_cmd):
    cmdstr = " ".join(in_cmd)
    ret = subprocess.run(cmdstr, shell=True).returncode
    if ret != 0:
        raise Exception(ret)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-path', help='the selinux compile output path', required=True)
    parser.add_argument('--source-root-dir', help='the project root path', required=True)
    parser.add_argument('--selinux-check-config', help='the selinux check config file path', required=True)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    check_config = read_json_file(os.path.join(args.source_root_dir, args.selinux_check_config))
    check_list = check_config.get("selinux_check")
    for check in check_list:
        script = os.path.join(args.source_root_dir, check.get("script"))
        cmd = ["python", script]
        request_args = get_request_args(args, check.get("args"))
        cmd.extend(request_args)
        extra_args = [check.get("extra_args")]
        cmd.extend(extra_args)
        run_command(cmd)
