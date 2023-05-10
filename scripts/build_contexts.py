#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
import re
import shutil
import subprocess
from collections import defaultdict


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--dst-dir', help='the output dest path', required=True)
    parser.add_argument('--tool-path',
                        help='the sefcontext_compile bin path', required=True)
    parser.add_argument('--policy-file',
                        help='the policy.31 file', required=True)
    parser.add_argument('--source-root-dir',
                        help='prj root path', required=True)
    parser.add_argument('--policy_dir_list',
                        help='policy dirs need to be included', required=True)
    parser.add_argument('--components',
                        help='system or vendor or default', required=True)
    return parser.parse_args()


def run_command(in_cmd):
    cmdstr = " ".join(in_cmd)
    ret = subprocess.run(cmdstr, shell=True).returncode
    if ret != 0:
        raise Exception(ret)


def traverse_folder_in_type(search_dir_list, file_suffix):
    """
    for special folder search_dir, find all files endwith file_suffix.
    :param search_dir: path to search
    :param file_suffix: postfix of file name
    :return: file list
    """
    flag = 0
    policy_file_list = []
    for item in search_dir_list:
        for root, _, files in os.walk(item):
            for each_file in files:
                file_name = os.path.basename(each_file)
                if file_name == file_suffix:
                    file_list_path = os.path.join(root, each_file)
                    flag |= check_contexts_file(file_list_path)
                    policy_file_list.append(file_list_path)
    if flag:
        raise Exception(flag)
    policy_file_list.sort()
    return " ".join(str(x) for x in policy_file_list)


def check_contexts_file(contexts_file):
    """
    Check the format of contexts file.
    :param contexts_file: list of te file
    :return:
    """
    err = 0
    lines = []
    with open(contexts_file, 'rb') as fp:
        lines = fp.readlines()
    if len(lines) == 0:
        return 0
    last_line = lines[-1]
    if b'\n' not in last_line:
        print("".join((contexts_file, " : need an empty line at end \n")))
        err = 1
    for line in lines:
        if line.endswith(b'\r\n') or line.endswith(b'\r'):
            print("".join((contexts_file, " : must be unix format\n")))
            err = 1
            break
    return err


def combine_contexts_file(file_contexts_list, combined_file_contexts):
    cat_cmd = ["cat",
               file_contexts_list,
               ">", combined_file_contexts + "_tmp"]
    run_command(cat_cmd)

    grep_cmd = ["grep -v ^#",
                combined_file_contexts + "_tmp",
                "| grep -v ^$",
                ">", combined_file_contexts]
    run_command(grep_cmd)


def check_redefinition(contexts_file):
    type_hash = defaultdict(list)
    err = 0
    with open(contexts_file, 'r') as contexts_read:
        pattern = re.compile(r'(\S+)\s+u:object_r:\S+:s0')
        line_index = 0
        for line in contexts_read:
            line_ = line.lstrip()
            line_index += 1
            if line_.startswith('#') or line_.strip() == '':
                continue
            match = pattern.match(line_)
            if match:
                type_hash[match.group(1)].append(line_index)
            else:
                print(contexts_file + ":" +
                      str(line_index) + " format check fail")
                err = 1
        contexts_read.close()
    if err:
        print("***********************************************************")
        print("please check whether the format meets the following rules:")
        print("[required format]: * u:object_r:*:s0")
        print("***********************************************************")
        raise Exception(err)
    err = 0
    for type_key in type_hash.keys():
        if len(type_hash[type_key]) > 1:
            err = 1
            str_seq = (contexts_file, ":")
            err_msg = "".join(str_seq)
            for linenum in type_hash[type_key]:
                str_seq = (err_msg, str(linenum), ":")
                err_msg = "".join(str_seq)
            str_seq = (err_msg, "'type ", str(type_key), " is redefinition'")
            err_msg = "".join(str_seq)
            print(err_msg)
    if err:
        raise Exception(err)


def check_common_contexts(args, contexts_file):
    """
    check whether context used in contexts_file is defined in policy.31.
    :param args:
    :param contexts_file: path of contexts file
    :return:
    """
    check_redefinition(contexts_file)

    check_cmd = [os.path.join(args.tool_path, "sefcontext_compile"),
                 "-o", contexts_file + ".bin",
                 "-p", args.policy_file,
                 contexts_file]
    run_command(check_cmd)
    if os.path.exists(contexts_file + ".bin"):
        os.unlink(contexts_file + ".bin")


def check_sehap_contexts(args, contexts_file, domain):
    """
    check domain or type defined in sehap_contexts.
    :param args:
    :param contexts_file: path of contexts file
    :param domain: true for domain, false for type
    :return:
    """
    shutil.copyfile(contexts_file, contexts_file + "_bk")
    err = 0
    with open(contexts_file + "_bk", 'r') as contexts_read, open(contexts_file, 'w') as contexts_write:
        pattern = re.compile(
            r'apl=(system_core|system_basic|normal)\s+((name|debuggable)=\S+\s+)?domain=(\S+)\s+type=(\S+)\s*\n')
        line_index = 0
        for line in contexts_read:
            line_ = line.lstrip()
            line_index += 1
            if line_.startswith('#') or line_.strip() == '':
                contexts_write.write(line)
                continue
            match = pattern.match(line_)
            if match:
                if domain:
                    line = match.group(1) + " u:r:" + match.group(4) + ":s0\n"
                else:
                    line = match.group(1) + " u:object_r:" + \
                        match.group(5) + ":s0\n"
                contexts_write.write(line)
            else:
                print(contexts_file + ":" +
                      str(line_index) + " format check fail")
                err = 1
        contexts_read.close()
        contexts_write.close()
    if err:
        shutil.move(contexts_file + "_bk", contexts_file)
        print("***********************************************************")
        print("please check whether the format meets the following rules:")
        print("[required format]: apl=* name=* domain=* type=*")
        print("apl=*, apl should be one of system_core|system_basic|normal")
        print("name=*, name is 'optional'")
        print("domain=*, hapdomain selinux type")
        print("type=*, hapdatafile selinux type")
        print("***********************************************************")
        raise Exception(err)
    check_cmd = [os.path.join(args.tool_path, "sefcontext_compile"),
                 "-o", contexts_file + ".bin",
                 "-p", args.policy_file,
                 contexts_file]
    ret = subprocess.run(" ".join(check_cmd), shell=True).returncode
    if ret != 0:
        shutil.move(contexts_file + "_bk", contexts_file)
        raise Exception(ret)
    shutil.move(contexts_file + "_bk", contexts_file)
    if os.path.exists(contexts_file + ".bin"):
        os.unlink(contexts_file + ".bin")


def build_file_contexts(args, output_path, policy_path):
    file_contexts_list = traverse_folder_in_type(
        policy_path, "file_contexts")

    combined_file_contexts = os.path.join(output_path, "file_contexts")
    combine_contexts_file(file_contexts_list, combined_file_contexts)

    build_tmp_cmd = ["m4",
                     "--fatal-warnings",
                     "-s", combined_file_contexts, ">", os.path.join(output_path, "file_contexts.tmp")]
    run_command(build_tmp_cmd)

    check_redefinition(combined_file_contexts)

    build_bin_cmd = [os.path.join(args.tool_path, "sefcontext_compile"),
                     "-o", os.path.join(args.dst_dir, "file_contexts.bin"),
                     "-p", args.policy_file,
                     os.path.join(output_path, "file_contexts.tmp")]
    run_command(build_bin_cmd)


def build_common_contexts(args, output_path, contexts_file_name, policy_path):
    contexts_list = traverse_folder_in_type(
        policy_path, contexts_file_name)

    combined_contexts = output_path + contexts_file_name
    combine_contexts_file(contexts_list, combined_contexts)

    check_common_contexts(args, combined_contexts)


def build_sehap_contexts(args, output_path, policy_path):
    contexts_list = traverse_folder_in_type(
        policy_path, "sehap_contexts")

    combined_contexts = os.path.join(output_path, "sehap_contexts")
    combine_contexts_file(contexts_list, combined_contexts)

    check_sehap_contexts(args, combined_contexts, 1)
    check_sehap_contexts(args, combined_contexts, 0)


def prepare_build_path(dir_list, root_dir, build_dir_list):
    build_contexts_list = ["base/security/selinux/sepolicy/base", "base/security/selinux/sepolicy/ohos_policy"]
    build_contexts_list += dir_list.split(":")

    for i in build_contexts_list:
        if i == "" or i == "default":
            continue
        path = os.path.join(root_dir, i)
        if (os.path.exists(path)):
            build_dir_list.append(path)
        else:
            print("following path not exists!! {}".format(path))
            exit(-1)


def traverse_folder_in_dir_name(search_dir, folder_suffix):
    folder_list = []
    for root, dirs, _ in os.walk(search_dir):
        for dir_i in dirs:
            if dir_i == folder_suffix:
                folder_list.append(os.path.join(root, dir_i))
    return folder_list


def build_all_file_contexts_bin(args, output_path, policy_path):
    file_contexts_list = traverse_folder_in_type(
        policy_path, "file_contexts")

    combined_file_contexts = os.path.join(output_path, "all_file_contexts")
    combine_contexts_file(file_contexts_list, combined_file_contexts)

    build_tmp_cmd = ["m4",
                     "--fatal-warnings",
                     "-s", combined_file_contexts, ">", os.path.join(output_path, "all_file_contexts.tmp")]
    run_command(build_tmp_cmd)

    build_bin_cmd = [os.path.join(args.tool_path, "sefcontext_compile"),
                     "-o", os.path.join(args.dst_dir, "file_contexts.bin"),
                     "-p", args.policy_file,
                     os.path.join(output_path, "all_file_contexts.tmp")]
    run_command(build_bin_cmd)


def main(args):
    output_path = args.dst_dir
    policy_path = []
    prepare_build_path(args.policy_dir_list, args.source_root_dir, policy_path)

    public_policy = []
    system_policy = []
    vendor_policy = []

    for item in policy_path:
        public_policy += traverse_folder_in_dir_name(item, "public")
        system_policy += traverse_folder_in_dir_name(item, "system")
        vendor_policy += traverse_folder_in_dir_name(item, "vendor")

    system_folder_list = public_policy + system_policy
    vendor_folder_list = public_policy + vendor_policy
    all_folder_list = public_policy + system_policy + vendor_policy

    if args.components == "system":
        build_file_contexts(args, output_path, system_folder_list)
        build_all_file_contexts_bin(args, output_path, all_folder_list)
    elif args.components == "vendor":
        build_file_contexts(args, output_path, vendor_folder_list)
        build_all_file_contexts_bin(args, output_path, all_folder_list)
    else:
        build_file_contexts(args, output_path, all_folder_list)

    build_common_contexts(args, output_path, "service_contexts", all_folder_list)
    build_common_contexts(args, output_path, "hdf_service_contexts", all_folder_list)
    build_common_contexts(args, output_path, "parameter_contexts", all_folder_list)
    build_sehap_contexts(args, output_path, all_folder_list)


if __name__ == "__main__":
    input_args = parse_args()
    main(input_args)
