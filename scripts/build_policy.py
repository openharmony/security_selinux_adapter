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
import subprocess
import tempfile
import shutil

# list of all macros and te for sepolicy build
SEPOLICY_TYPE_LIST = ["security_classes",
                      "initial_sids",
                      "access_vectors",
                      "glb_perm_def.spt",
                      "glb_never_def.spt",
                      "mls",
                      "policy_cap",
                      "glb_te_def.spt",
                      "attributes",
                      ".te",
                      "glb_roles.spt",
                      "users",
                      "initial_sid_contexts",
                      "fs_use",
                      "virtfs_contexts",
                      ]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--dst-file', help='the policy dest path', required=True)
    parser.add_argument('--tool-path',
                        help='the policy tool bin path', required=True)
    parser.add_argument('--source-root-dir',
                        help='prj root path', required=True)
    parser.add_argument('--policy_dir_list',
                        help='policy dirs need to be included', required=True)
    parser.add_argument('--debug-version',
                        help='build for debug target', required=True)
    parser.add_argument('--updater-version',
                        help='build for updater target', required=True)
    parser.add_argument('--components',
                        help='system or vendor or default', required=True)
    return parser.parse_args()


def traverse_folder_in_dir_name(search_dir, folder_suffix):
    folder_list = []
    for root, dirs, _ in os.walk(search_dir):
        for dir_i in dirs:
            if dir_i == folder_suffix:
                folder_list.append(os.path.join(root, dir_i))
    return folder_list


def traverse_folder_in_type(search_dir, file_suffix, build_root):
    policy_file_list = []
    flag = 0
    for root, _, files in os.walk(search_dir):
        for each_file in files:
            if each_file.endswith(file_suffix):
                path = os.path.join(root, each_file)
                rel_path = os.path.relpath(path, build_root)
                flag |= check_empty_row(rel_path)
                policy_file_list.append(rel_path)
    policy_file_list.sort()
    return " ".join(str(x) for x in policy_file_list), flag


def traverse_file_in_each_type(folder_list, sepolicy_type_list, build_root):
    policy_files = ""
    err = 0
    for policy_type in sepolicy_type_list:
        for folder in folder_list:
            str_tra, flag = traverse_folder_in_type(folder, policy_type, build_root)
            err |= flag
            str_seq = (policy_files, str_tra)
            policy_files = " ".join(str_seq)
    if err:
        raise Exception(err)
    return policy_files


def check_empty_row(policy_file_list):
    """
    Check whether the last line of te is empty.
    :param policy_file_list: list of te file
    :return:
    """
    err = 0
    with open(policy_file_list, 'r') as fp:
        lines = fp.readlines()
        if len(lines) != 0:
            last_line = lines[-1]
            if '\n' not in last_line:
                print(policy_file_list + " :" + " need an empty line at end \n")
                err = 1
    return err


def run_command(in_cmd):

    cmdstr = " ".join(in_cmd)
    ret = subprocess.run(cmdstr, shell=True).returncode
    if ret != 0:
        raise Exception(ret)


def build_conf(args, output_conf, input_policy_file_list):
    m4_args = "-D build_with_debug=" + args.debug_version + " "
    m4_args += "-D build_with_updater=" + args.updater_version + " "

    build_conf_cmd = ["m4",
                      "--fatal-warnings", m4_args,
                      "-s", input_policy_file_list, ">", output_conf]

    run_command(build_conf_cmd)


def build_cil(args, output_cil, input_conf):
    check_policy_cmd = [os.path.join(args.tool_path, "checkpolicy"),
                        input_conf,
                        "-M -C -c 31",
                        "-o " + output_cil]
    run_command(check_policy_cmd)


def build_policy(args, output_policy, vendor_cil, system_cil):
    build_policy_cmd = [os.path.join(args.tool_path, "secilc"),
                        vendor_cil,
                        system_cil,
                        "-m -M true -G -c 31",
                        "-f /dev/null",
                        "-o " + output_policy]
    run_command(build_policy_cmd)



def prepare_build_path(dir_list, root_dir, build_dir_list, sepolicy_path):
    build_policy_list = [os.path.join(sepolicy_path, "base"), os.path.join(sepolicy_path, "ohos_policy")]
    build_policy_list += dir_list.split(":")

    for i in build_policy_list:
        if i == "" or i == "default":
            continue
        path = os.path.join(root_dir, i)
        if (os.path.exists(path)):
            build_dir_list.append(path)
        else:
            print("following path not exists!! {}".format(path))
            exit(-1)


def filter_out(pattern_file, input_file):
    patterns = []
    patterns.extend(open(pattern_file).readlines())

    tmp_output = tempfile.NamedTemporaryFile()
    with open(input_file, 'r') as in_file:
        tmp_output.writelines(line.encode(encoding='utf-8') for line in in_file.readlines()
            if line not in patterns)
        tmp_output.write("\n".encode(encoding='utf-8'))
        tmp_output.flush()
    shutil.copyfile(tmp_output.name, input_file)


def generate_hash_file(input_file, output_file):
    build_policy_cmd = ["sha256sum",
                        input_file,
                        "| cut -d' ' -f1",
                        ">",
                        output_file]
    run_command(build_policy_cmd)


def main(args):
    output_path = os.path.abspath(os.path.dirname(args.dst_file))
    build_root = os.path.abspath(os.path.join(args.tool_path, "../../.."))
    sepolicy_path = os.path.join(args.source_root_dir, "base/security/selinux/sepolicy/")
    dir_list = []
    prepare_build_path(args.policy_dir_list, args.source_root_dir, dir_list, sepolicy_path)
    min_policy = [os.path.join(sepolicy_path, "min")]
    system_policy = []
    public_policy = []
    vendor_policy = []

    for item in dir_list:
        public_policy += traverse_folder_in_dir_name(item, "public")
        system_policy += traverse_folder_in_dir_name(item, "system")
        vendor_policy += traverse_folder_in_dir_name(item, "vendor")

    # list of all policy folders
    system_folder_list =  public_policy + system_policy
    vendor_folder_list =  public_policy + vendor_policy + min_policy

    # add temp dirs base/te folders
    system_folder_list.append(os.path.join(sepolicy_path, "base/te"))
    vendor_folder_list.append(os.path.join(sepolicy_path, "base/te"))

    # list of all policy files
    system_policy_file_list = traverse_file_in_each_type(system_folder_list, SEPOLICY_TYPE_LIST, build_root)
    vendor_policy_file_list = traverse_file_in_each_type(vendor_folder_list, SEPOLICY_TYPE_LIST, build_root)
    min_policy_file_list = traverse_file_in_each_type(min_policy, SEPOLICY_TYPE_LIST, build_root)

    system_output_conf = os.path.join(output_path, "system.conf")
    vendor_output_conf = os.path.join(output_path, "vendor.conf")
    min_output_conf = os.path.join(output_path, "min.conf")

    system_cil_path = os.path.join(output_path, "system.cil")
    vendor_cil_path = os.path.join(output_path, "vendor.cil")
    min_cil_path = os.path.join(output_path, "min.cil")

    # build system.conf
    build_conf(args, system_output_conf, system_policy_file_list)
    # build system.cil
    build_cil(args, system_cil_path, system_output_conf)

    if args.components == "system":
        system_cil_sha256 = os.path.join(output_path, "system.cil.sha256")
        generate_hash_file(system_cil_path, system_cil_sha256)

    elif args.components == "vendor":
        prebuild_sepolicy_system_cil_sha256 = os.path.join(output_path, "prebuild_sepolicy.system.cil.sha256")
        generate_hash_file(system_cil_path, prebuild_sepolicy_system_cil_sha256)

    # build vendor.conf
    build_conf(args, vendor_output_conf, vendor_policy_file_list)
    # build vendor.cil
    build_cil(args, vendor_cil_path, vendor_output_conf)

    # build min.conf
    build_conf(args, min_output_conf, min_policy_file_list)
    # build min.cil
    build_cil(args, min_cil_path, min_output_conf)

    filter_out(min_cil_path, vendor_cil_path)
    build_policy(args, args.dst_file, vendor_cil_path, system_cil_path)


if __name__ == "__main__":
    input_args = parse_args()
    main(input_args)
