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

from check_common import *


class PolicyDb(object):
    def __init__(self, attributes_map, allow_map, class_map):
        self.attributes_map = attributes_map
        self.allow_map = allow_map
        self.class_map = class_map


def simplify_string(string):
    return string.replace('(', '').replace(')', '').replace('\n', '').strip()


def deal_with_allow(args, allow_map, attributes_map):
    with open(args.cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(allow ') and not line.startswith('(auditallow '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            # (allow A B (dir (getattr)))
            if len(elem_list) < 5:
                return
            scontext = elem_list[1]
            tcontext = elem_list[2]
            tclass = elem_list[3]
            perm = elem_list[4:]
            if scontext in attributes_map:
                for scon in attributes_map[scontext]:
                    # allow attribute self
                    if tcontext == 'self':
                        allow_map[(scon, scon)][tclass] += perm
                    # allow attribute attribute
                    elif tcontext in attributes_map:
                        for tcon in attributes_map[tcontext]:
                            allow_map[(scon, tcon)][tclass] += perm
                    # allow attribute type
                    else:
                        allow_map[(scon, tcontext)][tclass] += perm
            else:
                # allow type self
                if tcontext == 'self':
                    allow_map[(scontext, scontext)][tclass] += perm
                # allow type attribute
                elif tcontext in attributes_map:
                    for tcon in attributes_map[tcontext]:
                        allow_map[(scontext, tcon)][tclass] += perm
                # allow type type
                else:
                    allow_map[(scontext, tcontext)][tclass] += perm


def deal_with_typeattributeset(args, attributes_map):
    with open(args.cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(typeattributeset '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            attributes_map[elem_list[1]] += elem_list[2:]


def deal_with_class(args, class_map):
    with open(args.cil_file, 'r', encoding='utf-8') as cil_read:
        common_map = defaultdict(list)
        for line in cil_read:
            if not line.startswith('(common '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            common_map[elem_list[1]] += elem_list[2:]

    with open(args.cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(class '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) > 2:
                class_map[elem_list[1]] += elem_list[2:]

    with open(args.cil_file, 'r', encoding='utf-8') as cil_read:
        for line in cil_read:
            if not line.startswith('(classcommon '):
                continue
            sub_string = simplify_string(line)
            elem_list = sub_string.split(' ')
            if len(elem_list) < 3:
                continue
            class_map[elem_list[1]] += common_map[elem_list[2]]


def generate_database(args):
    attributes_map = defaultdict(list)
    class_map = defaultdict(list)
    allow_map = defaultdict(lambda: defaultdict(list))
    deal_with_typeattributeset(args, attributes_map)
    deal_with_allow(args, allow_map, attributes_map)
    deal_with_class(args, class_map)
    return PolicyDb(attributes_map, allow_map, class_map)


class CheckPermGroup(object):
    def __init__(self, check_class_list, check_perms):
        self.check_class_list = check_class_list
        self.check_perms = check_perms


def get_check_class_list(check_tclass, check_perms, class_map):
    if check_tclass == '*':
        check_class_list = []
        for tclass in class_map.keys():
            if set(check_perms) <= set(class_map[tclass]):
                check_class_list.append(tclass)
        return check_class_list
    return [check_tclass]


def get_perm_group_list(rule, class_map):
    check_perm_group_list = []
    perm_group_list = rule.get('perm_group')
    for perm_group in perm_group_list:
        check_tclass = perm_group.get('tclass')
        check_perms = perm_group.get('perm').split(' ')
        check_class_list = get_check_class_list(check_tclass, check_perms, class_map)
        check_perm_group_list.append(CheckPermGroup(check_class_list, check_perms))
    return check_perm_group_list


def check_perm_group(args, rule, policy_db, white_list):
    check_name = rule.get('name')
    check_perm_group_list = get_perm_group_list(rule, policy_db.class_map)
    contexts_list = []
    for item in white_list:
        if item.get('name') == check_name:
            contexts_list = item.get('contexts')

    non_exempt_violator_list = []
    violator_list = []
    for contexts in policy_db.allow_map.keys():
        check_result = 0
        for perm_group in check_perm_group_list:
            check_success = False
            for check_class in perm_group.check_class_list:
                if set(perm_group.check_perms) <= set(policy_db.allow_map[contexts][check_class]):
                    check_success = True
            if check_success:
                check_result += 1
        if check_result != len(check_perm_group_list):
            continue
        violater = ' '.join(contexts)
        # all violation list
        violator_list.append(violater)
        # if not in whitelist
        if violater not in contexts_list:
            non_exempt_violator_list.append(violater)

    if len(non_exempt_violator_list):
        print('\tcheck rule \'{}\' failed, {}'.format(check_name, rule.get('description')))
        print('\tviolation list (scontext tcontext):')
        for violation in non_exempt_violator_list:
            print('\t\t{}'.format(violation))
        print('\tThere are two solutions:\n',
              '\t1. Add the above list to whitelist file \'{}\'\n'.format(os.path.join(script_path, args.whitelist)),
              '\t2. Change the policy to avoid violating rule \'{}\'\n'.format(check_name))
        return True

    diff_list = list(set(contexts_list) - set(violator_list))
    if len(diff_list):
        print('\tcheck rule \'{}\' failed in whitelist file \'{}\'\n'.format(check_name,
              os.path.join(script_path, args.whitelist)),
              '\tremove the following unnecessary whitelists in rule \'{}\':'.format(check_name))
        for diff in diff_list:
            print('\t\t{}'.format(diff))
        return True
    return False


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--cil_file', help='the cil file path', required=True)
    parser.add_argument(
        '--whitelist', help='the whitelist file path', required=True)
    parser.add_argument(
        '--config', help='the config file path', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    script_path = os.path.dirname(os.path.realpath(__file__))
    white_list = read_json_file(os.path.join(script_path, args.whitelist)).get('whitelist')

    policy_db = generate_database(args)
    check_rules = read_json_file(os.path.join(script_path, args.config)).get('check_rules')
    check_result = False
    for rule in check_rules:
        check_result |= check_perm_group(args, rule, policy_db, white_list)
    if check_result:
        raise Exception(-1)
