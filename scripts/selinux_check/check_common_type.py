#!/usr/bin/env python
# coding: utf-8

"""
Copyright (c) 2026 Huawei Device Co., Ltd.
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
from check_common import read_json_file, traverse_file_in_each_type

AUTH_RULE_NAMES = ("allow", "allowxperm", "auditallow", "auditallowxperm")
AUTH_RULE_PATTERN = re.compile(r'^\s*({})\b'.format("|".join(AUTH_RULE_NAMES)))
MACRO_CALL_PATTERN = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')
TOKEN_PATTERN = re.compile(r'-?[A-Za-z_][A-Za-z0-9_]*')
WHITELIST_FILE_NAME = "restricted_common_type_whitelist.txt"


def strip_comment(line):
    return line.split("#", 1)[0]


def normalize_rule_text(text):
    return " ".join(text.split())


def get_tokens(text):
    return [token.lstrip("-") for token in TOKEN_PATTERN.findall(text)]


def get_restricted_tokens(text, restricted_types):
    result = []
    for token in get_tokens(text):
        if token in restricted_types and token not in result:
            result.append(token)
    return result


def load_restricted_type_config(config_path):
    config = read_json_file(config_path)
    restricted_types = set(config.get("restricted_types", []))
    suggestions = config.get("suggestions", {})
    return restricted_types, suggestions


def get_restricted_type_config(args):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.join(script_dir, args.config)
    restricted_types, suggestions = load_restricted_type_config(config_path)

    extra_config_name = os.path.basename(args.config)
    extra_config_list = traverse_file_in_each_type(args.policy_dir_list, extra_config_name)
    for path in extra_config_list:
        extra_restricted_types, extra_suggestions = load_restricted_type_config(path)
        restricted_types.update(extra_restricted_types)
        suggestions.update(extra_suggestions)
    return restricted_types, suggestions


def get_rule_suggestions(restricted_tokens, suggestions):
    suggestion_list = []
    for token in restricted_tokens:
        if token in suggestions:
            suggestion_list.append("{} -> {}".format(token, suggestions[token]))
    return suggestion_list


def record_violation(violations, policy_file, line_no, rule_type, text, restricted_tokens):
    violations.append({
        "file": policy_file,
        "line": line_no,
        "rule_type": rule_type,
        "text": normalize_rule_text(text),
        "restricted_tokens": restricted_tokens,
    })


def collect_auth_rule(statement, start_line_no, policy_file, restricted_types, violations):
    restricted_tokens = get_restricted_tokens(statement, restricted_types)
    if restricted_tokens:
        rule_name = statement.strip().split(None, 1)[0]
        record_violation(violations, policy_file, start_line_no, rule_name, statement, restricted_tokens)


def clean_macro_body_text(text):
    return text.replace("`", " ").replace("'", " ").strip()


def collect_inline_policy_text(text, line_no, policy_file, restricted_types, violations):
    body = clean_macro_body_text(text)
    for statement in body.split(";"):
        statement = statement.strip()
        if not statement:
            continue
        if AUTH_RULE_PATTERN.match(statement):
            collect_auth_rule(statement + ";", line_no, policy_file, restricted_types, violations)
            continue
        collect_macro_calls(statement + ";", line_no, policy_file, restricted_types, violations)


def find_matching_right_paren(line, left_paren_index):
    depth = 0
    for index in range(left_paren_index, len(line)):
        if line[index] == "(":
            depth += 1
        elif line[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def collect_macro_calls(line, line_no, policy_file, restricted_types, violations):
    skip_until = -1
    for macro_match in MACRO_CALL_PATTERN.finditer(line):
        if macro_match.start() < skip_until:
            continue
        macro_name = macro_match.group(1)
        if macro_name in AUTH_RULE_NAMES:
            continue
        args_start = macro_match.end()
        left_paren_index = args_start - 1
        args_end = find_matching_right_paren(line, left_paren_index)
        if args_end == -1:
            args_text = line[args_start:]
            skip_until = len(line)
        else:
            args_text = line[args_start:args_end]
            skip_until = args_end + 1
        if macro_name.endswith("_only"):
            collect_inline_policy_text(args_text, line_no, policy_file, restricted_types, violations)
            continue
        restricted_tokens = get_restricted_tokens(args_text, restricted_types)
        if restricted_tokens:
            record_violation(violations, policy_file, line_no, macro_name, line.strip(), restricted_tokens)


def collect_violations_from_te(policy_file, restricted_types):
    violations = []
    in_auth_rule = False
    auth_rule_lines = []
    auth_rule_start_line = 0

    with open(policy_file, 'r', encoding='utf-8') as policy_read:
        for line_no, raw_line in enumerate(policy_read, 1):
            line = strip_comment(raw_line).strip()
            if not line:
                continue
            if in_auth_rule:
                auth_rule_lines.append(line)
                if ";" in line:
                    collect_auth_rule(" ".join(auth_rule_lines), auth_rule_start_line,
                                      policy_file, restricted_types, violations)
                    in_auth_rule = False
                    auth_rule_lines = []
                continue

            if AUTH_RULE_PATTERN.match(line):
                in_auth_rule = True
                auth_rule_start_line = line_no
                auth_rule_lines = [line]
                if ";" in line:
                    collect_auth_rule(line, line_no, policy_file, restricted_types, violations)
                    in_auth_rule = False
                    auth_rule_lines = []
                continue

            collect_macro_calls(line, line_no, policy_file, restricted_types, violations)

    if in_auth_rule:
        collect_auth_rule(" ".join(auth_rule_lines), auth_rule_start_line,
                          policy_file, restricted_types, violations)
    return violations


def collect_violations(policy_dir_list, restricted_types):
    violations = []
    for policy_file in traverse_file_in_each_type(policy_dir_list, ".te"):
        violations.extend(collect_violations_from_te(policy_file, restricted_types))
    return violations


def load_whitelist(policy_dir_list):
    whitelist = set()
    whitelist_files = traverse_file_in_each_type(policy_dir_list, WHITELIST_FILE_NAME)
    for whitelist_file in whitelist_files:
        with open(whitelist_file, 'r', encoding='utf-8') as whitelist_read:
            for line in whitelist_read:
                text = normalize_rule_text(strip_comment(line).strip())
                if text:
                    whitelist.add(text)
    return whitelist


def filter_whitelist(violations, whitelist):
    if not whitelist:
        return violations
    return [violation for violation in violations if violation["text"] not in whitelist]


def check_restricted_types(args, restricted_types, config_suggestions):
    violations = collect_violations(args.policy_dir_list, restricted_types)
    whitelist = load_whitelist(args.policy_dir_list)
    violations = filter_whitelist(violations, whitelist)
    if not violations:
        return False

    print("Check restricted type in te files failed.")
    print("The following te rules use restricted types directly:")
    for violation in violations:
        print("\t{}:{}: {}".format(
            violation["file"], violation["line"], violation["text"]))
        suggestion_list = get_rule_suggestions(violation["restricted_tokens"], config_suggestions)
        if suggestion_list:
            print("\t\tsuggestion: {}".format(", ".join(suggestion_list)))
    print("solution:")
    print("\t1. move the direct type in the rule to the corresponding attribute.")
    print("\t2. if the direct type must be kept, add the te rule text to {}.".format(WHITELIST_FILE_NAME))
    return True


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cil_file', help='unused, kept for compatibility', required=False)
    parser.add_argument('--developer_cil_file', help='unused, kept for compatibility', required=False)
    parser.add_argument('--config', help='the config file path', required=True)
    parser.add_argument('--policy-dir-list', help='policy dirs need to be included', required=True)
    return parser.parse_args()


if __name__ == '__main__':
    input_args = parse_args()
    restricted_types, suggestions = get_restricted_type_config(input_args)

    if check_restricted_types(input_args, restricted_types, suggestions):
        raise Exception(-1)
