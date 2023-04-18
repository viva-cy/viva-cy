#!/usr/bin/env python3
"""
    This script patches "ifx-mbedtls/tests/include/test/macros.h" file to add defines
    are needed for build ifx-mbedTLS test suites
"""

import os.path
import sys
import argparse
from copy import deepcopy
import json

# constants that are used as flags
NOT_DEFINED = -1  # value of variable is not defined and will define or will not be used
EOF = -2  # End-of-File: block has to be added to end of file
ALL = -1  # means that all found entries will be changed/replaced
ONLY_ONCE = -2

psa_import_gen_copy_data = {
    "path": None,
    "blocks": [],
    "find_replace_insert": [
        {
            # Applied by OR - when one of strings found
            "before_strings": [],
            # Applied by AND - when all strings found
            "after_strings": ["/* Helper Functions */"],
            "find": "psa_import_key",
            "replace": "",
            "insert_before": ["SET_SE_KEY_LOCATION(<@param#1@>);"],
            "insert_after": [""],
            "index": ALL  # ALL: all, x: sequence number of matches; ALL by default
        },
        {
            "after_strings": ["/* Helper Functions */"],
            "find": "psa_generate_key",
            "insert_before": ["SET_SE_KEY_LOCATION(<@param#1@>);"],
        },
        {
            "after_strings": ["/* Helper Functions */"],
            "find": "psa_copy_key",
            "insert_before": ["SET_SE_KEY_LOCATION(<@param#2@>);"],
        },
    ]
}

api_coverage_rule_templ = {
            "after_strings": ['ifx_se_status_t %s('],
            "find": "{",
            "insert_after": ['    printf("API_COVERAGE: %s\\n");'],
            "index": ONLY_ONCE
}

rules = {
    "macros.h": {
        "path": ["tests", "include", "test", "macros.h"],
        "blocks": [{
            "before_strings": ["/**"],
            "line_for_insertion": NOT_DEFINED,
            "block_to_insert": [
                "",
                "/* --- IFX streams defines ---*/",
                "#include <stdio.h>",
                "",
                "#undef stdin",
                "#define stdin  (FILE*)0x00u",
                "",
                "#undef stdout",
                "#define stdout (FILE*)0x01u",
                "",
                "#undef stderr",
                "#define stderr (FILE*)0x02u",
                "",
                "#define logout (FILE*)0x03u",
                "#define datain (FILE*)0x04u",
                "",
                "int ifx_test_fprintf( FILE *stream, const char * format, ... );",
                "int ifx_mbedtls_test_equal( const char *test, int line_no, const char* filename,",
                "                            unsigned long value1, unsigned long value2 );",
                "int ifx_mbedtls_test_le_u( const char *test, int line_no, const char* filename,",
                "                           unsigned long value1, unsigned long value2 );",
                "int ifx_mbedtls_test_le_s( const char *test, int line_no, const char* filename,",
                "                           long value1, long value2 );",
                "/* --- end of IFX streams defines ---*/",
            ],
            "block_to_insert_index": 1,
        }],
        "find_replace_insert": [
            {
                "find": "mbedtls_test_equal",
                "replace": "ifx_mbedtls_test_equal",
                "index": ALL  # ALL: all, x: sequence number of matches; ALL by default
            },
            {
                "find": "mbedtls_test_le_u",
                "replace": "ifx_mbedtls_test_le_u",
            },
            {
                "find": "mbedtls_test_le_s",
                "replace": "ifx_mbedtls_test_le_s",
            },
        ]
    },
    "test_suite_psa_crypto.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto.data": {
        "path": None,
        "blocks": [
            {
                "from_file": [
                    "ci", "build",
                    "mbedtls_ifx_testcases",
                    "ifx_test_suite_psa_crypto.data"],
                "before_strings": [],
                "line_for_insertion": EOF,
                "block_to_insert": [],
                "block_to_insert_index": 0,
            }
        ],
        "find_replace_insert": []
    },
    "test_suite_psa_crypto.function": {
        "path": None,
        "blocks": [
            {
                "from_file": [
                    "ci", "build",
                    "mbedtls_ifx_testcases",
                    "ifx_test_suite_psa_crypto.c"],
                "before_strings": [],
                "line_for_insertion": EOF,
                "block_to_insert": [],
                "block_to_insert_index": 2,
            }
        ],
        "find_replace_insert": []
    },
    "test_suite_psa_crypto_driver_wrappers.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_entropy.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_init.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_generate_key.generated.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_not_supported.generated.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_not_supported.misc.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_op_fail.generated.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_op_fail.misc.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_persistent_key.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_slot_management.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_storage_format.current.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_storage_format.misc.c": deepcopy(psa_import_gen_copy_data),
    "test_suite_psa_crypto_storage_format.v0.c": deepcopy(psa_import_gen_copy_data),
}


def add_api_coverage_rules(se_rt_utils_api_lists):
    """
    Adds rules for ifx_se_psacrypto and  ifx_se_platform to measure API coverage
    :param se_rt_utils_api_lists: API lists
    :return: number of added items
    """
    rules["ifx_se_psacrypto.c"] = {
        "path": None,
        "blocks": [
            {
                "after_strings": ['#include "cy_device.h"'],
                "block_to_insert": ['#include "stdio.h"'],
                "block_to_insert_index": 0,
            }
        ],
        "find_replace_insert": []
    }
    rules["ifx_se_platform.c"] = {
        "path": None,
        "blocks": [
            {
                "after_strings": ['#include "ifx_se_platform.h"'],
                "block_to_insert": ['#include "stdio.h"'],
                "block_to_insert_index": 0,
            }
        ],
        "find_replace_insert": []
    }
    add_counter = 0
    for api_name in se_rt_utils_api_lists.get("se_rt_utils_psacrypto_api_list", []):
        item = deepcopy(api_coverage_rule_templ)
        item["after_strings"][0] = item["after_strings"][0] % api_name
        item["insert_after"][0] = item["insert_after"][0] % api_name
        rules["ifx_se_psacrypto.c"]["find_replace_insert"].append(item)
        add_counter += 1

    for api_name in se_rt_utils_api_lists.get("se_rt_utils_platform_api_list", []):
        item = deepcopy(api_coverage_rule_templ)
        item["after_strings"][0] = item["after_strings"][0] % api_name
        item["insert_after"][0] = item["insert_after"][0] % api_name
        rules["ifx_se_platform.c"]["find_replace_insert"].append(item)
        add_counter += 1
    return add_counter


def does_contain(line, data_dict):
    """
    Check that strings exist in line
    :param line: line from file to search
    :param data_dict: srtings source
    :return: True if all srtings exist in line else False
    """
    ret = True
    strings = data_dict.get("before_strings", None)
    if strings is None:
        strings = data_dict.get("after_strings", None)
    if line.startswith(strings[0]):
        for i in range(1, len(strings)):
            ret = strings[i] in line
            if not ret:
                break
    else:
        return False
    return ret


def find_between(inp_string, first, last):
    """
    Finds and returns substring between first and last substrings in input_string
    :param inp_string: Input string
    :param first: First substring
    :param last: Last substring
    :return: substring between first and last substrings else empty strung
    """
    try:
        start = inp_string.index(first) + len(first)
        end = inp_string.index(last, start)
        return inp_string[start:end]
    except ValueError:
        return ""


def get_param_number(pattern):
    """
    Gets parameter number from pattern
    :param pattern: pattern to parse
    :return: Parameter number
    """
    # build dictionary with all possible patterns in format:
    # {"param#0": 0, "param#1": 1, ... }
    p_nums = {f"param#{i}": i-1 for i in range(10)}
    # get and return number (dict value by pattern)
    return p_nums.get(pattern, None)


def resolve_subst_string(ins_line, file_lines, file_index, find_pattern):
    """
    Resolves subst string in string
    :param ins_line:
    :param file_lines:
    :param file_index:
    :param find_pattern:
    :return:
    """
    # <@xxx@> in line to insert
    # 1st_param - first parameter of API in "find" pattern
    if "<@" not in ins_line and "@>" not in ins_line:
        return ins_line

    # collect full API call; ";" will be end-of-api-call
    line = file_lines[file_index]
    line = line[line.find(find_pattern)+len(find_pattern):]
    api_call = line.replace("\n", "")
    while ";" not in api_call:
        file_index += 1
        api_call += file_lines[file_index].replace("\n", "").strip()
    api_call = find_between(api_call, "(", ")").strip()
    params = api_call.split(",")
    pattern = find_between(ins_line, "<@", "@>")
    subst = f"<@{pattern}@>"
    p_num = get_param_number(find_between(ins_line, "<@", "@>"))
    ins_line = ins_line.replace(subst, params[p_num])
    return ins_line


def patch_file(rules_part):
    """
    Patches file
    :param rules_part: part of global rules structure related to taken file
    :return: 0 if success else 1
    """
    if not os.path.exists(rules_part['path']):
        print(f"File {rules_part['path']} does not exist!")
        return 1

    newline_char = ""
    with open(rules_part["path"], "r") as file:
        lines = file.readlines()
        newline_char = file.newlines

    # process "block" insertion
    for block in rules_part["blocks"]:
        already_patched = False
        # if rules_part for insertion is in file read it
        file_name = block.get("from_file", None)
        if file_name:
            file_name = os.path.join(*file_name)
            file_name = os.path.abspath(file_name)
            if not os.path.exists(file_name):
                print(f"File {file_name} does not exist!")
                continue
            with open(os.path.abspath(file_name), "rt") as from_file:
                block["block_to_insert"] = from_file.readlines()

        for i, line in enumerate(lines):
            # search not from first line
            if not i:
                continue
            if line.startswith(block["block_to_insert"][block["block_to_insert_index"]]):
                print(f"File {rules_part['path']} already patched with "
                      f"\"{block['block_to_insert'][block['block_to_insert_index']]}\"!")
                already_patched = True
                break
            if block.get("line_for_insertion", NOT_DEFINED) == NOT_DEFINED and \
                    does_contain(line, block):
                block["line_for_insertion"] = i - 1
                break

        if already_patched:
            continue

        if block.get("line_for_insertion", NOT_DEFINED) == EOF:
            block["line_for_insertion"] = len(lines)
            if not lines[-1].startswith(newline_char):
                block["block_to_insert"].insert(0, newline_char)

        if block.get("line_for_insertion", NOT_DEFINED) in [NOT_DEFINED, EOF]:
            strings = block.get('before_strings', None)
            if strings is None:
                strings = block.get('after_strings', None)
            print(f"Pattern \"{strings}\" not in file!")
            return 1

        for line in reversed(block["block_to_insert"]):
            lines.insert(block["line_for_insertion"], line +
                         (newline_char if not line.endswith(newline_char) else ""))
        print(f"{len(block['block_to_insert'])} lines added to {rules_part['path']}")

    # process find-replace-insert
    find_replaced_counter = 0
    for find_replace in rules_part["find_replace_insert"]:
        pattern = find_replace.get("find", None)
        subst = find_replace.get("replace", None)
        ins_before = find_replace.get("insert_before", [""])
        ins_after = find_replace.get("insert_after", [""])
        index = find_replace.get("index", ALL)

        before_strings = find_replace.get("before_strings", None)
        after_strings = find_replace.get("after_strings", None)

        if not pattern or not (subst or ins_before or ins_after):
            continue
        skip_next_lines = 0
        for i, line in enumerate(lines):
            if skip_next_lines:
                skip_next_lines -= 1
                continue
            if after_strings:
                for a_str in after_strings:
                    if a_str in line:
                        after_strings.remove(a_str)
                continue
            if before_strings:
                finish = False
                for b_str in before_strings:
                    if b_str in line:
                        finish = True
                if finish:
                    break

            if pattern in line:
                if index != ALL and index != ONLY_ONCE and i != index:
                    continue
                if subst:
                    if subst in line:  # already patched
                        if index != ALL:
                            break
                        else:
                            continue
                    lines[i] = lines[i].replace(pattern, subst)
                    find_replaced_counter += 1
                    if index != ALL:
                        break
                if ins_before[0]:
                    # check for already patched
                    if ins_before[0][:ins_before[0].find("<@")] in lines[i-1]:
                        if index != ALL:
                            break
                        else:
                            continue
                    ws_cnt = len(line) - len(line.lstrip())
                    for ins_l in ins_before:
                        ins_l = resolve_subst_string(ins_l, lines, i, pattern)
                        lines.insert(i, " "*ws_cnt + ins_l + "\n")
                        find_replaced_counter += 1
                    skip_next_lines += len(ins_before)
                    if index != ALL:
                        break
                if ins_after[0]:
                    # check for already patched
                    if ins_after[0][:ins_after[0].find("<@")] in lines[i+1]:
                        if index != ALL:
                            break
                        else:
                            continue
                    ws_cnt = len(line) - len(line.lstrip())
                    for ins_l in ins_after:
                        lines.insert(i+1, " "*ws_cnt + ins_l + "\n")
                        find_replaced_counter += 1
                    skip_next_lines += len(ins_after)
                    if index != ALL:
                        break
    if find_replaced_counter:
        print(f"{find_replaced_counter} blocks added/updated to/in {rules_part['path']}")

    with open(rules_part['path'], "w", newline=newline_char) as file:
        file.writelines(lines)
    return 0


def main():
    """
    Main function
    :return: None
    """
    # Contains part to "tests" folder include "tests"
    path_to_tests_root = "../../tests"

    parser = argparse.ArgumentParser(description='Patches macros.h file')
    parser.add_argument('path', type=str, default="", nargs='?',
                        help='Path to file')
    parser.add_argument('--api-list', type=str, default="",
                        help='Path to se-rt-utils list (JSON file)')
    args = parser.parse_args()
    print(f"{args}")
    if args.path:
        path_to_tests_root = os.path.abspath(args.path)
    if args.api_list and os.path.exists(args.api_list):
        with open(args.api_list, "rt", encoding="utf-8") as j_file:
            try:
                se_rt_utils_api_lists = json.load(j_file)
                item_num = add_api_coverage_rules(se_rt_utils_api_lists)
                print(f"Added {item_num} rules from \"{args.api_list}\" file.")
            except Exception as exc:
                print('Exception during load "%s" file:\n\t%s', args.api_list, exc)
                exit(1)
    if not os.path.exists(path_to_tests_root):
        print(f"File '{path_to_tests_root}' does NOT exists")
        sys.exit(1)
    f_name = os.path.basename(path_to_tests_root)
    config = rules.get(f_name, None)
    if not config:
        print(f"No rules to update file '{path_to_tests_root}'")
        sys.exit(1)
    rules[f_name]["path"] = path_to_tests_root
    ret = patch_file(rules[f_name])

    sys.exit(ret)


if __name__ == '__main__':
    main()
