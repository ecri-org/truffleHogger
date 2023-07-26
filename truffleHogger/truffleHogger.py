#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

import argparse
import ctypes
import datetime
import enum
import git
import hashlib
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile


def generate_charset(from_range, to_range):
    charset = []
    for ascii_code in range(from_range, to_range):
        charset.append(chr(ascii_code))

    return ''.join(charset)


# Will be merged with anything provided by the user.
SECRET_CHARSET = generate_charset(33, 127)
HEX_CHARS = "1234567890abcdefABCDEF"


def process_pattern_list(paths, pattern_list=[], comment='#'):
    for pattern in set(line[:-1].lstrip() for line in paths):
        if pattern and not pattern.startswith(comment):
            pattern_list.append(re.compile(pattern))
    return pattern_list


def load_regexes(args, file_path="regexes.json"):
    regexes = {}

    with open(os.path.join(os.path.dirname(__file__), file_path), 'r') as f:
        file = json.loads(f.read())
        for key, pattern in file.items():
            regexes[key] = re.compile(pattern)

    return regexes


class ExitCode(enum.Enum):
    FOUND_NONE = 0
    FOUND_ENTROPY = 1
    FOUND_REGEX = 2
    FOUND_ENTROPY_AND_REGEX = 3


def zero_out(variable):
    """
    Not a guarentee but we can at least try and zero out any memory we're not comfortable with.
    """
    strlen = len(variable)
    offset = sys.getsizeof(variable) - strlen - 1
    ctypes.memset(id(variable) + offset, 0, strlen)
    del variable


def mask(should_mask, value):
    """
    I normally don't like to use global, but we're passing vars all the way down multiple levels.
    If I were to rewrite this I'd consider a config object to pass params rather than all these
    vars.
    """
    masked_string_placeholder = "<masked-possible-password>"

    if should_mask:
        if isinstance(value, list):
            return [masked_string_placeholder for _ in value]
        return masked_string_placeholder
    else:
        return value


def exit_app(exit_code):
    sys.exit(exit_code.value)


def summary(args, output):
    # By default nothing found, simply exit.
    exit_code = ExitCode.FOUND_NONE

    if output["countEntropy"] > 0 and output["countRegex"] > 0:
        exit_code = ExitCode.FOUND_ENTROPY_AND_REGEX
    elif output["countEntropy"] > 0:
        exit_code = ExitCode.FOUND_ENTROPY
    elif output["countRegex"] > 0:
        exit_code = ExitCode.FOUND_REGEX

    output["countTotal"] = output["countEntropy"] + output["countRegex"]
    output['exitCode'] = {'name': exit_code.name, 'value': exit_code.value}

    if args.output_json and args.output_json_stream:
        # remove found_issues and output (as we streamed the results already)
        del output['foundIssues']

    if args.output_json:
        print(json.dumps(output, sort_keys=True))

    exit_app(exit_code)


def has_minified_whitespace(file_contents, threshold=0.08):
    whitespace_count = len(re.findall(r'\s', file_contents))

    if len(file_contents) <= 0:
        whitespace_ratio = 0
    else:
        whitespace_ratio = whitespace_count / len(file_contents)

    return whitespace_ratio < threshold


# Not accurate
def has_short_variable_names(file_contents, threshold_length=2):
    variable_names = re.findall(r'\b\w{1,' + str(threshold_length) + r'}\b', file_contents)
    return len(variable_names) > 0


# Not accurate, i.e. printing tables, though one should do it programmatically...
def has_repeated_characters(file_contents, threshold_repeats=5):
    repeated_chars = re.findall(r'(\S)\1{' + str(threshold_repeats - 1) + r',}', file_contents)
    return len(repeated_chars) > 0


# Not accurate
def has_short_string_literals(file_contents, threshold_length=3):
    string_literals = re.findall(r'["\'][\S\s]{1,' + str(threshold_length - 1) + r'}["\']', file_contents)
    return len(string_literals) > 0


# a very low threshold, where minified has hardly ANY
# i.e. values as low as 0.0008
def has_low_comment_ratio(file_contents, threshold=0.01, comment_patterns=None):
    # Combine all comment patterns into a single regex pattern
    # all_comment_patterns = '|'.join([f'({pattern})' for pattern in comment_patterns])
    # Combine all multi-line comment patterns into a single regex pattern
    # all_multi_line_comment_patterns = '|'.join([f'({pattern})' for pattern in multi_line_comment_patterns])
    comment_patterns_combined = [
        r'//(?!https?://|ftp://|sftp://).*',  # JavaScript, Java, C, C++
        r'(\'\'\'|""")[\s\S]*?\1',        # Python
        r'--.*',                          # SQL, Lua
        r'=begin[\s\S]*?=end',            # Ruby
        r'<!--.*?-->',                    # HTML/XML
        r'/\*[\s\S]*?\*/',                # Multi-line C Style
        r'#.*',                           # Bash/Shell, PHP, Single line Perl
        r'=pod[\s\S]*?=cut',              # Multi-line Perl POD comments
        r'(?<!\\)\#.*',                   # Single-line C-style comments in Perl
        r'\-\-\[\[\s\S]*?\]\]'            # Multi-line Lua comments
    ]

    if comment_patterns is None:
        comment_patterns = comment_patterns_combined

    # Combine all comment patterns into a single regex pattern
    all_comment_patterns = '|'.join([f'({pattern})' for pattern in comment_patterns_combined])

    # Remove all comments from the content
    content_without_comments = re.sub(all_comment_patterns, '', file_contents)

    if len(file_contents) <= 0:
        comment_ratio = 0
    else:
        # Calculate the ratio of comments to total characters
        comment_ratio = (len(file_contents) - len(content_without_comments)) / len(file_contents)

    # Check if the comment ratio is below the threshold
    # print(comment_ratio)
    return comment_ratio < threshold


def minified_source_map(file_contents, regex=r'.*js.map'):
    found = re.findall(regex, file_contents)
    return len(found) > 0


# Not accurate
def has_single_line_structure(file_contents, threshold_lines=2):
    line_count = len(file_contents.splitlines())
    return line_count <= threshold_lines


def has_single_line(file_contents):
    return len(file_contents.split('\n')) == 1


def has_long_single_first_line(file_contents, line_length_threshold=500):
    return len(file_contents.split('\n')[0]) > line_length_threshold


# try and ensure file_data is the entire file
def human_readable_code(args, file_contents):
    '''
    There are numerous ways to detect minified code, none and all would only give you an idea. The techniques below
    coupled with a generic regex rule we use above can help.

    Comment-to-Code Ratio: Minified code typically removes or significantly reduces the number of comments to reduce
    file size. One can check the ratio of comments to the total code length to identify whether the content might be minified.

    Whitespace Detection: Minified code often lacks whitespace characters, such as spaces, tabs, and line breaks.
    One can check for the presence of whitespace in the code. For example, you can count the number of whitespace
    characters and calculate the whitespace ratio.

    Variable Name Length: Minified code tends to use shorter variable and function names to reduce the file size.
    One can check if the code contains a significant number of single-character or very short variable names.

    Repeated Characters: Minified code might use repeated characters, such as ';;;;;' or '////'.
    One can check for the presence of multiple repeated characters in a row.

    Function Argument Names: Minified code may use shortened function argument names like 'a', 'b', 'c', etc.
    One can check for the prevalence of single-letter argument names.

    String Literal Length: Minified code often shortens string literals to save space.
    One can check if there are many very short string literals.

    Code Structure: Minified code is often written in a single line or has very few line breaks.
    One can check the number of lines in the code and the average length of the lines.
    '''

    # has_short_variable_names(file_contents),  # not accurate
    # has_repeated_characters(file_contents),   # not accurate
    # has_short_string_literals(file_contents), # not accurate
    # has_single_line_structure(file_contents), # not accurate
    structure_pattern = [
        has_minified_whitespace(file_contents),
        has_low_comment_ratio(file_contents),
        has_single_line(file_contents),
        has_long_single_first_line(file_contents, args.max_line_length),
        minified_source_map(file_contents)
    ]

    match structure_pattern:
        case [True, True, _, True]:       # no white space, low comments, and a long first line
            return False, structure_pattern
        case [True, True, False, False]:  # no white space, low comments, no single line attrs
            return False, structure_pattern
        case [True, _, _, True, _]:       # no white space, but has a long single line
            return False, structure_pattern
        case [_, _, True, True]:          # single line attrs
            return False, structure_pattern
        case [_, _, _, _, True]:          # has source map at end
            return False, structure_pattern
        case _:
            return True, structure_pattern


def display_info(args, path_inclusions, path_exclusions):
    if not args.output_json:
        labels = {
            "git_url": "Git Url",
            "human_readable_only": "Human Readable Only",
            "entropy_threshold": "Entropy Threshold",
            "max_line_length": "Max Line Length",
            "print_diff": "Print Diff",
            "mask_secrets": "Show Secrets"
        }

        max_label_length = max(len(label) for label in labels.values())

        msg = "---------------------------------------------------------------\n"
        for arg_name, label in labels.items():
            value = getattr(args, arg_name)
            msg += f"    {label.ljust(max_label_length)}: {value}\n"
        msg += f"    Path inclusions    : {[k for k in path_inclusions]}\n"
        msg += f"    Path exclusions    : {[k for k in path_exclusions]}\n"
        msg += "---------------------------------------------------------------\n"

        print(msg)


def read_file_entries(file, compiled_dict={}):
    try:
        with open(file, "r") as entryFile:
            compiled_dict = json.loads(entryFile.read())
            for entry in compiled_dict:
                compiled_dict[entry] = re.compile(compiled_dict[entry])
        return compiled_dict
    except (IOError, ValueError) as e:
        raise f'Error reading entry file {file}'


def main():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument('--json-streaming', dest="output_json_stream", action="store_true",
                        help="Output should be streaming when using json")
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable high signal regex checks")
    parser.add_argument("--rules", dest="rules", help="Ignore default regexes and source from json file")
    parser.add_argument("--allow", dest="allow", help="Explicitly allow regexes from json list file")
    parser.add_argument("--length_threshold", dest="length_threshold", type=int,
                        help="minimum length of any 'word' to be scanned for entropy. Default is [19].")
    parser.add_argument("--entropy", dest="do_entropy", help="Enable entropy checks")
    parser.add_argument("--entropy_threshold", type=float, dest="entropy_threshold",
                        help="desired threshold when using a typical password character set for randomness, "
                             "accepts values between 0.0 (low) and 8.0 (high). Default is [5.5].")
    parser.add_argument("--entropy_threshold_hex", type=float, dest="entropy_threshold_hex",
                        help="desired threshold when using hex code set for randomness, "
                             "accepts values between 0.0 (low) and 8.0 (high). Default is [3.0]")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth",
                        help="The max commit depth to go back when searching for secrets")
    parser.add_argument("--max_line_length_threshold", dest="max_line_length",
                        help="The max line length to consider, anything longer than this must not be human readable (minified code)")
    parser.add_argument("--branch", dest="branch", help="Name of the branch to be scanned")
    parser.add_argument('-i', '--include_paths', type=argparse.FileType('r'), metavar='INCLUDE_PATHS_FILE',
                        help='File with regular expressions (one per line), at least one of which must match a Git '
                             'object path in order for it to be scanned; lines starting with "#" are treated as '
                             'comments and are ignored. If empty or not provided (default), all Git object paths are '
                             'included unless otherwise excluded via the --exclude_paths option.')
    parser.add_argument('-x', '--exclude_paths', type=argparse.FileType('r'), metavar='EXCLUDE_PATHS_FILE',
                        help='File with regular expressions (one per line), none of which may match a Git object path '
                             'in order for it to be scanned; lines starting with "#" are treated as comments and are '
                             'ignored. If empty or not provided (default), no Git object paths are excluded unless '
                             'effectively excluded via the --include_paths option.')
    parser.add_argument("--repo_path", type=str, dest="repo_path",
                        help="Path to the cloned repo. If provided, git_url will not be used")
    parser.add_argument("--print-diff", dest="print_diff", action='store_true', help="Print the diff")
    parser.add_argument("--suppress-summary", dest="suppress_summary", action='store_true',
                        help="Suppress summary output (meant for ci/cd tools")
    parser.add_argument("--human-readable-only", dest="human_readable_only", action='store_true',
                        help="Try to only analyze human readable files - WARNING: VERY SLOW and sometimes not accurate")
    parser.add_argument("--show-hr-ignored-files", dest="show_hr_ignored_files", action='store_true',
                        help="Show files that are ignored as not human readable or files that don't pass our human readable tests")
    # The topic is 'mask_secrets', and the flag 'show-secrets' will mark mask_secrets as false,
    # otherwise we always mask secrets. It makes user interface flags easier to use.
    parser.add_argument("--show-secrets", dest="mask_secrets", action='store_false',
                        help="Do not mask secrets in any output")
    parser.add_argument("--color", dest="color", action='store_true',
                        help="Print console friendly colors.")

    parser.add_argument('git_url', type=str, help='URI to use use in the form of URI'
                                                  'such as https|git|file _OR_ local path (i.e. /some/path)')

    parser.set_defaults(do_regex=False)
    parser.set_defaults(rules={})
    parser.set_defaults(allow={})
    parser.set_defaults(max_depth=1000000)
    parser.set_defaults(max_line_length=500)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(length_threshold=20)
    parser.set_defaults(entropy=True)
    # parser.set_defaults(entropy_threshold_base64=4.5)
    parser.set_defaults(entropy_threshold=5.5)
    parser.set_defaults(entropy_threshold_hex=3.0)
    parser.set_defaults(branch=None)
    parser.set_defaults(repo_path=None)
    parser.set_defaults(print_diff=False)
    parser.set_defaults(mask_secrets=True)
    parser.set_defaults(output_json_stream=False)
    parser.set_defaults(suppress_summary=False)
    parser.set_defaults(human_readable_only=False)
    parser.set_defaults(show_hr_ignored_files=False)
    parser.set_defaults(color=False)
    parser.set_defaults(regexes={})

    path_inclusions = path_exclusions = []
    args = parser.parse_args()

    rules = allow = {}
    if args.do_regex:
        args.regexes = load_regexes(args, "regexes.json")
    if args.rules:  # when rules source regex from file, ignore ALL preset seeded rules
        rules = read_file_entries(args.rules, {})
        for regex in args.regexes.copy():
            del args.regexes[regex]
        args.regexes.update(rules)
    if args.allow:
        allow = read_file_entries(args.allow, {})
    if args.include_paths:
        path_inclusions = process_pattern_list(args.include_paths)
    if args.exclude_paths:
        path_exclusions = process_pattern_list(args.exclude_paths)
    else:
        path_exclusions = load_regexes(args, "ignore.json")

    display_info(args, path_inclusions, path_exclusions)

    output = find_strings(args,
                          args.git_url,
                          args.since_commit,
                          args.max_depth,
                          args.output_json,
                          args.do_regex,
                          str2bool(args.do_entropy),
                          branch=args.branch,
                          repo_path=args.repo_path,
                          path_inclusions=path_inclusions,
                          path_exclusions=path_exclusions,
                          allow=allow,
                          print_diff=args.print_diff,
                          output_json_stream=args.output_json_stream
                          )

    if not args.suppress_summary:
        summary(args, output)


def read_pattern(r):
    if r.startswith("regex:"):
        return re.compile(r[6:])
    converted = re.escape(r)
    converted = re.sub(r"((\\*\r)?\\*\n|(\\+r)?\\+n)+", r"( |\\t|(\\r|\\n|\\\\+[rn])[-+]?)*", converted)
    return re.compile(converted)


def str2bool(v):
    if v is None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    Returns a range between 0.0 and 8.0. Values close to 8.0 would indicate a high entropy,
    hence the likelihood of compressed or otherwise highly random data. Low values would
    indicate low complexity data such as text or executable instructions or any other
    data exhibiting clear patterns.
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    git.Repo.clone_from(git_url, project_path)
    return project_path


def print_results(args, issue, print_diff):
    if args.color:
        line_color_start = bcolors.OKGREEN
        line_color_end = bcolors.ENDC
    else:
        line_color_start = ''
        line_color_end = ''

    commit_time = issue['date']
    branch_name = issue['branch']
    prev_commit = issue['commit']
    printable_diff = issue['printDiff']
    commit_hash = issue['commitHash']
    lines_found = issue['linesFound']
    detailed_found = issue['detailedFound']
    if 'secretTypesFound' in issue.keys():
        secrettypes_found = issue['secretTypesFound']
    reason = issue['reason']
    path = issue['path']

    reason_str = f"{line_color_start}Reason: {reason}{line_color_end}"
    date_str = f"{line_color_start}Date: {commit_time}{line_color_end}"
    hash_str = f"{line_color_start}Hash: {commit_hash}{line_color_end}"
    file_path = f"{line_color_start}Filepath: {path}{line_color_end}"
    lines_str = f"{line_color_start}Lines: {lines_found}{line_color_end}"

    if args.mask_secrets:
        detail_str = f"{line_color_start}DetailedLines: <masked-possible-passwords> {line_color_end}"
    else:
        detail_str = f"{line_color_start}DetailedLines: {detailed_found}{line_color_end}"

    if sys.version_info >= (3, 0):
        branch_str = f"{line_color_start}Branch: {branch_name}{line_color_end}"
        commit_str = f"{line_color_start}Commit: {prev_commit}{line_color_end}".replace('\n', '')
        diff = printable_diff if print_diff else '<suppressed>'
        diff_str = f'{line_color_start}Diff: {diff}{line_color_end}'
    else:
        branch_str = f"{line_color_start}Branch: {branch_name.encode('utf-8')}{line_color_end}"
        commit_str = f"{line_color_start}Commit: {prev_commit.encode('utf-8')}{line_color_end}".replace('\n', '')
        diff = printable_diff.encode("utf-8") if print_diff else '<suppressed>'
        diff_str = f'{line_color_start}Diff: {diff}{line_color_end}'

    output = f'''
    {file_path}
        {reason_str}
        {date_str}
        {hash_str}
        {branch_str}
        {lines_str}
        {secrettypes_found if reason == 'Regex' else detail_str}
        {commit_str[0:65]}
        {diff_str}
    '''

    print(output)


def get_hunk_values(diff):
    curr_line = 0
    original_start = 0
    original_count = 0
    modified_start = 0
    index_correction = 1  # always count by 1
    hunk_line_numbers = re.findall(r'@@ [-+]?(\d+),(\d+)(?: ([-+]?\d+))?', diff)

    if hunk_line_numbers:
        original_start = abs(int(hunk_line_numbers[0][0]))
        original_count = abs(int(hunk_line_numbers[0][1]))
        modified_start = abs(int(hunk_line_numbers[0][2]))

    if original_start == original_count:  # file added
        prefix = '+'
    else:  # count removals
        prefix = '-'

    # pattern match here for strange cases
    # if f'{original_start},{original_count},{modified_start}' == '0,0,1':  # the case where 1 file, 1 line
    if (original_start, original_count, modified_start) == (0, 0, 1):  # the case where 1 file, 1 line
        index_correction = 0

    return curr_line, index_correction, original_start, original_count, prefix


def find_entropy(args, printable_diff, commit_time, branch_name, prev_commit, blob, file_path, print_diff):
    strings_found = []
    line_numbers_found = []
    entropy_values = []
    threshold = args.length_threshold
    curr_line, index_correction, original_start, original_count, prefix = get_hunk_values(printable_diff)

    for index, line in enumerate(printable_diff.split("\n")):
        if line.startswith(prefix) or line.startswith(' '):  # always count empty
            # the next line in the hunk is the start of the 0 index
            curr_line = (original_start - index_correction) + index

        for word in line.split():
            base64_strings = get_strings_of_set(word, SECRET_CHARSET, threshold)
            hex_strings = get_strings_of_set(word, HEX_CHARS, threshold)

            for string in base64_strings:
                entropy_value = shannon_entropy(string, SECRET_CHARSET)
                if entropy_value > args.entropy_threshold:
                    secret = mask(args.mask_secrets, string)
                    strings_found.append(secret)
                    entropy_values.append(entropy_value)
                    line_numbers_found.append(curr_line)
                    printable_diff = printable_diff.replace(
                        string,
                        bcolors.WARNING + mask(args.mask_secrets, string) + bcolors.ENDC
                    )
            for string in hex_strings:
                hex_entropy = shannon_entropy(string, HEX_CHARS)
                if hex_entropy > args.entropy_threshold_hex:
                    secret = mask(args.mask_secrets, string)
                    strings_found.append(secret)
                    entropy_values.append(entropy_value)
                    line_numbers_found.append(curr_line)
                    printable_diff = printable_diff.replace(
                        string,
                        bcolors.WARNING + mask(args.mask_secrets, string) + bcolors.ENDC
                    )

    if len(strings_found) > 0:
        entropic_diff = {}
        _commit = prev_commit.message
        entropic_diff['date'] = commit_time
        entropic_diff['path'] = file_path
        entropic_diff['branch'] = branch_name
        entropic_diff['commit'] = (_commit[:120] + '..') if len(_commit) > 120 else _commit
        # please rely on printDiff as that is masked
        # entropic_diff['diff'] = blob.diff.decode('utf-8', errors='replace')
        entropic_diff['stringsFound'] = strings_found  # already has masked strings, don't remask
        entropic_diff['linesFound'] = line_numbers_found  # lines where hits found
        entropic_diff['detailedFound'] = zipEntries(
            zipEntries(line_numbers_found, entropy_values),
            strings_found,
            False
        )
        entropic_diff['printDiff'] = printable_diff if print_diff else "<diff-suppressed>"
        entropic_diff['commitHash'] = prev_commit.hexsha
        entropic_diff['reason'] = "High Entropy"
        return entropic_diff

    return None


def zipEntries(lines, strings, annotate=True):
    zipped = zip(lines, strings)

    if annotate:
        return [f'L{x}:{y}' for x, y in zipped]

    return [f'{x}:{y}' for x, y in zipped]


def regex_check(args, printable_diff, commit_time, branch_name, prev_commit, blob, print_diff, file_path, custom_regexes={}):
    strings_found = []
    line_numbers_found = []
    regex_matches = []
    secret_types_found = []

    if custom_regexes:
        secret_regexes = custom_regexes
    else:
        secret_regexes = args.regexes

    curr_line, index_correction, original_start, original_count, prefix = get_hunk_values(printable_diff)

    for index, line in enumerate(printable_diff.split("\n")):
        if line.startswith(prefix) or line.startswith(' '):  # always count empty
            # the next line in the hunk is the start of the 0 index
            curr_line = (original_start - index_correction) + index

        for key in secret_regexes:
            found_strings = re.findall(secret_regexes[key], line)

            for found_string in found_strings:
                secret = mask(args.mask_secrets, found_string)
                found_diff = printable_diff.replace(printable_diff, bcolors.WARNING + secret + bcolors.ENDC)
                strings_found.append(secret)
                secret_types_found.append(key)
                line_numbers_found.append(curr_line)

    if len(strings_found) > 0:
        foundRegex = {}
        _commit = prev_commit.message
        foundRegex['date'] = commit_time
        foundRegex['path'] = file_path
        foundRegex['branch'] = branch_name
        foundRegex['commit'] = (_commit[:120] + '..') if len(_commit) > 120 else _commit
        # please rely on printDiff as that is masked
        # entropic_diff['diff'] = blob.diff.decode('utf-8', errors='replace')
        foundRegex['stringsFound'] = strings_found  # already has masked strings, don't remask
        foundRegex['linesFound'] = line_numbers_found  # lines where hits found
        foundRegex['secretTypesFound'] = zipEntries(
            zipEntries(line_numbers_found, secret_types_found),
            strings_found,
        )
        foundRegex['detailedFound'] = zipEntries(line_numbers_found, strings_found)
        foundRegex['printDiff'] = found_diff if print_diff else "<diff-suppressed>"
        foundRegex['commitHash'] = prev_commit.hexsha
        foundRegex['reason'] = "Regex"
        regex_matches.append(foundRegex)

    return regex_matches


def diff_worker(args,
                repo,
                diff,
                curr_commit,
                prev_commit,
                branch_name,
                commitHash,
                custom_regexes,
                do_entropy,
                do_regex,
                printJson,
                path_inclusions,
                path_exclusions,
                allow,
                print_diff,
                output_json_stream):
    issues = []
    count_entropy = 0
    count_regex = 0

    for blob in diff:
        found_issues = []
        printable_diff = blob.diff.decode('utf-8', errors='replace')
        file_path = blob.b_path if blob.b_path else blob.a_path

        if printable_diff.startswith("Binary files"):
            continue
        if not include_path(blob, path_inclusions, path_exclusions):
            continue

        # from here on, we try and get file contents
        repo_commit = repo.commit(prev_commit)
        repo_curr_commit = repo.commit(commitHash)

        if blob.deleted_file:
            file_contents = repo_commit.tree[file_path].data_stream.read().decode('utf-8', errors='replace')
        else:
            file_contents = repo_curr_commit.tree[file_path].data_stream.read().decode('utf-8', errors='replace')

        if args.human_readable_only:  # if user requests we determine human readable code ...
            is_human_readable, file_hr_signature = human_readable_code(args, file_contents)
            if not is_human_readable:
                binary_hr_signature = [int(x) for x in file_hr_signature]  # pattern signature for future stats
                if args.show_hr_ignored_files and not is_human_readable:
                    entropic_diff = {}
                    _commit = prev_commit.message
                    commit_time = datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
                    entropic_diff['date'] = commit_time
                    entropic_diff['path'] = file_path
                    entropic_diff['branch'] = branch_name
                    entropic_diff['commit'] = (_commit[:120] + '..') if len(_commit) > 120 else _commit
                    entropic_diff['printDiff'] = "<diff-suppressed>"
                    entropic_diff['commitHash'] = prev_commit.hexsha
                    entropic_diff['reason'] = "Ignored"
                    entropic_diff['hr-signature'] = binary_hr_signature

                    if printJson and output_json_stream:  # stream data if asked to
                        print(json.dumps(entropic_diff, sort_keys=True))
                    if not printJson:
                        print_results(args, found_issue, print_diff)
                continue

        for key in allow:
            printable_diff = allow[key].sub('', printable_diff)

        commit_time = datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')

        if do_entropy:
            entropic_diff = find_entropy(args,
                                         printable_diff,
                                         commit_time,
                                         branch_name,
                                         prev_commit,
                                         blob,
                                         file_path,
                                         print_diff)
            if entropic_diff:
                found_issues.append(entropic_diff)
                count_entropy += 1

        if do_regex:
            found_regexes = regex_check(args,
                                        printable_diff,
                                        commit_time,
                                        branch_name,
                                        prev_commit,
                                        blob,
                                        print_diff,
                                        file_path,
                                        custom_regexes)
            if len(found_regexes):
                found_issues += found_regexes
                count_regex += len(found_regexes)

        for found_issue in found_issues:
            if printJson and output_json_stream:
                print(json.dumps(found_issue, sort_keys=True))
            if not printJson:
                print_results(args, found_issue, print_diff)

        if len(found_issues) > 0:
            issues.extend(found_issues)

    return issues, count_entropy, count_regex


def include_path(blob, include_patterns=None, exclude_patterns=None):
    """Check if the diff blob object should included in analysis.

    If defined and non-empty, `include_patterns` has precedence over `exclude_patterns`, such that a blob that is not
    matched by any of the defined `include_patterns` will be excluded, even when it is not matched by any of the defined
    `exclude_patterns`. If either `include_patterns` or `exclude_patterns` are undefined or empty, they will have no
    effect, respectively. All blobs are included by this function when called with default arguments.

    :param blob: a Git diff blob object
    :param include_patterns: iterable of compiled regular expression objects; when non-empty, at least one pattern must
     match the blob object for it to be included; if empty or None, all blobs are included, unless excluded via
     `exclude_patterns`
    :param exclude_patterns: iterable of compiled regular expression objects; when non-empty, _none_ of the patterns may
     match the blob object for it to be included; if empty or None, no blobs are excluded if not otherwise
     excluded via `include_patterns`
    :return: False if the blob is _not_ matched by `include_patterns` (when provided) or if it is matched by
    `exclude_patterns` (when provided), otherwise returns True
    """
    path = blob.b_path if blob.b_path else blob.a_path
    if include_patterns and any([re.compile(exclude_patterns[k]).match(path) for k in include_patterns]):
        return False
    if exclude_patterns and any([re.compile(exclude_patterns[k]).match(path) for k in exclude_patterns]):
        return False

    return True


def find_strings(args,
                 git_url,
                 since_commit=None,
                 max_depth=1000000,
                 printJson=False,
                 do_regex=False,
                 do_entropy=True,
                 custom_regexes={},
                 branch=None,
                 repo_path=None,
                 path_inclusions=None,
                 path_exclusions=None,
                 allow={},
                 print_diff=True,
                 output_json_stream=False):
    output = {"foundIssues": [], "countEntropy": 0, "countRegex": 0}

    if repo_path:
        project_path = repo_path
    else:
        project_path = clone_git_repo(git_url)

    repo = git.Repo(project_path)
    already_searched = set()

    if branch:
        branches = repo.remotes.origin.fetch(branch)
    else:
        branches = repo.remotes.origin.fetch()

    for remote_branch in branches:
        since_commit_reached = False
        branch_name = remote_branch.name
        friendly_branch_name = f'origin/{branch}' if remote_branch.name == 'FETCH_HEAD' else remote_branch.name
        prev_commit = None

        for curr_commit in repo.iter_commits(branch_name, max_count=max_depth):
            commitHash = curr_commit.hexsha

            if commitHash == since_commit:
                since_commit_reached = True
                break

            # if not prev_commit, then curr_commit is the newest commit. And we have nothing to diff with.
            # But we will diff the first commit with NULL_TREE here to check the oldest code.
            # In this way, no commit will be missed.
            diff_hash = hashlib.md5((str(prev_commit) + str(curr_commit)).encode('utf-8')).digest()
            if not prev_commit:
                prev_commit = curr_commit
                continue
            elif diff_hash in already_searched:
                prev_commit = curr_commit
                continue
            else:
                diff = prev_commit.diff(curr_commit, create_patch=True)

            # avoid searching the same diffs
            already_searched.add(diff_hash)

            found_issues, count_entropy, count_regex = diff_worker(
                args,
                repo,
                diff,
                curr_commit,
                prev_commit,
                friendly_branch_name,
                commitHash,
                custom_regexes,
                do_entropy,
                do_regex,
                printJson,
                path_inclusions,
                path_exclusions,
                allow,
                print_diff,
                output_json_stream,
            )

            if len(found_issues) > 0:
                output['foundIssues'].extend(found_issues)
                output['countEntropy'] += count_entropy
                output['countRegex'] += count_regex

            prev_commit = curr_commit

        # Check if since_commit was used to check which diff should be grabbed
        if since_commit_reached:
            # Handle when there's no prev_commit (used since_commit on the most recent commit)
            if prev_commit is None:
                continue
            diff = prev_commit.diff(curr_commit, create_patch=True)
        else:
            diff = curr_commit.diff(git.NULL_TREE, create_patch=True)

        found_issues, count_entropy, count_regex = diff_worker(
            args,
            repo,
            diff,
            curr_commit,
            prev_commit,
            friendly_branch_name,
            commitHash,
            custom_regexes,
            do_entropy,
            do_regex,
            printJson,
            path_inclusions,
            path_exclusions,
            allow,
            print_diff,
            output_json_stream)

        if len(found_issues) > 0:
            output['foundIssues'].extend(found_issues)
            output['countEntropy'] += count_entropy
            output['countRegex'] += count_regex

    output['args'] = {
        "human_readable_only": args.human_readable_only,
        "entropy_threshold": args.entropy_threshold,
        "max_line_length": args.max_line_length,
        "print_diff": args.print_diff,
        "mask_secrets": args.mask_secrets,
        "git_url": args.git_url
    }

    if not repo_path:
        shutil.rmtree(project_path, onerror=del_rw)
    return output


if __name__ == "__main__":
    main()
