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
import mmap
import os
import re
import shutil
import stat
import sys
import tempfile
import time


def generate_charset(from_range, to_range):
    charset = []
    for ascii_code in range(from_range, to_range):
        charset.append(chr(ascii_code))

    return ''.join(charset)


# Will be merged with anything provided by the user.
SECRET_CHARSET = generate_charset(33, 127)
HEX_CHARS = "1234567890abcdefABCDEF"


def process_pattern_list(paths, pattern_list=None, comment='#'):
    if pattern_list is None:
        pattern_list = []

    pattern_list = load_pattern_dict(paths.items())

    return pattern_list


def load_pattern_dict(items):
    regexes = {}

    for key, pattern in items:
        regexes[key] = re.compile(pattern, re.IGNORECASE)

    return regexes


def load_regexes(file_obj):
    regexes = {}

    file = json.loads(file_obj.read())
    regexes = load_pattern_dict(file.items())

    return regexes

def load_regex_file(args, file_path="regexes.json"):
    regexes = {}

    with open(os.path.join(os.path.dirname(__file__), file_path), 'r') as f:
        regexes = load_regexes(f)

    return regexes


class ExitCode(enum.Enum):
    FOUND_NONE = 0
    FOUND_ENTROPY = 1
    FOUND_REGEX = 2
    FOUND_ENTROPY_AND_REGEX = 3


def zero_out(variable):
    """
    Not a guarantee but we can at least try and zero out any memory we're not comfortable with.
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


def has_minified_whitespace(data):
    minified_whitespace_threshold = data['thresholds']['minified_whitespace_threshold']
    whitespace_count = data['stats']['whitespace_count']
    total_characters = data['stats']['total_characters']

    # Read the line from data
    line_str = data['line']

    # Calculate the number of whitespace characters in the line and update the count
    whitespace_count += len(re.findall(r'\s', line_str))
    # Update the total characters count with the length of the current line
    total_characters += len(line_str)
    whitespace_ratio = whitespace_count / total_characters

    # Update the pattern dictionary in the data with the updated counts
    data['stats']['whitespace_count'] = whitespace_count
    data['stats']['total_characters'] = total_characters
    data['stats']['whitespace_ratio'] = whitespace_ratio
    data['pattern']['has_minified_whitespace'] = whitespace_ratio < minified_whitespace_threshold

    return data


# a very low threshold, where minified has hardly ANY
# i.e. values as low as 0.0008
def has_low_comment_ratio(data, comment_patterns=None):
    threshold = data['thresholds']['low_comment_ratio_threshold']
    comment_count = data['stats']['comment_count']
    total_characters = data['stats']['total_characters']

    # Read the line from data
    line_str = data['line']

    # Update the total characters count with the length of the current line
    total_characters += len(line_str)

    # Calculate the number of comments in the line and update the count
    if comment_patterns is None:
        comment_patterns = [
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
    all_comment_patterns = '|'.join([f'({pattern})' for pattern in comment_patterns])
    comment_count += len(re.findall(all_comment_patterns, line_str))

    # Update the comment-related values in the data dictionary
    data['stats']['comment_count'] = comment_count
    data['stats']['total_characters'] = total_characters
    data['stats']['comment_ratio'] = comment_count / total_characters
    comment_ratio = (comment_count / total_characters) < threshold

    # Check if the comment ratio is below the threshold
    data['pattern']['has_low_comment_ratio'] = comment_ratio

    return data


def has_one_line(data):
    line_count = data['stats']['line_count']

    # Increment the line count
    line_count += 1

    # Update the line count in the data dictionary
    data['stats']['line_count'] = line_count

    # Check if the line count is greater than 1
    data['pattern']['has_single_line'] = line_count == 1

    return data


def has_long_line(data):
    threshold = data['thresholds']['line_length_threshold']
    curr_max_length = data['stats']['max_length']
    length = len(data['line'])

    if length > curr_max_length:
        data['stats']['max_length'] = length

    data['pattern']['has_long_line'] = length > threshold

    return data


def minified_source_map(data, regex=r'.*js.map'):
    found = data['stats']['minified_source_map']

    # Read the line from data
    line_str = data['line']

    # Check if the regex pattern is found in the current line
    found += len(re.findall(regex, line_str))

    # Update the 'found' count in the data dictionary
    data['stats']['minified_source_map'] = found

    # Check if 'found' is greater than 0
    data['pattern']['minified_source_map'] = found > 0

    return data


def seed_patterns(funcs):
    patterns = {}
    for fx in funcs:
        patterns[fx] = False
    return patterns


def get_new_data(funcs,
                 line_length_threshold=300,
                 minified_whitespace_threshold=0.04,
                 low_comment_ratio_threshold=0.01):
    return {
        'line': '',
        'thresholds': {
            'line_length_threshold': line_length_threshold,
            'minified_whitespace_threshold': minified_whitespace_threshold,
            'low_comment_ratio_threshold': low_comment_ratio_threshold,
        },
        'stats': {
            'line_count': 0,
            'first_line': None,
            'max_length': 0,
            'whitespace_count': 0,
            'whitespace_ratio': 0,
            'comment_ratio': 0,
            'comment_count': 0,
            'total_characters': 0,
            'minified_source_map': 0,
        },

        'pattern': seed_patterns(funcs)
    }


def get_pattern(data, funcs):
    return [data['pattern'][fx] for fx in funcs]


def process_file(args, tmp_file_path, funcs):
    data = get_new_data(funcs)
    line_threshold = data['thresholds']['line_length_threshold']

    with open(tmp_file_path, 'r') as file:
        with mmap.mmap(file.fileno(), length=0, access=mmap.ACCESS_READ) as file_mmap:
            for line in iter(file_mmap.readline, b''):
                line_str = line.decode('utf-8', errors='replace')
                data['line'] = line_str[0:(line_threshold * 2)]  # single line can be HUGE, limit it but grab enough
                data['stats']['line_count'] += 1

                # Trying to be runtime efficient, I've gone full-blown mutant with heavy mutation ...
                # Professor Xavier, where are you?
                # Why do it this way? The function list is shared with the pattern extractor
                [globals()[func_name](data) for func_name in funcs]
        file_mmap.close()
    return data


def human_readable_code(args, tmp_file_path):
    """
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
    """

    funcs = [
        'has_minified_whitespace',
        'has_low_comment_ratio',
        'has_one_line',
        'has_long_line',
        'minified_source_map',
    ]
    data = process_file(args, tmp_file_path, funcs)
    structure_pattern = get_pattern(data, funcs)

    match structure_pattern:
        case [True, True, _, True, _]:       # no white space, low comments, and a long first line
            return False, structure_pattern
        case [True, True, False, False, _]:  # no white space, low comments, no single line attrs
            return False, structure_pattern
        case [True, _, _, True, _]:          # no white space, but has a long single line
            return False, structure_pattern
        case [_, _, True, True, _]:          # single line attrs
            return False, structure_pattern
        case [_, _, _, _, True]:             # has source map at end
            return False, structure_pattern
        case _:                              # default case, file is human-readable
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


def read_file_entries(file, compiled_dict=None):
    if compiled_dict is None:
        compiled_dict = {}

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
    parser.add_argument('-i', '--include_paths', type=str, metavar='INCLUDE_PATHS_FILE',
                        help='JSON File with K:V entries, where the key is the description and value is a regex expression')
    parser.add_argument('-x', '--exclude_paths', type=str, metavar='EXCLUDE_PATHS_FILE',
                        help='JSON File with K:V entries, where the key is the description and value is a regex expression')
    parser.add_argument("--repo_path", type=str, dest="repo_path",
                        help="Path to the cloned repo. If provided, git_url will not be used")
    parser.add_argument("--print-diff", dest="print_diff", action='store_true', help="Print the diff")
    parser.add_argument("--suppress-summary", dest="suppress_summary", action='store_true',
                        help="Suppress summary output (meant for ci/cd tools")
    parser.add_argument("--human-readable-only", dest="human_readable_only", action='store_true',
                        help="Try to only analyze human readable files - WARNING: OK, not very accurate")
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
    parser.set_defaults(output_json=False)
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
        args.regexes = load_regex_file(args, "regexes.json")
    if args.rules:  # when rules source regex from file, ignore ALL preset seeded rules
        rules = read_file_entries(args.rules, {})
        for regex in args.regexes.copy():
            del args.regexes[regex]
        args.regexes.update(rules)
    if args.allow:
        allow = read_file_entries(args.allow, {})

    if args.include_paths:
        path_inclusions = load_regex_file(args, args.include_paths)

    if args.exclude_paths:
        path_exclusions = load_regex_file(args, args.exclude_paths)
    else:
        path_exclusions = load_regex_file(args, "ignore.json")

    display_info(args, path_inclusions, path_exclusions)

    output = find_strings(args=args,
                          git_url=args.git_url,
                          since_commit=args.since_commit,
                          max_depth=args.max_depth,
                          print_json=args.output_json,
                          do_regex=args.do_regex,
                          do_entropy=str2bool(args.do_entropy),
                          custom_regexes=args.regexes,
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
        secret_types_found = issue['secretTypesFound']
    else:
        secret_types_found = []

    reason = issue['reason']
    path = issue['path']

    if 'hrSignature' in issue.keys():
        hr_signature = issue['hrSignature']
        hr_signature_str = f"{line_color_start}Human readable score: {hr_signature}{line_color_end}"
    else:
        hr_signature_str = f"{line_color_start}Human readable score: n/a{line_color_end}"

    if 'elapsedTime' in issue.keys():
        elapsed_time = issue['elapsedTime']
        elapsed_time_str = f"{line_color_start}Evaluation elapsed time: {elapsed_time}{line_color_end}"
    else:
        elapsed_time_str = f"{line_color_start}Evaluation elapsed time: n/a{line_color_end}"

    if 'fileSize' in issue.keys():
        file_size = issue['fileSize']
        file_size_str = f"{line_color_start}File size: {file_size}{line_color_end}"
    else:
        file_size_str = f"{line_color_start}File size: n/a{line_color_end}"

    secret_types_found_str = f"{line_color_start}Detailed line numbers: {secret_types_found}{line_color_end}"
    reason_str = f"{line_color_start}Reason: {reason}{line_color_end}"
    date_str = f"{line_color_start}Date: {commit_time}{line_color_end}"
    hash_str = f"{line_color_start}Hash: {commit_hash}{line_color_end}"
    file_path_str = f"{line_color_start}File path: [{path}]{line_color_end}"
    lines_str = f"{line_color_start}Line numbers: {lines_found}{line_color_end}"

    if args.mask_secrets:
        detail_str = f"{line_color_start}Detailed line numbers: <masked-possible-passwords> {line_color_end}"
    else:
        detail_str = f"{line_color_start}Detailed lines numbers: {detailed_found}{line_color_end}"


    branch_str = f"{line_color_start}Branch: {branch_name}{line_color_end}"
    commit_str = f"{line_color_start}Commit message: {prev_commit[0:65].rstrip().lstrip()}{line_color_end}".replace('\n', '')
    diff = printable_diff if print_diff else '<suppressed>'
    diff_str = f'{line_color_start}Diff: {diff}{line_color_end}'

    output = f'''
    {file_path_str}
        {file_size_str}
        {reason_str}
        {hr_signature_str}
        {elapsed_time_str}
        {date_str}
        {hash_str}
        {branch_str}
        {lines_str}
        {secret_types_found_str if reason == 'Regex' else detail_str}
        {commit_str}
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
    if (original_start, original_count, modified_start) == (0, 0, 1):  # the case where 1 file, 1 line
        index_correction = 0

    return curr_line, index_correction, original_start, original_count, prefix


def zipEntries(lines, strings, annotate=True):
    zipped = zip(lines, strings)

    if annotate:
        return [f'L{x}:{y}' for x, y in zipped]

    return [f'{x}:{y}' for x, y in zipped]


def analyze_diff(args,
                 printable_diff,
                 commit_time,
                 branch_name,
                 commit,
                 blob,
                 file_path,
                 print_diff,
                 file_hr_signature,
                 file_size,
                 custom_regexes=None,
                 elapsed_time=0,
                 perform_entropy=True,
                 perform_regex=False):

    if custom_regexes is None:
        custom_regexes = {}

    entropy_results = {
        'strings_found': [],
        'line_numbers_found': [],
        'entropy_values': [],
    }

    regex_results = {
        'strings_found': [],
        'line_numbers_found': [],
        'secret_types_found': [],
    }

    found_diff = 'n/a'
    threshold = args.length_threshold

    for index, line in enumerate(printable_diff.split("\n")):
        curr_line, index_correction, original_start, original_count, prefix = get_hunk_values(line)

        if line.startswith(prefix) or line.startswith(' '):  # always count empty
            # the next line in the hunk is the start of the 0 index
            curr_line = (original_start - index_correction) + index

        if perform_entropy:
            for word in line.split():
                base64_strings = get_strings_of_set(word, SECRET_CHARSET, threshold)
                hex_strings = get_strings_of_set(word, HEX_CHARS, threshold)

                for string in base64_strings:
                    entropy_value = shannon_entropy(string, SECRET_CHARSET)
                    if entropy_value > args.entropy_threshold:
                        secret = mask(args.mask_secrets, string)

                        entropy_results['strings_found'].append(secret)
                        entropy_results['entropy_values'].append(entropy_value)
                        entropy_results['line_numbers_found'].append(curr_line)
                        entropy_results['printDiff'] = printable_diff if print_diff else "<diff-suppressed>"
                        printable_diff = printable_diff.replace(
                            string,
                            bcolors.WARNING + mask(args.mask_secrets, string) + bcolors.ENDC
                        )

                for string in hex_strings:
                    hex_entropy = shannon_entropy(string, HEX_CHARS)
                    if hex_entropy > args.entropy_threshold_hex:
                        secret = mask(args.mask_secrets, string)
                        entropy_results['strings_found'].append(secret)
                        entropy_results['entropy_values'].append(hex_entropy)
                        entropy_results['line_numbers_found'].append(curr_line)
                        entropy_results['printDiff'] = printable_diff if print_diff else "<diff-suppressed>"
                        printable_diff = printable_diff.replace(
                            string,
                            bcolors.WARNING + mask(args.mask_secrets, string) + bcolors.ENDC
                        )

        if perform_regex:
            for key in custom_regexes:
                found_strings = re.findall(custom_regexes[key], line)

                for found_string in found_strings:
                    if isinstance(found_string, tuple):
                        secret = mask(args.mask_secrets, ''.join(found_string))
                    else:
                        secret = mask(args.mask_secrets, line)

                    found_diff = printable_diff.replace(printable_diff, bcolors.WARNING + secret + bcolors.ENDC)
                    regex_results['printDiff'] = found_diff if print_diff else "<diff-suppressed>"
                    regex_results['strings_found'].append(secret)
                    regex_results['secret_types_found'].append(key)
                    regex_results['line_numbers_found'].append(curr_line)

    start_time = time.time()
    end_time = time.time()  # bulk of ops end here, record it
    diff_elapsed_time = end_time - start_time

    results = {}

    if perform_entropy and len(entropy_results['strings_found']) > 0:
        entropy_results['date'] = commit_time
        entropy_results['path'] = file_path
        entropy_results['branch'] = branch_name
        entropy_results['commit'] = commit.message[:120] + '..' if len(commit.message) > 120 else commit.message
        entropy_results['commitHash'] = commit.hexsha
        entropy_results['linesFound'] = entropy_results['line_numbers_found']
        entropy_results['detailedFound'] = zipEntries(entropy_results['line_numbers_found'], entropy_results['strings_found'])
        entropy_results['reason'] = "High Entropy"
        entropy_results['elapsedTime'] = f"hr:{elapsed_time:.6f}, diff:{diff_elapsed_time:.10f} seconds"
        entropy_results['hrSignature'] = file_hr_signature
        entropy_results['fileSize'] = f"{file_size} bytes"
        results['entropy'] = entropy_results

    if perform_regex and len(regex_results['strings_found']) > 0:
        regex_results['date'] = commit_time
        regex_results['path'] = file_path
        regex_results['branch'] = branch_name
        regex_results['commit'] = commit.message[:120] + '..' if len(commit.message) > 120 else commit.message
        regex_results['commitHash'] = commit.hexsha
        regex_results['linesFound'] = regex_results['line_numbers_found']
        regex_results['secretTypesFound'] = zipEntries(
            zipEntries(regex_results['line_numbers_found'], regex_results['secret_types_found']),
            regex_results['strings_found'], annotate=False
        )
        regex_results['detailedFound'] = zipEntries(regex_results['line_numbers_found'], regex_results['strings_found'])
        regex_results['reason'] = "Regex"
        regex_results['elapsedTime'] = f"hr:{elapsed_time:.6f}, diff:{diff_elapsed_time:.10f} seconds"
        regex_results['hrSignature'] = file_hr_signature
        regex_results['fileSize'] = f"{file_size} bytes"
        results['regex'] = regex_results

    return results

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
    file_hr_signature = 'n/a'
    binary_hr_signature = 'n/a'
    hr_signature_str = 'n/a'
    file_size = 0
    working_commit = None

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
        working_commit = prev_commit
        repo_curr_commit = repo.commit(commitHash)
        elapsed_time = 0

        if args.human_readable_only:  # if user requests we determine human readable code ...
            hr_start_time = time.time()  # start here as we want to include time it takes to write a tmp file
            with tempfile.TemporaryDirectory() as tmpdir:
                # Save the file from repo_commit to a temporary location
                tmp_file_path = os.path.join(tmpdir, os.path.basename(file_path))
                with open(tmp_file_path, 'w') as tmp_file:
                    if blob.deleted_file:
                        tmp_file.write(repo_commit.tree[file_path].data_stream.read().decode('utf-8', errors='replace'))
                        working_commit = repo_commit
                    else:
                        tmp_file.write(repo_curr_commit.tree[file_path].data_stream.read().decode('utf-8', errors='replace'))
                        working_commit = repo_curr_commit

                    tmp_file.flush()

                tmp_file.close()
                file_size = os.path.getsize(tmp_file_path)

                if file_size > 0:
                    is_human_readable, file_hr_signature = human_readable_code(args, tmp_file_path)
                    binary_hr_signature = [int(x) for x in file_hr_signature]  # pattern signature for future stats
                    hr_signature_str = f"{binary_hr_signature}, {is_human_readable}"

                    hr_end_time = time.time()  # bulk of ops end here, record it
                    elapsed_time = hr_end_time - hr_start_time

                    if not is_human_readable:
                        if args.show_hr_ignored_files:
                            entropic_diff = {}
                            commit_msg = working_commit.message
                            commit_time = datetime.datetime.fromtimestamp(working_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
                            entropic_diff['date'] = commit_time
                            entropic_diff['path'] = file_path
                            entropic_diff['branch'] = branch_name
                            entropic_diff['commit'] = (commit_msg[:120] + '..') if len(commit_msg) > 120 else commit_msg
                            entropic_diff['printDiff'] = "<diff-suppressed>"
                            entropic_diff['commitHash'] = working_commit.hexsha
                            entropic_diff['reason'] = "Ignored"
                            entropic_diff['hrSignature'] = hr_signature_str
                            entropic_diff['elapsedTime'] = f"hr:{elapsed_time:.6f} seconds"
                            entropic_diff['fileSize'] = f"{file_size} bytes"
                            entropic_diff['linesFound'] = 'n/a'
                            entropic_diff['detailedFound'] = 'n/a'

                            if printJson and output_json_stream:  # stream data if asked to
                                print(json.dumps(entropic_diff, sort_keys=True))
                            if not printJson:
                                print_results(args, entropic_diff, print_diff)

                        continue
                else:
                    continue

        for key in allow:
            printable_diff = allow[key].sub('', printable_diff)

        commit_time = datetime.datetime.fromtimestamp(working_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')

        # Perform both entropy analysis and regex matching
        results = analyze_diff(args=args,
                               printable_diff=printable_diff,
                               commit_time=commit_time,
                               branch_name=branch_name,
                               commit=working_commit,
                               blob=blob,
                               file_path=file_path,
                               print_diff=print_diff,
                               file_hr_signature=binary_hr_signature,
                               file_size=file_size,
                               custom_regexes=custom_regexes,
                               elapsed_time=elapsed_time,
                               perform_entropy=do_entropy,
                               perform_regex=do_regex
                               )

        entropic_diff = {}
        if 'entropy' in results.keys():
            entropic_diff = results['entropy']
            found_issues.append(entropic_diff)
            count_entropy += 1

        found_regexes = {}
        if 'regex' in results.keys():
            found_regexes = results['regex']
            found_issues.append(found_regexes)
            count_regex += len(found_regexes)

        # streaming
        for found_issue in found_issues:
            if printJson and output_json_stream:
                print(json.dumps(found_issue, sort_keys=True))
            if not printJson:
                print_results(args, found_issue, print_diff)

        if len(found_issues) > 0:
            issues.extend(found_issues)

    return issues, count_entropy, count_regex


def include_path(blob, include_patterns=None, exclude_patterns=None):
    """Check if the diff blob object should be included in analysis.

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

    if include_patterns and not any([re.compile(include_patterns[k]).match(path) for k in include_patterns]):
        return False
    if exclude_patterns and any([re.compile(exclude_patterns[k]).match(path) for k in exclude_patterns]):
        return False

    return True


def find_strings(args,
                 git_url,
                 since_commit=None,
                 max_depth=1000000,
                 print_json=False,
                 do_regex=False,
                 do_entropy=True,
                 custom_regexes=None,
                 branch=None,
                 repo_path=None,
                 path_inclusions=None,
                 path_exclusions=None,
                 allow=None,
                 print_diff=True,
                 output_json_stream=False):

    if allow is None:
        allow = {}

    if custom_regexes is None:
        custom_regexes = {}

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
        curr_commit = None
        prev_commit = None
        commitHash = None

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
                args=args,
                repo=repo,
                diff=diff,
                curr_commit=curr_commit,
                prev_commit=prev_commit,
                branch_name=friendly_branch_name,
                commitHash=commitHash,
                custom_regexes=custom_regexes,
                do_entropy=do_entropy,
                do_regex=do_regex,
                printJson=print_json,
                path_inclusions=path_inclusions,
                path_exclusions=path_exclusions,
                allow=allow,
                print_diff=print_diff,
                output_json_stream=output_json_stream,
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
            print_json,
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
