#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import sys
import math
import datetime
from enum import Enum
import argparse
import uuid
import hashlib
import tempfile
import os
import re
import json
import stat
from git import Repo
from git import NULL_TREE

import ctypes

mask_secrets = True  # this can be removed later after migrating to args
regexes = {}


def load_regexes():
    regex_list = {}
    with open(os.path.join(os.path.dirname(__file__), "regexes.json"), 'r') as f:
        regex_list = json.loads(f.read())

    for key in regexes:
        regex_list[key] = re.compile(regex_list[key])

    return regex_list


class ExitCode(Enum):
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


def mask(value):
    """
    I normally don't like to use global, but we're passing vars all the way down multiple levels.
    If I were to rewrite this I'd consider a config object to pass params rather than all these
    vars.
    """
    global mask_secrets
    masked_string_placeholder = "<masked-possible-password>"

    if mask_secrets:
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

    print(json.dumps(output, sort_keys=True))

    exit_app(exit_code)


def main():
    global mask_secrets
    global regexes

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
    parser.add_argument("--entropy_threshold_base64", type=float, dest="entropy_threshold_base64",
                        help="desired threshold when using a base64 set for randomness, "
                             "accepts values between 0.0 (low) and 8.0 (high). Default is [4.5].")
    parser.add_argument("--entropy_threshold_hex", type=float, dest="entropy_threshold_hex",
                        help="desired threshold when using hex code set for randomness, "
                             "accepts values between 0.0 (low) and 8.0 (high). Default is [3.0]")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth",
                        help="The max commit depth to go back when searching for secrets")
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

    # The topic is 'mask_secrets', and the flag 'show-secrets' will mark mask_secrets as false,
    # otherwise we always mask secrets. It makes user interface flags easier to use.
    parser.add_argument("--show-secrets", dest="mask_secrets", action='store_false',
                        help="Do not mask secrets in any output")

    parser.add_argument('git_url', type=str, help='URI to use use in the form of URI'
                                                  'such as https|git|file _OR_ local path (i.e. /some/path)')

    parser.set_defaults(regex=False)
    parser.set_defaults(rules={})
    parser.set_defaults(allow={})
    parser.set_defaults(max_depth=1000000)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(length_threshold=20)
    parser.set_defaults(entropy=True)
    parser.set_defaults(entropy_threshold_base64=4.5)
    parser.set_defaults(entropy_threshold_hex=3.0)
    parser.set_defaults(branch=None)
    parser.set_defaults(repo_path=None)
    parser.set_defaults(print_diff=False)
    parser.set_defaults(mask_secrets=True)
    parser.set_defaults(output_json_stream=False)
    args = parser.parse_args()
    mask_secrets = args.mask_secrets

    if args.do_regex:
        regexes = load_regexes()

    rules = {}
    if args.rules:
        try:
            with open(args.rules, "r") as ruleFile:
                rules = json.loads(ruleFile.read())
                for rule in rules:
                    rules[rule] = re.compile(rules[rule])
        except (IOError, ValueError) as e:
            raise("Error reading rules file")

        for regex in dict(regexes):
            del regexes[regex]
        for regex in rules:
            regexes[regex] = rules[regex]
    allow = {}
    if args.allow:
        try:
            with open(args.allow, "r") as allowFile:
                allow = json.loads(allowFile.read())
                for rule in allow:
                    allow[rule] = read_pattern(allow[rule])
        except (IOError, ValueError) as e:
            raise("Error reading allow file")

    do_entropy = str2bool(args.do_entropy)

    # read & compile path inclusion/exclusion patterns
    path_inclusions = []
    path_exclusions = []
    if args.include_paths:
        for pattern in set(line[:-1].lstrip() for line in args.include_paths):
            if pattern and not pattern.startswith('#'):
                path_inclusions.append(re.compile(pattern))
    if args.exclude_paths:
        for pattern in set(line[:-1].lstrip() for line in args.exclude_paths):
            if pattern and not pattern.startswith('#'):
                path_exclusions.append(re.compile(pattern))

    output = find_strings(args,
                          args.git_url,
                          args.since_commit,
                          args.max_depth,
                          args.output_json,
                          args.do_regex,
                          do_entropy,
                          surpress_output=False,
                          branch=args.branch,
                          repo_path=args.repo_path,
                          path_inclusions=path_inclusions,
                          path_exclusions=path_exclusions,
                          allow=allow,
                          print_diff=args.print_diff,
                          output_json_stream=args.output_json_stream
                          )

    summary(args, output)


def read_pattern(r):
    if r.startswith("regex:"):
        return re.compile(r[6:])
    converted = re.escape(r)
    converted = re.sub(r"((\\*\r)?\\*\n|(\\+r)?\\+n)+", r"( |\\t|(\\r|\\n|\\\\+[rn])[-+]?)*", converted)
    return re.compile(converted)


def str2bool(v):
    if v == None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"


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
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
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
    Repo.clone_from(git_url, project_path)
    return project_path


def print_results(issue, print_diff):
    global mask_secrets

    commit_time = issue['date']
    branch_name = issue['branch']
    prev_commit = issue['commit']
    printable_diff = issue['printDiff']
    commit_hash = issue['commitHash']
    lines_found = issue['linesFound']
    detailed_found = issue['detailedFound']
    reason = issue['reason']
    path = issue['path']

    reason = f"{bcolors.OKGREEN}Reason: {reason}{bcolors.ENDC}"
    date_str = f"{bcolors.OKGREEN}Date: {commit_time}{bcolors.ENDC}"
    hash_str = f"{bcolors.OKGREEN}Hash: {commit_hash}{bcolors.ENDC}"
    file_path = f"{bcolors.OKGREEN}Filepath: {path}{bcolors.ENDC}"
    lines_str = f"{bcolors.OKGREEN}Lines: {lines_found}{bcolors.ENDC}"

    if mask_secrets:
        detail_str = f"{bcolors.OKGREEN}DetailedLines: <masked-possible-passwords> {bcolors.ENDC}"
    else:
        detail_str = f"{bcolors.OKGREEN}DetailedLines: {detailed_found}{bcolors.ENDC}"

    if sys.version_info >= (3, 0):
        branch_str = f"{bcolors.OKGREEN}Branch: {branch_name}{bcolors.ENDC}"
        commit_str = f"{bcolors.OKGREEN}Commit: {prev_commit}{bcolors.ENDC}".replace('\n', '')
        diff = printable_diff if print_diff else '<suppressed>'
        diff_str = f'{bcolors.OKGREEN}Diff: {diff}{bcolors.ENDC}'
    else:
        branch_str = f"{bcolors.OKGREEN}Branch: {branch_name.encode('utf-8')}{bcolors.ENDC}"
        commit_str = f"{bcolors.OKGREEN}Commit: {prev_commit.encode('utf-8')}{bcolors.ENDC}".replace('\n', '')
        diff = printable_diff.encode("utf-8") if print_diff else '<suppressed>'
        diff_str = f'{bcolors.OKGREEN}Diff: {diff}{bcolors.ENDC}'

    output = f'''
    ~~~~~~~~~~~~~~~~~~~~~
    {reason}
    {date_str}
    {hash_str}
    {file_path}
    {branch_str}
    {lines_str}
    {detail_str}
    {commit_str[0:65]}
    {diff_str}
    ~~~~~~~~~~~~~~~~~~~~~
    '''

    print(output)


def find_entropy(args, printable_diff, commit_time, branch_name, prev_commit, blob, print_diff):
    strings_found = []
    line_numbers_found = []
    threshold = args.length_threshold

    hunk_line_numbers = re.findall(r'@@ [-+]?(\d+),(\d+)', printable_diff)
    original_start = 0
    original_count = 0
    curr_line = 0

    if hunk_line_numbers:
        original_start = abs(int(hunk_line_numbers[0][0]))
        original_count = abs(int(hunk_line_numbers[0][1]))

    for index, line in enumerate(printable_diff.split("\n")):
        if original_start == original_count:  # file added
            prefix = '+'
        else:  # count removals
            prefix = '-'

        if line.startswith(prefix) or line.startswith(' '):  # always count empty
            curr_line = (original_start - 1) + index  # the next line in the hunk is the start of the 0 index

        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS, threshold)
            hex_strings = get_strings_of_set(word, HEX_CHARS, threshold)

            for string in base64_strings:
                b64_entropy = shannon_entropy(string, BASE64_CHARS)
                if b64_entropy > args.entropy_threshold_base64:
                    secret = mask(string)
                    strings_found.append(secret)
                    line_numbers_found.append(curr_line)
                    printable_diff = printable_diff.replace(string,
                                                            bcolors.WARNING + mask(string) + bcolors.ENDC)
            for string in hex_strings:
                hex_entropy = shannon_entropy(string, HEX_CHARS)
                if hex_entropy > args.entropy_threshold_hex:
                    secret = mask(string)
                    strings_found.append(secret)
                    line_numbers_found.append(curr_line)
                    printable_diff = printable_diff.replace(string,
                                                            bcolors.WARNING + mask(string) + bcolors.ENDC)

    if len(strings_found) > 0:
        entropic_diff = {}
        _commit = prev_commit.message
        entropic_diff['date'] = commit_time
        entropic_diff['path'] = blob.b_path if blob.b_path else blob.a_path
        entropic_diff['branch'] = branch_name
        entropic_diff['commit'] = (_commit[:120] + '..') if len(_commit) > 120 else _commit
        # please rely on printDiff as that is masked
        # entropic_diff['diff'] = blob.diff.decode('utf-8', errors='replace')
        entropic_diff['stringsFound'] = strings_found  # already has masked strings, don't remask
        entropic_diff['linesFound'] = line_numbers_found  # lines where hits found
        entropic_diff['detailedFound'] = zipEntries(line_numbers_found, strings_found)
        entropic_diff['printDiff'] = printable_diff if print_diff else "<diff-suppressed>"
        entropic_diff['commitHash'] = prev_commit.hexsha
        entropic_diff['reason'] = "High Entropy"
        return entropic_diff

    return None


def zipEntries(lines, strings):
    zipped = zip(lines, strings)
    return [f'L{x}:{y}' for x, y in zipped]


def regex_check(printable_diff, commit_time, branch_name, prev_commit, blob, print_diff, custom_regexes={}):
    strings_found = []
    line_numbers_found = []
    regex_matches = []

    if custom_regexes:
        secret_regexes = custom_regexes
    else:
        secret_regexes = regexes

    hunk_line_numbers = re.findall(r'@@ [-+]?(\d+),(\d+)', printable_diff)
    original_start = 0
    original_count = 0
    curr_line = 0

    if hunk_line_numbers:
        original_start = abs(int(hunk_line_numbers[0][0]))
        original_count = abs(int(hunk_line_numbers[0][1]))

    for index, line in enumerate(printable_diff.split("\n")):
        if original_start == original_count:  # file added
            prefix = '+'
        else:  # count removals
            prefix = '-'

        if line.startswith(prefix) or line.startswith(' '):  # always count empty
            curr_line = (original_start - 1) + index  # the next line in the hunk is the start of the 0 index

        for key in secret_regexes:
            found_strings = re.findall(secret_regexes[key], line)

            for found_string in found_strings:
                secret = mask(found_string)
                found_diff = printable_diff.replace(printable_diff, bcolors.WARNING + secret + bcolors.ENDC)
                strings_found.append(secret)
                line_numbers_found.append(curr_line)

    if len(strings_found) > 0:
        foundRegex = {}
        _commit = prev_commit.message
        foundRegex['date'] = commit_time
        foundRegex['path'] = blob.b_path if blob.b_path else blob.a_path
        foundRegex['branch'] = branch_name
        foundRegex['commit'] = (_commit[:120] + '..') if len(_commit) > 120 else _commit
        # please rely on printDiff as that is masked
        # entropic_diff['diff'] = blob.diff.decode('utf-8', errors='replace')
        foundRegex['stringsFound'] = strings_found  # already has masked strings, don't remask
        foundRegex['linesFound'] = line_numbers_found  # lines where hits found
        foundRegex['detailedFound'] = zipEntries(line_numbers_found, strings_found)
        foundRegex['printDiff'] = found_diff if print_diff else "<diff-suppressed>"
        foundRegex['commitHash'] = prev_commit.hexsha
        foundRegex['reason'] = "High Entropy"
        regex_matches.append(foundRegex)

    return regex_matches

def diff_worker(args,
                diff,
                curr_commit,
                prev_commit,
                branch_name,
                commitHash,
                custom_regexes,
                do_entropy,
                do_regex,
                printJson,
                surpress_output,
                path_inclusions,
                path_exclusions,
                allow,
                print_diff,
                output_json_stream):
    issues = []
    count_entropy = 0
    count_regex = 0

    for blob in diff:
        printable_diff = blob.diff.decode('utf-8', errors='replace')
        if printable_diff.startswith("Binary files"):
            continue
        if not path_included(blob, path_inclusions, path_exclusions):
            continue
        for key in allow:
            printable_diff = allow[key].sub('', printable_diff)

        commit_time = datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')

        found_issues = []

        if do_entropy:
            entropic_diff = find_entropy(args, printable_diff, commit_time, branch_name, prev_commit, blob, print_diff)
            if entropic_diff:
                found_issues.append(entropic_diff)
                count_entropy += 1

        if do_regex:
            found_regexes = regex_check(printable_diff, commit_time, branch_name, prev_commit, blob, print_diff, custom_regexes)
            if len(found_regexes):
                found_issues += found_regexes
                count_regex += len(found_regexes)

        if not surpress_output:
            for found_issue in found_issues:
                if printJson and output_json_stream:
                    print(json.dumps(found_issue, sort_keys=True))
                if not printJson:
                    print_results(found_issue, print_diff)

        if len(found_issues) > 0:
            issues.extend(found_issues)

    return issues, count_entropy, count_regex


def path_included(blob, include_patterns=None, exclude_patterns=None):
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
    if include_patterns and not any(p.match(path) for p in include_patterns):
        return False
    if exclude_patterns and any(p.match(path) for p in exclude_patterns):
        return False
    return True


def find_strings(args,
                 git_url,
                 since_commit=None,
                 max_depth=1000000,
                 printJson=False,
                 do_regex=False,
                 do_entropy=True,
                 surpress_output=True,
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

    repo = Repo(project_path)
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
                diff,
                curr_commit,
                prev_commit,
                friendly_branch_name,
                commitHash,
                custom_regexes,
                do_entropy,
                do_regex,
                printJson,
                surpress_output,
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
            diff = curr_commit.diff(NULL_TREE, create_patch=True)

        found_issues, count_entropy, count_regex = diff_worker(
            args,
            diff,
            curr_commit,
            prev_commit,
            friendly_branch_name,
            commitHash,
            custom_regexes,
            do_entropy,
            do_regex,
            printJson,
            surpress_output,
            path_inclusions,
            path_exclusions,
            allow,
            print_diff,
            output_json_stream)

        if len(found_issues) > 0:
            output['foundIssues'].extend(found_issues)
            output['countEntropy'] += count_entropy
            output['countRegex'] += count_regex

    output["cloneUri"] = git_url

    if not repo_path:
        shutil.rmtree(project_path, onerror=del_rw)
    return output


if __name__ == "__main__":
    main()
