import unittest
import os
import sys
import json
import io
import re
from collections import namedtuple
from truffleHogger import truffleHogger


try:
    from mock import patch 
    from mock import MagicMock
except:
    from unittest.mock import patch
    from unittest.mock import MagicMock


class MockArg:
    def __init__(self, git_url,
                 color=False,
                 entropy_threshold=4.5,
                 entropy_threshold_hex=3,
                 length_threshold=20,
                 human_readable_only=False,
                 max_line_length=500,
                 print_diff=False,
                 mask_secrets=True):
        self.git_url = git_url
        self.entropy_threshold = entropy_threshold
        self.entropy_threshold_hex = entropy_threshold_hex
        self.length_threshold = length_threshold
        self.human_readable_only = human_readable_only
        self.max_line_length = max_line_length
        self.print_diff = print_diff
        self.mask_secrets = mask_secrets
        self.color = color


class TestStringMethods(unittest.TestCase):
    def test_regex(self):
        mock_arg = MockArg("test_repo")
        regexes = truffleHogger.load_regexes(mock_arg)
        # every one of these should match and if any did not, fail the test
        test_strings = [
            'sk_test_4eC39HqLyjWDarjtT1zdp7dc',
            'rk_test_4eC39HqLyjWDarjtT1zdp7dc',
            'ghp_000000000000000000000000000000000000',
            'ghp_ki4gI9AaxP1Tc53PEMmbv4d2NDzzez3fMWop'
            'gho_000000000000000000000000000000000000',
            'gho_ki4gI9AaxP1Tc53PEMmbv4d2NDzzez3fMWop'
            'ghu_000000000000000000000000000000000000',
            'ghu_ki4gI9AaxP1Tc53PEMmbv4d2NDzzez3fMWop'
            'ghs_000000000000000000000000000000000000',
            'ghs_ki4gI9AaxP1Tc53PEMmbv4d2NDzzez3fMWop'
            'ghr_000000000000000000000000000000000000',
            'ghr_ki4gI9AaxP1Tc53PEMmbv4d2NDzzez3fMWop'
        ]
        for test_string in test_strings:
            matches = 0
            for key in regexes:
                found_strings = re.findall(regexes[key], test_string)
                if len(found_strings) > 0:
                    # print(f"regex: {regexes[key]}, found:{found_strings}")
                    matches += 1
            if matches == 0:
                self.fail(f"Expected to find a regex match but could not for {test_string}")

    def test_shannon(self):
        random_stringB64 = "ZWVTjPQSdhwRgl204Hc51YCsritMIzn8B=/p9UyeX7xu6KkAGqfm3FJ+oObLDNEva"
        random_stringHex = "b3A0a1FDfe86dcCE945B72" 
        self.assertGreater(truffleHogger.shannon_entropy(random_stringB64, truffleHogger.SECRET_CHARSET), 4.5)
        self.assertGreater(truffleHogger.shannon_entropy(random_stringHex, truffleHogger.HEX_CHARS), 3)

    def test_cloning(self):
        project_path = truffleHogger.clone_git_repo("https://github.com/ecri-org/truffleHogger.git")
        license_file = os.path.join(project_path, "LICENSE")
        self.assertTrue(os.path.isfile(license_file))

    @patch('truffleHogger.truffleHogger.clone_git_repo')
    @patch('truffleHogger.truffleHogger.git.Repo')
    @patch('shutil.rmtree')
    def test_branch(self, rmtree_mock, repo_const_mock, clone_git_repo):
        repo = MagicMock()
        repo_const_mock.return_value = repo

        mock_arg = MockArg("test_repo")
        truffleHogger.find_strings(mock_arg, mock_arg.git_url, branch="testbranch")
        repo.remotes.origin.fetch.assert_called_once_with("testbranch")

    def test_path_included(self):
        Blob = namedtuple('Blob', ('a_path', 'b_path'))
        blobs = {
            'file-root-dir': Blob('file', 'file'),
            'file-sub-dir': Blob('sub-dir/file', 'sub-dir/file'),
            'new-file-root-dir': Blob(None, 'new-file'),
            'new-file-sub-dir': Blob(None, 'sub-dir/new-file'),
            'deleted-file-root-dir': Blob('deleted-file', None),
            'deleted-file-sub-dir': Blob('sub-dir/deleted-file', None),
            'renamed-file-root-dir': Blob('file', 'renamed-file'),
            'renamed-file-sub-dir': Blob('sub-dir/file', 'sub-dir/renamed-file'),
            'moved-file-root-dir-to-sub-dir': Blob('moved-file', 'sub-dir/moved-file'),
            'moved-file-sub-dir-to-root-dir': Blob('sub-dir/moved-file', 'moved-file'),
            'moved-file-sub-dir-to-sub-dir': Blob('sub-dir/moved-file', 'moved/moved-file'),
        }
        src_paths = set(blob.a_path for blob in blobs.values() if blob.a_path is not None)
        dest_paths = set(blob.b_path for blob in blobs.values() if blob.b_path is not None)
        all_paths = src_paths.union(dest_paths)
        all_paths_patterns = [re.escape(p) for p in all_paths]

        all_paths_patterns = {f'pattern_{i}': re.escape(p) for i, p in enumerate(all_paths)}

        overlap_patterns = {
            'pattern_01': r'sub-dir/.*',
            'pattern_02': r'moved/',
            'pattern_03': r'[^/]*file$'
        }

        sub_dirs_patterns = {
            'pattern_01': r'.+/.+'
        }

        deleted_paths_patterns = {
            'pattern_01': r'(.*/)?deleted-file$'
        }

        for name, blob in blobs.items():
            self.assertTrue(truffleHogger.include_path(blob),
                            '{} should be included by default'.format(blob))

            self.assertTrue(truffleHogger.include_path(blob, include_patterns=all_paths_patterns),
                            f'{blob} should be included with include_patterns: {all_paths_patterns}')

            self.assertFalse(truffleHogger.include_path(blob, exclude_patterns=all_paths_patterns),
                             '{} should be excluded with exclude_patterns: {}'.format(blob, all_paths_patterns))

            self.assertFalse(
                truffleHogger.include_path(blob,
                                           include_patterns=all_paths_patterns,
                                           exclude_patterns=all_paths_patterns),
                f'{blob} should be excluded with overlapping patterns: \n\tinclude: {all_paths_patterns}\n\texclude: {all_paths_patterns}')

            self.assertFalse(truffleHogger.include_path(blob,
                                                        include_patterns=overlap_patterns,
                                                        exclude_patterns=all_paths_patterns),
                             '{} should be excluded with overlapping patterns: \n\tinclude: {}\n\texclude: {}'.format(
                                 blob, overlap_patterns, all_paths_patterns))

            self.assertFalse(truffleHogger.include_path(blob,
                                                        include_patterns=all_paths_patterns,
                                                        exclude_patterns=overlap_patterns),
                             '{} should be excluded with overlapping patterns: \n\tinclude: {}\n\texclude: {}'.format(
                                 blob, all_paths_patterns, overlap_patterns))

            path = blob.b_path if blob.b_path else blob.a_path
            if '/' in path:
                self.assertTrue(truffleHogger.include_path(blob, include_patterns=sub_dirs_patterns),
                                '{}: inclusion should include sub directory paths: {}'.format(blob, sub_dirs_patterns))
                self.assertFalse(truffleHogger.include_path(blob, exclude_patterns=sub_dirs_patterns),
                                 '{}: exclusion should exclude sub directory paths: {}'.format(blob, sub_dirs_patterns))
            else:
                self.assertFalse(truffleHogger.include_path(blob, include_patterns=sub_dirs_patterns),
                                 '{}: inclusion should exclude root directory paths: {}'.format(blob, sub_dirs_patterns))
                self.assertTrue(truffleHogger.include_path(blob, exclude_patterns=sub_dirs_patterns),
                                '{}: exclusion should include root directory paths: {}'.format(blob, sub_dirs_patterns))
            if name.startswith('deleted-file-'):
                self.assertTrue(truffleHogger.include_path(blob, include_patterns=deleted_paths_patterns),
                                '{}: inclusion should match deleted paths: {}'.format(blob, deleted_paths_patterns))
                self.assertFalse(truffleHogger.include_path(blob, exclude_patterns=deleted_paths_patterns),
                                 '{}: exclusion should match deleted paths: {}'.format(blob, deleted_paths_patterns))



    @patch('truffleHogger.truffleHogger.clone_git_repo')
    @patch('truffleHogger.truffleHogger.git.Repo')
    @patch('shutil.rmtree')
    def test_repo_path(self, rmtree_mock, repo_const_mock, clone_git_repo):
        mock_arg = MockArg("test_repo")
        truffleHogger.find_strings(mock_arg, mock_arg.git_url, repo_path="test/path/")
        rmtree_mock.assert_not_called()
        clone_git_repo.assert_not_called()

if __name__ == '__main__':
    unittest.main()
