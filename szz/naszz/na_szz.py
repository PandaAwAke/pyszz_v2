import json
import os
import logging as log
import platform
import subprocess
from typing import Set, List

from git import Commit

from options import Options
from szz.core.abstract_szz import DetectLineMoved, LineChangeType
from szz.ra_szz import RASZZ


class NASZZ(RASZZ):
    """
    New-line Aware SZZ
    """

    def __init__(self, repo_full_name: str, repo_url: str, repos_dir: str = None):
        self.repo_full_name = repo_full_name
        self.repos_dir = repos_dir
        super().__init__(repo_full_name, repo_url, repos_dir)

    def _extract_method_history(self, commit: str, file_path: str, method_name: str,
                                method_declaration_line: str | int):
        if platform.system() == 'Windows':
            PATH_TO_CODE_TRACKER = os.path.join(Options.PYSZZ_HOME, 'tools/CodeTracker-2.7/bin/CodeTracker.bat')
        else:
            PATH_TO_CODE_TRACKER = os.path.join(Options.PYSZZ_HOME, 'tools/CodeTracker-2.7/bin/CodeTracker')

        log.info(f'Running CodeTracker on {commit}, {file_path + "#" + method_name}')
        cmd = [
            PATH_TO_CODE_TRACKER,
            '-r', self._repository_path,
            '-c', commit,
            '-f', file_path,
            '-m', method_name,
            '-l', str(method_declaration_line)
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        if not result:
            return {"commits": []}
        else:
            return json.loads(result.stdout)

    def _extract_commit_file_ast_mapping(self, commit: str, file_paths: List[str], algorithm: str = 'gt'):
        if platform.system() == 'Windows':
            PATH_TO_AST_MAPPING = os.path.join(Options.PYSZZ_HOME, 'tools/ICSE2021AstMapping/bin/AstMapping.bat')
        else:
            PATH_TO_AST_MAPPING = os.path.join(Options.PYSZZ_HOME, 'tools/ICSE2021AstMapping/bin/AstMapping')

        log.info(f'Running ICSE2021 Ast Mapping on {commit}, {file_paths}')
        cmd = [
            PATH_TO_AST_MAPPING,
            '-a', algorithm,
            '-p', self.repos_dir,
            '-n', self.repo_full_name,
            '-c', commit,
            '-f', ','.join(file_paths)
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        if not result:
            return []
        else:
            return json.loads(result.stdout)

    def _extract_file_def_use(self, file_path: str):
        if platform.system() == 'Windows':
            PATH_TO_TINY_PDG = os.path.join(Options.PYSZZ_HOME, 'tools/TinyPDG/bin/TinyPDG.bat')
        else:
            PATH_TO_TINY_PDG = os.path.join(Options.PYSZZ_HOME, 'tools/TinyPDG/bin/TinyPDG')

        log.info(f'Running TinyPDG on {file_path}')
        cmd = [
            PATH_TO_TINY_PDG,
            '-t', 'ddg',
            '-f', file_path,
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        if not result:
            return []
        else:
            return json.loads(result.stdout)

    def start(self, fix_commit_hash: str, commit_issue_date, **kwargs) -> Set[Commit]:
        file_ext_to_parse = kwargs.get('file_ext_to_parse')
        only_deleted_lines = False
        ignore_revs_file_path = kwargs.get('ignore_revs_file_path')
        max_change_size = kwargs.get('max_change_size')
        issue_date_filter = kwargs.get('issue_date_filter')
        detect_move_within_file = kwargs.get('detect_move_within_file', None)
        filter_revert_commits = kwargs.get('filter_revert_commits', False)

        detect_move_from_other_files = kwargs.get('detect_move_from_other_files', None)
        if detect_move_from_other_files:
            detect_move_from_other_files = DetectLineMoved(detect_move_from_other_files)

        assert kwargs.get('defuse_chain_radius') >= 0, "defuse_chain_radius param must be >= 0"
        distance_radius = kwargs['defuse_chain_radius']
        log.info("using def-use chain graph distance radius: {}".format(distance_radius))

        imp_files = self.get_impacted_files(fix_commit_hash, file_ext_to_parse, only_deleted_lines)

        # process impacted files with deleted lines
        imp_files_delete = [f for f in imp_files if f.line_change_type == LineChangeType.DELETE]
        bic_found = super().find_bic(fix_commit_hash=fix_commit_hash,
                                     impacted_files=imp_files_delete,
                                     ignore_revs_file_path=ignore_revs_file_path,
                                     max_change_size=max_change_size,
                                     detect_move_within_file=detect_move_within_file,
                                     detect_move_from_other_files=detect_move_from_other_files,
                                     issue_date_filter=issue_date_filter,
                                     issue_date=commit_issue_date,
                                     filter_revert_commits=filter_revert_commits)

        # # process impacted files with added lines
        # impacted_files_duchain = self._process_impacted_files(fix_commit_hash, imp_files, distance_radius)
        # bic_found.update(super().find_bic(blame_rev_pointer='HEAD',
        #                                   fix_commit_hash=fix_commit_hash,
        #                                   impacted_files=impacted_files_duchain,
        #                                   ignore_revs_file_path=ignore_revs_file_path,
        #                                   max_change_size=max_change_size,
        #                                   detect_move_within_file=detect_move_within_file,
        #                                   detect_move_from_other_files=detect_move_from_other_files,
        #                                   issue_date_filter=issue_date_filter,
        #                                   issue_date=commit_issue_date,
        #                                   filter_revert_commits=filter_revert_commits))

        bic_found = {c for c in bic_found if c.hexsha != fix_commit_hash}
        return bic_found


# # Tests
# _szz = NASZZ("activemq", None, r"E:\github\vulnerable-analysis")
# r = _szz._extract_commit_file_ast_mapping('a30cb8e263300855d4d38710f7d5d9b61223c98f',
#                                           ['activemq-kahadb-store/src/main/java/org/apache/activemq/store/kahadb/disk/page/PageFile.java'])
# r = _szz._extract_file_def_use(r'E:\github\TinyPDG\test.txt')
# print(r)
