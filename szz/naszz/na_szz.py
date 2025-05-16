import json
import os
import logging as log
import platform
import subprocess
import tempfile
from collections import defaultdict
from typing import Set, List

from git import Commit

from options import Options
from szz.core.abstract_szz import DetectLineMoved, LineChangeType, ImpactedFile
from szz.naszz.java_parser import JavaParser, Function
from szz.ra_szz import RASZZ

SUPPORTED_FILE_EXT = ['.java']


class NASZZ(RASZZ):
    """
    New-line Aware SZZ
    """

    def __init__(self, repo_full_name: str, repo_url: str, repos_dir: str = None):
        self.repo_full_name = repo_full_name
        self.repos_dir = repos_dir
        super().__init__(repo_full_name, repo_url, repos_dir)

    @staticmethod
    def extract_method_history(repository_path: str, commit: str,
                               file_path: str, method_name: str,
                               method_declaration_line: str | int):
        if platform.system() == 'Windows':
            PATH_TO_CODE_TRACKER = os.path.join(Options.PYSZZ_HOME, 'tools/CodeTracker-2.7/bin/CodeTracker.bat')
        else:
            PATH_TO_CODE_TRACKER = os.path.join(Options.PYSZZ_HOME, 'tools/CodeTracker-2.7/bin/CodeTracker')

        log.info(f'Running CodeTracker on {commit}, {file_path + "#" + method_name}')
        cmd = [
            PATH_TO_CODE_TRACKER,
            '-r', repository_path,
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

    @staticmethod
    def extract_content_ast_mapping(old_content: str, new_content: str, algorithm: str = 'gt'):
        if platform.system() == 'Windows':
            PATH_TO_AST_MAPPING = os.path.join(Options.PYSZZ_HOME, 'tools/ICSE2021AstMapping/bin/AstMapping.bat')
        else:
            PATH_TO_AST_MAPPING = os.path.join(Options.PYSZZ_HOME, 'tools/ICSE2021AstMapping/bin/AstMapping')

        log.info(f'Running ICSE2021 Ast Mapping')
        with tempfile.NamedTemporaryFile(mode='r+', delete=False) as tmpfile_old,\
                tempfile.NamedTemporaryFile(mode='r+', delete=False) as tmpfile_new:
            tmpfile_old.write(old_content)
            tmpfile_new.write(new_content)

        cmd = [
            PATH_TO_AST_MAPPING,
            '-a', algorithm,
            '-o', tmpfile_old.name,
            '-n', tmpfile_new.name
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        os.remove(tmpfile_old.name)
        os.remove(tmpfile_new.name)

        if not result:
            return []
        else:
            return json.loads(result.stdout)['statementMappings']

    @staticmethod
    def extract_file_def_use(source: str):
        if platform.system() == 'Windows':
            PATH_TO_TINY_PDG = os.path.join(Options.PYSZZ_HOME, 'tools/TinyPDG/bin/TinyPDG.bat')
        else:
            PATH_TO_TINY_PDG = os.path.join(Options.PYSZZ_HOME, 'tools/TinyPDG/bin/TinyPDG')

        log.info(f'Running TinyPDG')
        with tempfile.NamedTemporaryFile(mode='r+', delete=False) as tmpfile:
            tmpfile.write(source)

        cmd = [
            PATH_TO_TINY_PDG,
            '-t', 'ddg',
            '-f', tmpfile.name,
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        os.remove(tmpfile.name)

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

        # process impacted files with added lines
        impacted_files_duchain = self._process_impacted_files(fix_commit_hash, imp_files)
        
        bic_found.update(super().find_bic(blame_rev_pointer='HEAD',
                                          fix_commit_hash=fix_commit_hash,
                                          impacted_files=impacted_files_duchain,
                                          ignore_revs_file_path=ignore_revs_file_path,
                                          max_change_size=max_change_size,
                                          detect_move_within_file=detect_move_within_file,
                                          detect_move_from_other_files=detect_move_from_other_files,
                                          issue_date_filter=issue_date_filter,
                                          issue_date=commit_issue_date,
                                          filter_revert_commits=filter_revert_commits))

        bic_found = {c for c in bic_found if c.hexsha != fix_commit_hash}
        return bic_found

    def _process_impacted_files(self, fix_commit_hash: str, impacted_files: List['ImpactedFile']) -> List['ImpactedFile']:
        """
        Extract DefUseChains using added lines from impacted files.

        :param impacted_files List['ImpactedFile'] impacted_files with the modified line ranges
        :returns List['ImpactedFile'] list of impacted files with lines selected with DefUseChains
        """

        def_use_imp_files = list()
        try:
            fix_commit_parent_hash = self.repository.git.rev_parse(f"{fix_commit_hash}^")
        except:
            log.warning(f"Encountered an exception while getting parent commit hash of: {fix_commit_hash}")
            return def_use_imp_files

        for imp_file in impacted_files:
            if imp_file.line_change_type == LineChangeType.ADD:
                if not os.path.splitext(imp_file.file_path)[-1].lower() in SUPPORTED_FILE_EXT:
                    log.warning(f"skip file not supported by define-use chains parser: {imp_file.file_path}")
                    continue

                try:
                    source_file_content_after = self.repository.git.show(f"{fix_commit_hash}:{imp_file.file_path}")
                    source_file_content_before = self.repository.git.show(f"{fix_commit_parent_hash}:{imp_file.file_path}")
                except:
                    # This is an introduced change, or some other errors occurred
                    continue

                lines_to_blame = self._select_suspicious_lines(imp_file, source_file_content_before, source_file_content_after)
                log.info(f"added lines to blame={lines_to_blame} for file={imp_file.file_path}")
                if lines_to_blame:
                    def_use_imp_files.append(ImpactedFile(imp_file.file_path, list(lines_to_blame), None))

        log.info(f"impacted_files_ext={def_use_imp_files}")

        return def_use_imp_files

    def _select_suspicious_lines(self, imp_file: ImpactedFile, source_before: str, source_after: str) -> Set:
        """
        Compute suspicious lines at function level from impacted lines (usually added lines)

        :param imp_file
        :param source_before Function source after the commit (should not be empty)
        :param source_after Function source before the commit (could be None)

        :return suspicious_lines
        """
        parser = JavaParser()

        # Get AST mapping result
        log.info(f'Running AST Mapping')
        ast_mapping_result = self.extract_content_ast_mapping(source_before, source_after)
        old_to_new_line_mapping = defaultdict(set)
        new_to_old_line_mapping = defaultdict(set)

        for stmt_mapping in ast_mapping_result:
            old_line = stmt_mapping['oldStmtStartLine']
            new_line = stmt_mapping['newStmtStartLine']
            if new_line != -1:
                old_to_new_line_mapping[old_line].add(new_line)
            if old_line != -1:
                new_to_old_line_mapping[new_line].add(old_line)

        # Get all functions in this file
        functions = parser.parse_functions(source_after)
        modified_functions = []

        # Remove functions which were not modified
        modified_lines_in_functions = []
        for func in functions:
            modified = False
            for line in imp_file.modified_lines:
                if func.start_line <= line <= func.end_line:
                    modified = True
                    modified_lines_in_functions.append(line)
            if modified:
                modified_functions.append(func)

        # For each modified function, try to find its previous version
        suspicious_lines = set()
        old_functions = parser.parse_functions(source_before)

        for func in modified_functions:
            old_start_line = new_to_old_line_mapping.get(func.start_line)
            matched_function = filter(lambda f: f.start_line in old_start_line, old_functions)
            if not matched_function:
                continue
            matched_function = next(matched_function)
            self._analyze_function_change(matched_function, func)


        return suspicious_lines

    def _analyze_function_change(self, old_function: Function, new_function: Function):
        log.info(f'Running TinyPDG')
        def_use_result_before = self.extract_file_def_use(function.source)
        # def_use_result_after = self.extract_file_def_use(source_after)
