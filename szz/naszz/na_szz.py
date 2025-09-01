import os
import sys
import traceback
from collections import deque
from collections import defaultdict
from typing import Set, List, Dict
from ordered_set import OrderedSet
from time import time as ts

import networkx as nx
from git import Commit
import logging as log

from pydriller import GitRepository, ModificationType

from szz.common.issue_date import filter_by_date
from szz.core.abstract_szz import DetectLineMoved, LineChangeType, ImpactedFile, BlameData
from szz.ma_szz import MASZZ
from szz.naszz.concurrent_cache import ConcurrentCache
from szz.naszz.model.function import Function
from szz.naszz.java_parser import JavaParser
import library_utils as utils
import dependency_graph as dg


SUPPORTED_FILE_EXT = ['.java']
LEVENSHTEIN_RATIO_THRESHOLD = 0.75


class NASZZ(MASZZ):
    """
    New-line Aware SZZ
    """

    def __init__(self, repo_full_name: str, repo_url: str, repos_dir: str = None):
        self.repo_full_name = repo_full_name
        self.repos_dir = repos_dir
        self.file_methods_cache = ConcurrentCache()
        self.parser = JavaParser()
        super().__init__(repo_full_name, repo_url, repos_dir)


    # -------------- Core functions --------------

    def _blame(self,
               rev: str,
               file_path: str,
               modified_lines: List[int],
               skip_comments: bool = False,
               ignore_revs_list: List[str] = None,
               ignore_revs_file_path: str = None,
               ignore_whitespaces: bool = False,
               detect_move_within_file: bool = False,
               detect_move_from_other_files: 'DetectLineMoved' = None
               ) -> Set['BlameData']:
        log.info("Running super-blame")
        candidate_blame_data = super()._blame(
            rev,
            file_path,
            modified_lines,
            skip_comments,
            ignore_revs_list,
            ignore_revs_file_path,
            ignore_whitespaces,
            detect_move_within_file,
            detect_move_from_other_files
        )

        commits = set([blame.commit.hexsha for blame in candidate_blame_data])

        refactorings = utils.extract_refactorings(self._repository_path, commits)

        to_reblame = dict()
        result_blame_data = set()
        for blame in candidate_blame_data:
            commit_key = blame.commit.hexsha + "@" + blame.file_path
            can_add = True
            # Case 1: Refactoring detected for this line
            for refactoring in utils.read_refactorings_for_commit(blame.commit.hexsha, refactorings):
                for location in refactoring['rightSideLocations']:
                    file_path = location['filePath']
                    from_line = location['startLine']
                    to_line   = location['endLine']

                    if blame.file_path == file_path and blame.line_num >= from_line and blame.line_num <= to_line and blame.commit.hexsha not in ignore_revs_list:
                        log.info(f'Ignoring {blame.file_path} line {blame.line_num} (refactoring {refactoring["type"]})')
                        if not commit_key in to_reblame:
                            to_reblame[commit_key] = ReblameCandidate(blame.commit.hexsha, blame.file_path, {blame.line_num})
                        else:
                            to_reblame[commit_key].modified_lines.add(blame.line_num)
                        can_add = False

            if not can_add:
                continue

            # Case 2: No previous version of this line was found, try to find it in the method history
            file_source = self.repository.git.show(f"{blame.commit.hexsha}:{blame.file_path}")
            methods: List[Function] = self.file_methods_cache.get_or_put(file_source,
                                                         lambda: self.parser.parse_functions(file_source))

            matched_method = None
            for method in methods:
                if method.start_line <= blame.line_num <= method.end_line:
                    matched_method = method
                    break

            if matched_method:
                history = utils.extract_method_history(self.repository_path, blame.commit.hexsha, blame.file_path, matched_method.name, matched_method.start_line)
                for index in range(len(history)):
                    method_history = history[index]
                    if method_history.commit_id == blame.commit.hexsha and index < len(history) - 1:
                        # Found the matched method in the history
                        commit_old = history[index + 1].commit_id
                        commit_new = method_history.commit_id

                        # TODO: Try to find AST mapping in it

                        if False:
                            if not commit_key in to_reblame:
                                to_reblame[commit_key] = ReblameCandidate(blame.commit.hexsha, blame.file_path, {blame.line_num})
                            else:
                                to_reblame[commit_key].modified_lines.add(blame.line_num)
                            can_add = False

            if can_add:
                result_blame_data.add(blame)

        for _, reblame_candidate in to_reblame.items():
            log.info(f'Re-blaming {reblame_candidate.file_path} @ {reblame_candidate.rev}, lines {reblame_candidate.modified_lines} because of refactoring')

            new_ignore_revs_list = ignore_revs_list.copy()
            new_ignore_revs_list.append(reblame_candidate.rev)

            new_blame_results = self._blame(
                reblame_candidate.rev,
                reblame_candidate.file_path,
                list(reblame_candidate.modified_lines),
                skip_comments,
                new_ignore_revs_list,
                ignore_revs_file_path,
                ignore_whitespaces,
                detect_move_within_file,
                detect_move_from_other_files
            )

            result_blame_data.update(new_blame_results)

        return result_blame_data

    def find_bic(self, fix_commit_hash: str, impacted_files: List['ImpactedFile'], **kwargs) -> Set[Commit]:
        log.info(f"find_bic() kwargs: {kwargs}")
        self._set_working_tree_to_commit(fix_commit_hash)

        max_change_size = kwargs.get('max_change_size', MASZZ.DEFAULT_MAX_CHANGE_SIZE)
        filter_revert = kwargs.get('filter_revert_commits', False)

        params = dict()
        params['ignore_revs_file_path'] = kwargs.get('ignore_revs_file_path', None)
        params['detect_move_within_file'] = kwargs.get('detect_move_within_file', True)
        params['detect_move_from_other_files'] = kwargs.get('detect_move_from_other_files', DetectLineMoved.SAME_COMMIT)
        params['ignore_revs_list'] = list()
        if kwargs.get('blame_rev_pointer', None):
            params['rev'] = kwargs['blame_rev_pointer']
        else:
            params['rev'] = 'HEAD^'     # See ag_szz._ag_annotate()

        # In vulnerability mode, NASZZ will trace the modified lines as earlier as possible
        VULNERABILITY_MODE = kwargs.get('vulnerability_mode', True)

        log.info("staring blame")
        start = ts()
        blame_data = set()
        commits_to_ignore = set()
        commits_to_ignore_current_file = set()

        bic = set()
        for imp_file in impacted_files:
            if VULNERABILITY_MODE:
                # In vulnerability mode, we will trace every line as earlier as possible
                blame_data = self._blame(
                    rev=f'{fix_commit_hash}^',
                    file_path=imp_file.file_path,
                    modified_lines=imp_file.modified_lines,
                    ignore_whitespaces=True,
                    skip_comments=True,
                    **kwargs
                )
                for bd in blame_data:
                    previous_bds = []   # TODO: use this

                    while True:
                        match = False
                        if os.path.splitext(imp_file.file_path)[-1].lower() in SUPPORTED_FILE_EXT:
                            # Try to map by Java AST Mapping things
                            try:
                                parent_hash = self.repository.git.rev_parse(f"{bd.commit.hexsha}^")
                                source_file_content_after = self.repository.git.show(f"{bd.commit.hexsha}:{imp_file.file_path}")
                                source_file_content_before = self.repository.git.show(f"{parent_hash}:{imp_file.file_path}")
                            except:
                                break

                            ast_mapping_result = utils.extract_content_ast_mapping(source_file_content_after, source_file_content_before)
                            for mapping in ast_mapping_result:
                                if mapping.old_stmt_start_line != -1 and mapping.new_stmt_start_line == bd.line_num:
                                    match = True
                                    break
                        else:
                            # Try to map by PyDriller mapping things (modified from V-SZZ)
                            repo = GitRepository(self.repository_path)
                            commit = repo.get_commit(bd.commit.hexsha)
                            for modification in commit.modifications:
                                # Filter: we only consider imp_file
                                path = modification.new_path
                                if modification.change_type in [ModificationType.DELETE, ModificationType.RENAME]:
                                    path = modification.old_path

                                if path != imp_file.file_path:
                                    continue

                                # If there is no 'old_path', break (usually an adding)
                                if not modification.old_path:
                                    break

                                lines_deleted = [deleted for deleted in modification.diff_parsed['deleted']]
                                if len(lines_deleted) == 0:
                                    break

                                if bd.line_str:
                                    # For each deleted line, see if any one has a similarity ratio over LEVENSHTEIN_RATIO_THRESHOLD
                                    tuples = []
                                    for line_number, line in lines_deleted:
                                        ratio = utils.compute_similarity_ratio(bd.line_str, line)
                                        line_distance = abs(bd.line_num - line_number)
                                        tuples.append((ratio, -line_distance, line_number))     # Used for sorting

                                    tuples.sort(reverse=True)
                                    if tuples[0][0] > LEVENSHTEIN_RATIO_THRESHOLD:
                                        match = True
                                        break

                        if not match:
                            break
                        previous_bds.append(bd)

                        if ts() - start > (60 * 60 * 1):  # 1 hour max time
                            log.error(f"blame timeout for {self.repository_path}")
                            break

                        # Blame forward for just this line
                        bd = next(iter(self._blame(
                            rev=f'{bd.commit.hexsha}^',
                            file_path=imp_file.file_path,
                            modified_lines=[],  # TODO: fix this
                            ignore_whitespaces=True,
                            skip_comments=True,
                            **kwargs
                        )))

                    bic.add(bd.commit)
            else:
                commits_to_ignore_current_file = commits_to_ignore.copy()
                to_blame = True
                while to_blame:
                    log.info(f"excluding commits: {params['ignore_revs_list']}")
                    try:
                        blame_data = self._blame(
                            file_path=imp_file.file_path,
                            modified_lines=imp_file.modified_lines,
                            ignore_whitespaces=True,
                            skip_comments=True,
                            **kwargs
                        )
                    except:
                        log.error(traceback.format_exc())

                    new_commits_to_ignore = set()
                    new_commits_to_ignore_current_file = set()
                    for bd in blame_data:
                        # Filtering unimportant commits
                        if bd.commit.hexsha not in new_commits_to_ignore and bd.commit.hexsha not in new_commits_to_ignore_current_file:
                            if bd.commit.hexsha not in commits_to_ignore_current_file:
                                # NASZZ: We do not ignore big changes here
                                # new_commits_to_ignore.update(self._exclude_commits_by_change_size(bd.commit.hexsha, max_change_size=max_change_size))

                                new_commits_to_ignore.update(self.get_merge_commits(bd.commit.hexsha))
                                new_commits_to_ignore_current_file.update(self.select_meta_changes(bd.commit.hexsha, bd.file_path, filter_revert))

                    if len(new_commits_to_ignore) == 0 and len(new_commits_to_ignore_current_file) == 0:
                        to_blame = False
                    if ts() - start > (60 * 60 * 1):  # 1 hour max time
                        log.error(f"blame timeout for {self.repository_path}")
                        break

                    commits_to_ignore.update(new_commits_to_ignore)
                    commits_to_ignore_current_file.update(commits_to_ignore)
                    commits_to_ignore_current_file.update(new_commits_to_ignore_current_file)
                    params['ignore_revs_list'] = list(commits_to_ignore_current_file)

                # NASZZ: We do not ignore big changes here
                # bic.update({bd.commit for bd in blame_data if bd.commit.hexsha not in self._exclude_commits_by_change_size(bd.commit.hexsha, max_change_size)})
                bic.update({bd.commit for bd in blame_data})

        if kwargs.get('issue_date_filter', False):
            bic = filter_by_date(bic, kwargs['issue_date'])
        else:
            log.info("Not filtering by issue date.")

        return bic

    def start(self, fix_commit_hash: str, commit_issue_date, **kwargs) -> Set[Commit]:
        # TODO: change this function
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
        bic_found = self.find_bic(fix_commit_hash=fix_commit_hash,
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
        
        bic_found.update(self.find_bic(blame_rev_pointer='HEAD',
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
        Args:
            fix_commit_hash: fix commit
            impacted_files: impacted_files with the modified line ranges

        Returns:
            A list of impacted files with lines selected with DefUseChains
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

                func_suspicious_lines = NASZZ.select_suspicious_lines(imp_file, source_file_content_before, source_file_content_after)
                log.info(f"added lines to blame={lines_to_blame} for file={imp_file.file_path}")
                if lines_to_blame:
                    def_use_imp_files.append(ImpactedFile(imp_file.file_path, list(lines_to_blame), None))

        log.info(f"impacted_files_ext={def_use_imp_files}")

        return def_use_imp_files

    def select_suspicious_lines(self, imp_file: ImpactedFile, source_file_before: str, source_file_after: str) -> Dict[Function, Set]:
        """
        Compute suspicious lines at function level from impacted lines (usually added lines)
        Args:
            imp_file:
            source_file_before: File source after the commit (should not be empty)
            source_file_after: File source before the commit (could be None)

        Returns:
            suspicious_lines of each function
        """

        # 1: Get AST mapping result
        log.info(f'Running AST Mapping')
        ast_mapping_result = utils.extract_content_ast_mapping(source_file_before, source_file_after)
        # old_to_new_line_mapping = defaultdict(set)
        new_to_old_line_mapping = defaultdict(set)

        for stmt_mapping in ast_mapping_result:
            old_line = stmt_mapping.old_stmt_start_line
            new_line = stmt_mapping.new_stmt_start_line
            # if new_line != -1:
            #     old_to_new_line_mapping[old_line].add(new_line)
            if old_line != -1:
                new_to_old_line_mapping[new_line].add(old_line)

        # 2: Get all functions in this file
        functions = self.file_methods_cache.get_or_put(source_file_after,
                                                       lambda: self.parser.parse_functions(source_file_after))
        modified_functions = []

        # 3: Remove functions which were not modified
        modified_lines_in_functions = defaultdict(list)
        for func in functions:
            modified = False
            for line in imp_file.modified_lines:
                if func.start_line <= line <= func.end_line:
                    modified = True
                    modified_lines_in_functions[func].append(line)
            if modified:
                modified_functions.append(func)

        # 4: For each modified function, try to find its previous version
        suspicious_lines = dict()
        old_functions = self.file_methods_cache.get_or_put(source_file_before,
                                                           lambda: self.parser.parse_functions(source_file_before))
        function_mapping = []

        for func in modified_functions:
            old_start_lines = new_to_old_line_mapping.get(func.start_line)
            old_func = filter(lambda f: f.start_line in old_start_lines, old_functions)
            if not old_func:
                continue
            old_func = next(old_func)
            function_mapping.append((old_func, func))

        # 5: For each modified function, analyze its function change
        for old_func, new_func in function_mapping:
            func_suspicious_lines = NASZZ.analyze_function_change(old_func, new_func, modified_lines_in_functions[new_func])
            suspicious_lines[new_func] = func_suspicious_lines

        return suspicious_lines

    @staticmethod
    def analyze_function_change(old_function: Function, new_function: Function, modified_lines: List[int]) -> Set[int]:
        """
        The main place to analyze suspicious lines from the function change (usually added lines).
        Args:
            old_function: The old function (before the commit)
            new_function: The new function (after the commit)
            modified_lines: Modified lines (usually added lines in the original file after the commit)

        Returns:
            Suspicious lines of this function (a set of line numbers)
        """
        G_old, _, _ = dg.analyze_function_dependency_graph(old_function)
        G_new, def_new, _ = dg.analyze_function_dependency_graph(new_function)

        # Calculate difference graph
        G_diff = dg.calculate_diff_graph(G_new, G_old)

        # Get the nodes of the graph (used as auxiliaries)
        nodes_old = OrderedSet(G_old.nodes())
        nodes_diff = OrderedSet(G_diff.nodes())

        # Get leaf variables
        leaf_variable_names = [name for name in G_diff.nodes() if G_diff.out_degree(name) == 0]

        suspicious_var_names = set()

        # Case 1: For every leaf (exclusive), traverse up to find the first variable which exists in G_old
        q = deque(leaf_variable_names)
        visited_var_names = OrderedSet()
        while len(q) > 0:
            var_name = q.pop()
            visited_var_names.add(var_name)

            in_edges = G_diff.in_edges(var_name)
            for edge in in_edges:
                pre_var_name = edge[0]
                if pre_var_name in nodes_old:
                    suspicious_var_names.add(pre_var_name)
                elif pre_var_name not in visited_var_names and pre_var_name not in q:
                    q.appendleft(pre_var_name)

        # Case 2: For every changed var in new lines, if it doesn't exist in G_diff,
        #         but it exists in G_old, then it was suspicious
        # Get changed variables by `modified_lines`
        new_line_changed_var_names = set()
        for line, vars in def_new.items():
            if line in modified_lines:
                for var in vars:
                    new_line_changed_var_names.add(var.name)

        for name in new_line_changed_var_names:
            if name in nodes_diff:
                continue
            if name not in nodes_old:
                continue
            suspicious_var_names.add(name)

        # Case 3: Cycles (including self-cycles) in G_diff were suspicious
        cycles = nx.simple_cycles(G_diff)
        for cycle in cycles:
            for name in cycle:
                if name not in nodes_old:
                    continue
                suspicious_var_names.add(name)

        # For every suspicious var, its defs and uses were suspicious
        suspicious_lines = set()
        for name in suspicious_var_names:
            for use_edge in G_old.in_edges(name):
                suspicious_lines.update(G_old.get_edge_data(use_edge[0], name)['lines'])
            for def_edge in G_old.out_edges(name):
                suspicious_lines.update(G_old.get_edge_data(name, def_edge[1])['lines'])

        return suspicious_lines


class ReblameCandidate:
    def __init__(self, rev, file_path, modified_lines: Set):
        self.rev = rev
        self.file_path = file_path
        self.modified_lines = modified_lines
