import hashlib
import json
import os
import logging as log
import platform
from queue import Queue
import subprocess
import tempfile
from collections import defaultdict
from typing import Set, List, Tuple
from ordered_set import OrderedSet

import networkx as nx
from git import Commit

from options import Options
from szz.core.abstract_szz import DetectLineMoved, LineChangeType, ImpactedFile
from szz.naszz.function import Function
from szz.naszz.java_parser import JavaParser
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

        # 1: Get AST mapping result
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

        # 2: Get all functions in this file
        functions = parser.parse_functions(source_after)
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
        suspicious_lines = set()
        old_functions = parser.parse_functions(source_before)
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
            self._analyze_function_change(old_func, new_func, modified_lines_in_functions[new_func])

        return suspicious_lines

    def _analyze_function_change(self, old_function: Function, new_function: Function,
                                 modified_lines: List[int]) -> Set[int]:
        """
        The main place to analyze suspicious lines from the function change (usually added lines).
        Args:
            old_function: The old function (before the commit)
            new_function: The new function (after the commit)
            modified_lines: Modified lines (usually added lines in the original file after the commit)

        Returns:
            Suspicious lines of this function (a set of line numbers)
        """
        G_old, _, _ = self.analyze_function_dependency_graph(old_function)
        G_new, def_new, _ = self.analyze_function_dependency_graph(new_function)

        # Calculate difference graph
        G_diff = self.calculate_diff_graph(G_new, G_old)

        # Get the nodes of the graph (used as auxiliaries)
        nodes_old = OrderedSet(G_old.nodes())
        nodes_diff = OrderedSet(G_diff.nodes())

        # Get leaf variables
        leaf_variable_names = [name for name in G_diff.nodes() if G_diff.out_degree(name) == 0]

        suspicious_var_names = set()

        # Case 1: For every leaf (exclusive), traverse up to find the first variable which exists in G_old
        q = Queue()
        for name in leaf_variable_names:
            q.put(name)

        visited_var_names = OrderedSet()
        while not q.empty():
            var_name = q.get()
            visited_var_names.add(var_name)

            in_edges = G_diff.in_edges(var_name)
            for edge in in_edges:
                pre_var_name = edge[0]
                if pre_var_name in nodes_old:
                    suspicious_var_names.add(pre_var_name)
                elif pre_var_name not in visited_var_names and pre_var_name not in q:
                    q.put(pre_var_name)

        # Case 2: For every changed var in new lines, if it doesn't exist in G_diff,
        #         but it exists in G_old, then it was suspicious
        # Get changed variables by `modified_lines`
        new_line_changed_var_names = set([var.name for line, var in def_new.items() if line in modified_lines])
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


    @staticmethod
    def analyze_function_dependency_graph(func: Function) -> Tuple[nx.DiGraph, defaultdict, defaultdict]:
        """
        Analyze the variable dependency graph of a function.
        Args:
            func: The function to analyze

        Returns: (G, D, U)
            G: The dependency graph (nx.DiGraph) of the function
            D: The lines and defined variables presented as a dictionary {linenum:  {var, ...}}
            U: The lines and used variables presented as a dictionary {linenum: {var, ...}}
        """
        log.info(f'Running TinyPDG')
        def_use_result: dict = NASZZ.extract_file_def_use(func.get_wrapped_source())
        def_use_result = next(iter(def_use_result.values()))['variableJsons']

        # The line number and defined/used "variable"s.
        line_var_def = defaultdict(set)
        line_var_use = defaultdict(set)

        for varDefUse in def_use_result:
            var = Var(varDefUse['name'], varDefUse['scopeJson'])
            def_lines = varDefUse['defStmtLineNumbers']
            use_lines = varDefUse['useStmtLineNumbers']
            for line in def_lines:
                line_var_def[line].add(var)
            for line in use_lines:
                line_var_use[line].add(var)

        edge_and_lines = defaultdict(set)
        for line, def_vars in line_var_def.items():
            for def_var in def_vars:
                if line in line_var_use.keys():
                    use_vars = line_var_use[line]
                    for use_var in use_vars:
                        edge_and_lines[(def_var.name, use_var.name)].add(line)

        G = nx.DiGraph()
        for edge, lines in edge_and_lines.items():
            G.add_edge(edge[0], edge[1], lines=lines)

        # G.remove_edges_from(list(nx.selfloop_edges(G)))   # Remove self-loops
        return G, line_var_def, line_var_use

    @staticmethod
    def calculate_diff_graph(G1: nx.DiGraph, G2: nx.DiGraph) -> nx.DiGraph:
        G = nx.DiGraph()
        nodes1 = OrderedSet(G1.nodes())
        nodes2 = OrderedSet(G2.nodes())

        matched_nodes = OrderedSet()
        for node in nodes1:
            if node in nodes2:
                matched_nodes.add(node)

        matched_edges = OrderedSet()
        for edge in G1.edges():
            u, v = edge
            if G2.has_edge(u, v):
                matched_edges.add(edge)

        for node in nodes1:
            if node not in matched_nodes:
                G.add_node(node)

        for edge in G1.edges():
            if edge not in matched_edges:
                G.add_edge(edge[0], edge[1])

        return G


class Var:
    def __init__(self, name: str, scope: dict | None = None):
        self.name = name
        self.scope = scope

    def get_scope_md5(self) -> str:
        """
        Hash the scope info of a variable into MD5 value.
        Args:
            scope: None, or a dict like
             {
                "type" : "StatementInfo",
                "lineNumber" : 2
             }

        Returns:
            The MD5 value of the scope. If scope is None, return empty string
        """

        if self.scope is None:
            return ''

        json_str = json.dumps(self.scope, sort_keys=True)
        md5_hash = hashlib.md5(json_str.encode('utf-8')).hexdigest()
        return md5_hash
