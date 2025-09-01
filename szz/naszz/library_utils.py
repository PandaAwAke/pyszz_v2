import json
import os
import platform

import subprocess
import tempfile
from typing import List, Dict

import Levenshtein

from options import Options
import logging as log

from szz.naszz.model.ast_mapping import ASTMapping
from szz.naszz.model.def_use import DefUse
from szz.naszz.model.method_history import MethodHistory


# --------------------- Library functions ---------------------

def extract_refactorings(repository_path, commits) -> Dict:
    """
    Extract refactorings in the commits from a Java repository.
    (Powered by Refactoring Miner)
    Args:
        repository_path: The repository path.
        commits: The commits to analyze.

    Returns:
        A dict contains each commit and its refactorings.
        The structure of a refactoring is defined by refactoring miner.

    See Also:
        https://github.com/tsantalis/RefactoringMiner?tab=readme-ov-file#refactoring-detection-command-line-options
    """
    if platform.system() == 'Windows':
        PATH_TO_REFMINER = os.path.join(Options.PYSZZ_HOME, 'tools/RefactoringMiner-2.0/bin/RefactoringMiner.bat')
    else:
        PATH_TO_REFMINER = os.path.join(Options.PYSZZ_HOME, 'tools/RefactoringMiner-2.0/bin/RefactoringMiner')

    refactorings = dict()
    for commit in commits:
        if not commit in refactorings:
            log.info(f'Running RefMiner on {commit}')
            cmd = [PATH_TO_REFMINER, '-c', repository_path, commit]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            if not result:
                return {}
            else:
                return json.loads(result.stdout)

    return refactorings


def extract_method_history(repository_path: str,
                           commit: str,
                           file_path: str,
                           method_name: str,
                           method_declaration_line: str | int) -> List['MethodHistory']:
    """
    Extract method history from a Java repository.
    (Powered by CodeTracker)
    Args:
        repository_path: The repository path.
        commit: The commit to analyze.
        file_path: The file path of the method.
        method_name: The name of the method.
        method_declaration_line: The declaration line of the method.

    Returns:
        A list of MethodHistory objects. (From latest to oldest)
    """
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
        return []
    else:
        history = json.loads(result.stdout)['commits']
        return list(map(lambda entry: MethodHistory(entry), history))


def extract_content_ast_mapping(old_content: str, new_content: str, algorithm: str = 'gt') -> List['ASTMapping']:
    """
    Extract ast mappings from two file contents.
    (Powered by ICSE2021AstMapping)
    Args:
        old_content: The 'old' source code of the file.
        new_content: The 'new' source code of the file.
        algorithm: The algorithm to use. Could be one of 'gt', 'mtdiff', 'ijm'.

    Returns:
        A list of ASTMapping objects.
    """
    if platform.system() == 'Windows':
        PATH_TO_AST_MAPPING = os.path.join(Options.PYSZZ_HOME, 'tools/ICSE2021AstMapping/bin/AstMapping.bat')
    else:
        PATH_TO_AST_MAPPING = os.path.join(Options.PYSZZ_HOME, 'tools/ICSE2021AstMapping/bin/AstMapping')

    log.info(f'Running ICSE2021 Ast Mapping')
    with tempfile.NamedTemporaryFile(mode='r+', delete=False) as tmpfile_old, \
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
        mappings = json.loads(result.stdout)['statementMappings']
        return list(map(lambda mapping: ASTMapping(mapping), mappings))


def extract_file_def_use(source: str) -> Dict['str', List['DefUse']]:
    """
    Extract ast mappings from two file contents.
    (Powered by refactored version of TinyPDG)
    Args:
        source: The source code of the file. Usually the source code of a class.

    Returns:
        A list of DefUse objects.
    """
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
        return {}
    else:
        def_use_dict: dict = json.loads(result.stdout)
        final_result = {}
        for func_id, def_uses in def_use_dict.items():
            final_result[func_id] = list(map(lambda def_use: DefUse(def_use), def_uses['variableJsons']))
        return final_result


# --------------------- Utility functions ---------------------

def read_refactorings_for_commit(commit_hash: str, fix_refactorings) -> List:
    """
    Read the refactoring results from Refactoring Miner.
    Args:
        commit_hash: The commit to get refactorings for.
        fix_refactorings: The result of the Refactoring Miner.

    Returns:
        The refactoring results.

    See Also:
        https://github.com/tsantalis/RefactoringMiner?tab=readme-ov-file#refactoring-detection-command-line-options
    """
    refactorings = list()
    try:
        refactorings = fix_refactorings[commit_hash]['commits'][0]['refactorings']
    except (KeyError, IndexError) as e:
        # no refactorings found
        pass

    return refactorings


def remove_whitespace(s: str) -> str:
    """
    Remove all whitespaces from a string.
    Args:
        s: The string to remove whitespaces.

    Returns:
        The string without whitespaces.
    """
    return ''.join(s.strip().split())


def compute_similarity_ratio(line_str1: str, line_str2: str) -> float:
    """
    Compute the similarity between two string lines.
    Args:
        line_str1: The first string line.
        line_str2: The second string line.

    Returns:
        The similarity ratio.
    """
    l1 = remove_whitespace(line_str1)
    l2 = remove_whitespace(line_str2)
    return Levenshtein.ratio(l1, l2)
