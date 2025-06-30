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


# Modified from RASZZ
def extract_refactorings(repository_path, commits):
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
                return None
            else:
                return json.loads(result.stdout)

    return refactorings


# Modified from RASZZ
def read_refactorings_for_commit(fix_commit_hash, fix_refactorings):
    refactorings = list()
    try:
        refactorings = fix_refactorings[fix_commit_hash]['commits'][0]['refactorings']
    except (KeyError, IndexError) as e:
        # no refactorings found
        pass

    return refactorings


def extract_method_history(repository_path: str, commit: str,
                           file_path: str, method_name: str,
                           method_declaration_line: str | int) -> List['MethodHistory']:
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


def remove_whitespace(s: str):
    return ''.join(s.strip().split())


def compute_similarity_ratio(line_str1: str, line_str2: str):
    l1 = remove_whitespace(line_str1)
    l2 = remove_whitespace(line_str2)
    return Levenshtein.ratio(l1, l2)
