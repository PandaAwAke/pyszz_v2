import hashlib
import json
from collections import defaultdict
from typing import Tuple

import networkx as nx
from ordered_set import OrderedSet
import logging as log

from szz.naszz.function import Function
from szz.naszz.library_utils import extract_file_def_use


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
    def_use_result: dict = extract_file_def_use(func.get_wrapped_source())
    def_use_result = next(iter(def_use_result.values()))['variableJsons']

    # The line number and defined/used "variable"s.
    line_var_def = defaultdict(set)
    line_var_use = defaultdict(set)

    for varDefUse in def_use_result:
        var = Var(varDefUse['name'], varDefUse['scopeJson'])
        def_lines = [func.transfer_wrapped_line(line) for line in varDefUse['defStmtLineNumbers']]
        use_lines = [func.transfer_wrapped_line(line) for line in varDefUse['useStmtLineNumbers']]
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

    return G, line_var_def, line_var_use


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

        Returns:
            The MD5 value of the scope. If scope is None, return empty string
        """

        if self.scope is None:
            return ''

        json_str = json.dumps(self.scope, sort_keys=True)
        md5_hash = hashlib.md5(json_str.encode('utf-8')).hexdigest()
        return md5_hash

