from typing import List


class DefUse:

    class Scope:
        def __init__(self, type: str, line_number: int):
            self.type = type
            self.line_number = line_number


    def __init__(self, json: dict):
        self.var_id: int = json.get('id')

        scope = json.get('scopeJson')
        if scope:
            scope = DefUse.Scope(scope.get('type'), scope.get('lineNumber'))

        self.var_scope: DefUse.Scope | None = scope
        self.var_name: str = json.get('name')
        self.def_stmt_lines: List['int'] = json.get('defStmtLineNumbers')
        self.use_stmt_lines: List['int'] = json.get('useStmtLineNumbers')
