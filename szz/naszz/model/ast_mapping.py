class ASTMapping:

    def __init__(self, json: dict):
        self.stmt_change_type: str = json.get('stmtChangeType')
        self.stmt_type: str = json.get('stmtType')
        self.old_stmt_start_line: int = json.get('oldStmtStartLine')
        self.new_stmt_start_line: int = json.get('newStmtStartLine')
        self.unchanged: bool = json.get('unchanged')
