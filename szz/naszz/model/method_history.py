from typing import List


class MethodHistory:

    def __init__(self, json: dict):
         self.commit_id: str = json.get('commitId')
         self.date: str = json.get('date')
         self.path_before: str = json.get('before')
         self.path_after: str = json.get('after')
         self.change_types: List['str'] = json.get('changeTypes')
