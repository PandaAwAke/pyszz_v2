from typing import List, Tuple

import javalang
from javalang.tree import MethodDeclaration, ConstructorDeclaration

from szz.naszz.model.function import Function


class JavaParser:

    def _parse_function_position(self, file_source: str, method: MethodDeclaration) -> Tuple[int, int]:
        """
        Parse the start line and the end line of the method.
        Args:
            file_source: The source code of the method.
            method: The MethodDeclaration object of the method.

        Returns:
            A tuple of (start_line, end_line).
        """
        start_line: int = method.position.line
        annotations = getattr(method, 'annotations')
        if annotations:
            start_line = min(start_line, min(map(lambda anno: anno.position.line, annotations)))

        # Find the end position
        lines = file_source.split('\n')
        brace_count = 0
        found_start = False

        end_line: int = -1
        for i in range(start_line - 1, len(lines)):
            line = lines[i]
            if not found_start and '{' in line:
                found_start = True

            if found_start:
                brace_count += line.count('{')
                brace_count -= line.count('}')

                if brace_count == 0:
                    end_line = i + 1
                    break

        assert start_line is not None and end_line != -1
        return start_line, end_line


    def parse_functions(self, file_source: str) -> List['Function']:
        """
        Parse functions in a file.
        Note that annotations and modifiers would be ignored.
        Args:
            file_source: The source code of the method.

        Returns:
            A list of Function objects.
        """
        try:
            tree = javalang.parse.parse(file_source)
        except javalang.parser.JavaSyntaxError:
            return []

        functions = []

        for path, node in tree.filter(ConstructorDeclaration):
            if node.body is None:   # Ignore empty body
                continue

            name = node.name
            is_constructor = True
            modifiers = ' '.join(node.modifiers) + ' ' if node.modifiers else ''
            params = ', '.join([f"{param.type} {param.name}" for param in node.parameters])
            signature = f"{modifiers}{name}({params})"
            start_line, end_line = self._parse_function_position(file_source, node)
            function_code = '\n'.join(file_source.split('\n')[start_line - 1:end_line])

            functions.append(Function(
                name,
                signature,
                is_constructor,
                function_code,
                start_line,
                end_line
            ))

        for path, node in tree.filter(MethodDeclaration):
            if node.body is None:   # Ignore empty body
                continue

            name = node.name

            # is_constructor = node.return_type is None and name == tree.types[0].name
            is_constructor = False

            modifiers = ' '.join(node.modifiers) + ' ' if node.modifiers else ''
            params = ', '.join([f"{param.type} {param.name}" for param in node.parameters])

            # return_type = '' if is_constructor else (str(node.return_type) + ' ' if node.return_type else 'void ')
            return_type = str(node.return_type) + ' ' if node.return_type else 'void '

            signature = f"{modifiers}{return_type}{name}({params})"
            start_line, end_line = self._parse_function_position(file_source, node)
            function_code = '\n'.join(file_source.split('\n')[start_line - 1:end_line])

            functions.append(Function(
                name,
                signature,
                is_constructor,
                function_code,
                start_line,
                end_line
            ))

        return functions
