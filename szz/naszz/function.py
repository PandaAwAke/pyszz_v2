
FUNCTION_WRAPPER_PREFIX = 'class UNKNOWN {\n'
FUNCTION_WRAPPER_SUFFIX = '\n}'


class Function:

    def __init__(self, name: str, signature: str, is_constructor: bool, source: str, start_line: int, end_line: int):
        self.name = name
        self.signature = signature
        self.is_constructor = is_constructor
        self.source = source
        self.start_line = start_line
        self.end_line = end_line

    def get_body_source(self):
        if hasattr(self, 'body_source'):
            return getattr(self, 'body_source')

        body_start = self.source.find('{')
        if body_start != -1:
            # signature_part = self.source[:body_start].strip()
            body_part = self.source[body_start:]
        else:
            # signature_part = self.signature
            body_part = ""

        setattr(self, 'body_source', body_part)
        return body_part

    def get_wrapped_source(self):
        return FUNCTION_WRAPPER_PREFIX + self.source + FUNCTION_WRAPPER_SUFFIX

    def transfer_wrapped_line(self, line_number: int, wrapped_to_original: bool = True):
        if wrapped_to_original:
            return self.start_line + line_number - 2
        else:
            return line_number - self.start_line + 2
