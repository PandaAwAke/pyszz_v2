from unittest import TestCase

from szz.naszz.java_parser import JavaParser


class TestJavaParser(TestCase):
    def test_parse_functions(self):
        parser = JavaParser()
        functions = parser.parse_functions("""public class Test {
                /**
                    Java doc
                */
                @Override
                private
                 String
                    bar (
                        int k
                        )
                {
                    if (k > 0) return "foo";
                    else if (k == 0) return "bar";
                }
            }
            """)

        # functions = parser.parse_function_positions("""public interface Test {
        #                 private String bar (int k);
        #             }""")
        print(functions)
