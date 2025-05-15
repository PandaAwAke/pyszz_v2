# include project root in sys path
import sys
import os

from szz.naszz.na_szz import NASZZ

# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, os.path.abspath("../../"))


# szz = NASZZ("activemq", None, r"E:\github\vulnerable-analysis")


def extract_method_history_test():
    r = NASZZ.extract_method_history(r"E:\github\vulnerable-analysis\activemq",
                                     '2cc17a2fa06b86fef58bd26141d29bb5cb0d715d',
                                     'activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java',
                                     'createThrowable',
                                     229)
    print(r)


# def extract_commit_file_ast_mapping_test():
#     r = NASZZ.extract_commit_file_ast_mapping(r"E:\github\vulnerable-analysis",
#                                               'activemq',
#                                               'a30cb8e263300855d4d38710f7d5d9b61223c98f',
#                                               ['activemq-kahadb-store/src/main/java/org/apache/activemq/store/kahadb/disk/page/PageFile.java'])
#     print(r)
#


def extract_file_def_use_test():
    with open(r'E:\github\TinyPDG\test.txt', mode='r') as f:
        content = f.read()
        r = NASZZ.extract_file_def_use(content)
        print(r)


if __name__ == '__main__':
    # extract_method_history_test()
    # extract_commit_file_ast_mapping_test()
    extract_file_def_use_test()
    print("+++ Test passed +++")
