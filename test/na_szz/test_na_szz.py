# include project root in sys path
import sys
import os

from szz.core.abstract_szz import ImpactedFile
from szz.naszz.java_parser import JavaParser
from szz.naszz.na_szz import NASZZ

# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, os.path.abspath("../../"))


# szz = NASZZ("activemq", None, r"E:\github\vulnerable-analysis")


def test_extract_method_history():
    r = NASZZ.extract_method_history(r"E:\github\vulnerable-analysis\activemq",
                                     '2cc17a2fa06b86fef58bd26141d29bb5cb0d715d',
                                     'activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java',
                                     'createThrowable',
                                     229)
    print(r)


# def test_extract_commit_file_ast_mapping():
#     r = NASZZ.extract_commit_file_ast_mapping(r"E:\github\vulnerable-analysis",
#                                               'activemq',
#                                               'a30cb8e263300855d4d38710f7d5d9b61223c98f',
#                                               ['activemq-kahadb-store/src/main/java/org/apache/activemq/store/kahadb/disk/page/PageFile.java'])
#     print(r)


def test_extract_content_ast_mapping():
    r = NASZZ.extract_content_ast_mapping(
        """public class Test {
        /**
            Java doc
        */
    public String bar(int k) {
        if (k > 0) return "bar";
    }

    public void foo(){ }
}""",
        """public class Test {
    private String bar (int k){
        if (k > 0) return "foo";
        else if (k == 0) return "bar";
    }
}"""
    )
    print(r)


def test_extract_file_def_use():
    with open(r'E:\github\TinyPDG\test.txt', mode='r') as f:
        content = f.read()
        r = NASZZ.extract_file_def_use(content)
        print(r)


def test_analyze_function_dependency_graph():
    parser = JavaParser()

    source = """
import org.apache.activemq.openwire.OpenWireFormat;
import org.apache.activemq.openwire.OpenWireUtil;
import org.apache.activemq.util.ByteSequence;

public abstract class BaseDataStreamMarshaller implements DataStreamMarshaller {

    public static final Constructor STACK_TRACE_ELEMENT_CONSTRUCTOR;
    private static final int MAX_EXCEPTION_MESSAGE_SIZE = 1024;

    static {
        Constructor constructor = null;
        try {
            constructor = StackTraceElement.class.getConstructor(new Class[] {String.class, String.class,
                                                                              String.class, int.class});
        } catch (Throwable e) {
        }
        STACK_TRACE_ELEMENT_CONSTRUCTOR = constructor;
    }
    
    public int tightMarshal1(OpenWireFormat wireFormat, Object o, BooleanStream bs) throws IOException {
        return 0;
    }

    public void tightMarshal2(OpenWireFormat wireFormat, Object o, DataOutput dataOut, BooleanStream bs)
        throws IOException {
    }
    
    private Throwable createThrowable(String className, String message) {
        try {
            Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
            OpenWireUtil.validateIsThrowable(clazz);
            Constructor constructor = clazz.getConstructor(new Class[] {String.class});
            return (Throwable)constructor.newInstance(new Object[] {message});
        } catch (IllegalArgumentException e) {
            return e;
        } catch (Throwable e) {
            return new Throwable(className + ": " + message);
        }
    }
}
"""
    functions = parser.parse_functions(source)
    assert len(functions) == 3

    for func in functions:
        G, _, _ = NASZZ.analyze_function_dependency_graph(func)
        print(G.edges())


def test_analyze_function_change():
    parser = JavaParser()

    source_old = """import org.apache.activemq.openwire.OpenWireUtil;

        public abstract class BaseDataStreamMarshaller implements DataStreamMarshaller {

            private static final int MAX_EXCEPTION_MESSAGE_SIZE = 1024;

            private Throwable createThrowable(String className, String message) {
                try {
                    Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
                    Constructor constructor = clazz.getConstructor(new Class[] {String.class});
                    return (Throwable)constructor.newInstance(new Object[] {message});
                } catch (Throwable e) {
                    return new Throwable(className + ": " + message);
                }
            }
        }
        """

    source_new = """import org.apache.activemq.openwire.OpenWireFormat;
        import org.apache.activemq.openwire.OpenWireUtil;

        public abstract class BaseDataStreamMarshaller implements DataStreamMarshaller {

            public static final Constructor STACK_TRACE_ELEMENT_CONSTRUCTOR;
            private static final int MAX_EXCEPTION_MESSAGE_SIZE = 1024;

            private Throwable createThrowable(String className, String message) {
                try {
                    Class clazz = Class.forName(className, false, BaseDataStreamMarshaller.class.getClassLoader());
                    OpenWireUtil.validateIsThrowable(clazz);
                    Constructor constructor = clazz.getConstructor(new Class[] {String.class});
                    return (Throwable)constructor.newInstance(new Object[] {message});
                } catch (IllegalArgumentException e) {
                    return e;
                } catch (Throwable e) {
                    return new Throwable(className + ": " + message);
                }
            }
        }
        """

    functions_old = parser.parse_functions(source_old)[0]
    functions_new = parser.parse_functions(source_new)[0]
    result = NASZZ.analyze_function_change(functions_old, functions_new, [12, 15, 16])
    print(result)


def test_na_szz():
    szz = NASZZ('activemq', '', r"E:\github\vulnerable-analysis")
    szz._select_suspicious_lines(
        ImpactedFile(None, [3], None),
        """public class Test {
        /**
            Java doc
        */
        @Override
    public String
     bar(int k) {
        if (k > 0) return "bar";
    }

    public void foo(){ }
}""",
        """public class Test {
        @Override
    private String
     bar (int k){
        if (k > 0) return "foo";
        else if (k == 0) return "bar";
    }
}"""
    )


if __name__ == '__main__':
    # test_extract_method_history()
    # test_extract_commit_file_ast_mapping()
    # test_extract_content_ast_mapping()
    # test_extract_file_def_use()
    # test_analyze_function_dependency_graph()
    test_analyze_function_change()

    # test_na_szz()
    print("+++ Test passed +++")
