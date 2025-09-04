# include project root in sys path
import sys
import os
from unittest import TestCase

from szz.core.abstract_szz import ImpactedFile
from szz.naszz.java_parser import JavaParser
import szz.naszz.library_utils as utils
import szz.naszz.dependency_graph as dg
from szz.naszz.na_szz import NASZZ


class TestNASZZ(TestCase):
    # ---------------- Static Methods ----------------

    def test_extract_method_history(self):
        r = utils.extract_method_history(r"E:\github\vulnerable-analysis\activemq",
                                         '2cc17a2fa06b86fef58bd26141d29bb5cb0d715d',
                                         'activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java',
                                         'createThrowable',
                                         229)
        print(r)

    def test_extract_content_ast_mapping(self):
        r = utils.extract_content_ast_mapping(
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

    def test_extract_file_def_use(self):
        with open(r'E:\github\TinyPDG\test.txt', mode='r') as f:
            content = f.read()
            r = utils.extract_file_def_use(content)
            print(r)

    def test_analyze_function_dependency_graph(self):
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
            G, _, _ = dg.analyze_function_dependency_graph(func)
            print(G.edges())

    def test_analyze_function_change(self):
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

    # ---------------- NA-SZZ ----------------

    def test_na_szz(self):
        szz = NASZZ('activemq', '', r"E:\github\vulnerable-analysis")
        szz.select_suspicious_lines(
            ImpactedFile(None, [18, 19], None),
            """package hudson.plugins.depgraph_view.model.operations;

import hudson.model.AbstractProject;



import java.io.IOException;

import jenkins.model.Jenkins;

public abstract class EdgeOperation {
    protected final AbstractProject<?, ?> source;
    protected final AbstractProject<?, ?> target;

    public EdgeOperation(String sourceJobName, String targetJobName) {
        this.source = Jenkins.getInstance().getItemByFullName(sourceJobName.trim(), AbstractProject.class);
        this.target = Jenkins.getInstance().getItemByFullName(targetJobName, AbstractProject.class);


    }

    /**
     * Removes double commas and also trailing an leading commas.
     * @param actualValue the actual value to be normalized
     * @return the value with no unrequired commas
     */
    public static String normalizeChildProjectValue(String actualValue){
        actualValue = actualValue.replaceAll("(,[ ]*,)", ", ");
        actualValue = actualValue.replaceAll("(^,|,$)", "");
        return actualValue.trim();
    }

    public abstract void perform() throws IOException;
}
            """,
            """package hudson.plugins.depgraph_view.model.operations;

import hudson.model.AbstractProject;
import hudson.security.Permission;
import jenkins.model.Jenkins;

import java.io.IOException;



public abstract class EdgeOperation {
    protected final AbstractProject<?, ?> source;
    protected final AbstractProject<?, ?> target;

    public EdgeOperation(String sourceJobName, String targetJobName) {
        this.source = Jenkins.getInstance().getItemByFullName(sourceJobName.trim(), AbstractProject.class);
        this.target = Jenkins.getInstance().getItemByFullName(targetJobName, AbstractProject.class);
        source.checkPermission(Permission.CONFIGURE);
        target.checkPermission(Permission.CONFIGURE);
    }

    /**
     * Removes double commas and also trailing an leading commas.
     * @param actualValue the actual value to be normalized
     * @return the value with no unrequired commas
     */
    public static String normalizeChildProjectValue(String actualValue){
        actualValue = actualValue.replaceAll("(,[ ]*,)", ", ");
        actualValue = actualValue.replaceAll("(^,|,$)", "");
        return actualValue.trim();
    }

    public abstract void perform() throws IOException;
}
            """
        )
