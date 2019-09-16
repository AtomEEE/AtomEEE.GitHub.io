import java.io.*;

public class AntObjectInputStream extends ObjectInputStream {


    public AntObjectInputStream(InputStream inputStream) throws IOException {
        super(inputStream);
    }

    /**
     * 只允许反序列化SerialObject class
     * <p>
     * 在应用上使用黑白名单校验方案比较局限，因为只有使用自己定义的AntObjectInputStream类，进行反序列化才能进行校验。
     * 类似fastjson通用类的反序列化就不能校验。
     * 但是RASP是通过HOOK java/io/ObjectInputStream类的resolveClass方法，全局的检测白名单。
     */
    @Override
    protected Class<?> resolveClass(final ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {
        String className = desc.getName();

        // Deserialize class name: org.joychou.security.AntObjectInputStream$MyObject
        System.out.println("Deserialize class name: " + className);

        String[] denyClasses = {"java.net.InetAddress",
                "org.apache.commons.collections.Transformer",
                "org.apache.commons.collections.functors"};

        for (String denyClass : denyClasses) {
            if (className.startsWith(denyClass)) {System.out.println("Found denyClass"); }
        }

        return super.resolveClass(desc);
    }
}
