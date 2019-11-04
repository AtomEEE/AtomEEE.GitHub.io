# Linux 命令集合

### python 小技巧

python -c 'import pty; pty.spawn("/bin/bash")' 交互式shell

### Linux 相关

关于busybox netstate 无-p 如何定位pid：

1. 比如查找5000端口的pid，先换算成16进制：1388

2. *cat /proc/net/tcp grep 1388* 查看inode 

3.  

   ```bash
   for dir in `find /proc -name "fd"`
   
   do 
   
   ls -l $dir | grep "socket\:\[inode\]" && echo $dir
   
   done
   ```

   