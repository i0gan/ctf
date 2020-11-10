# PWN FOR AWD 

扫描对方IP:
ifconfig (先获取自己的IP)
netdiscover -r 192.168.0.1/24   (扫描1~124的IP)

获取IP后:
nmap -sV 192.168.0.104 (端口扫描)
nmap -A -v -T4 192.168.0.104 (TCP 端口扫描)



ssh操作

ssh <-p 端口> 用户名@IP　　//登录
scp 文件路径  用户名@IP:存放路径　　//向ssh服务器上传输文件

用户管理
　　w 　　//查看当前用户
　　pkill -kill -t <用户tty>　　 //踢掉当前登录用户

进程管理

　　ps aux | grep pid或者进程名　　//查看进程信息

　　查看已建立的网络连接及进程
　　netstat -antulp | grep EST

　　查看指定端口被哪个进程占用
　　lsof -i:端口号 或者 netstat -tunlp|grep 端口号

　　结束进程命令
　　kill PID
　　killall <进程名>
　　kill -9 <PID>

iptables命令

　　封杀某个IP或者ip段，如：123.4.5.6
　　iptables -I INPUT -s 123.4.5.6 -j DROP
　　iptables -I INPUT -s 123.4.5.1/24 -j DROP

　　禁止从某个主机ssh远程访问登陆到本机，如123.4.5.6
　　iptable -t filter -A INPUT -s 123.4.5.6 -p tcp --dport 22 -j DROP

安全检查

　　find / *.php -perm 4777 　　 //查找777的权限的php文件 
　　awk -F: '{if($3==0)print $1}' /etc/passwd　　//查看root权限的账号
　　crontab -l　　//查看计划任务

　　检测所有的tcp连接数量及状态
　　netstat -ant|awk '{print $5 "\t" $6}' |grep "[1-9][0-9]*\."|sed -e 's/::ffff://' -e 's/:[0-9]*//'|sort|uniq -c|sort -rn

　　查看页面访问排名前十的IP
　　cat /var/log/apache2/access.log | cut -f1 -d " " | sort | uniq -c | sort -k 1 -r | head -10

　　查看页面访问排名前十的URL
　　cat /var/log/apache2/access.log | cut -f4 -d " " | sort | uniq -c | sort -k 1 -r | head -10　　



  

