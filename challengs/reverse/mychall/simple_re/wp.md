# 制作过程



### 编译

* 注: flag文件在源码文件夹中

进入 源代码目录

首先安装 upx 压缩软件

```
sudo apt install upx
```

编译

```
chmod +x complie.sh
./complie.sh
```

编译后即可获得 simple_re 文件

### 源代码

```c++
#include <cstdio>
#include <string>
#include <getopt.h>
#include <iostream>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <cstring>
#include <unistd.h>


struct flag_data {
	char buf[65] = {0};
	int c_pos = 0;
	int length = 0;
};

const char *real_flag = "^%+%!%^%+^+%@^)$%$!$#$&%*@-&&@=$!$`!+%%%#@$^&$=!%$*$&^~&*$=#+@(^+$=@+^%~";

struct flag_data flag;
sem_t sem_1, sem_2;


void *thread_func_1(void *arg);
void *thread_func_2(void *arg);
std::string encode(const std::string &s);
bool check_flag();

void *thread_func_1(void *arg) {
	while(flag.c_pos < flag.length) {
		flag.buf[flag.c_pos] = flag.buf[flag.c_pos] ^ (flag.c_pos % 16) + 1;
		++flag.c_pos;
		sem_post(&sem_1);
		sem_wait(&sem_2);	
	}
	sem_post(&sem_1);
	flag.buf[flag.c_pos] = '\x0';
	return (void*)0;
}

void *thread_func_2(void *arg) {
	while(flag.c_pos < flag.length) {
		sem_wait(&sem_1);	
		flag.buf[flag.c_pos] = (flag.buf[flag.c_pos] ^ (flag.c_pos % 32)) + (flag.c_pos % 16);
		++flag.c_pos;
		sem_post(&sem_2);
	}
	sem_post(&sem_2);
	flag.buf[flag.c_pos] = '\x0';
	return (void*)0;
}

bool check_flag() {
	std::string flag_ = encode(flag.buf);
	//std::cout << "ok[" << flag.buf << "] re [" << flag_ << "] real_flag[" << real_flag << "]\n";
	return flag_ == real_flag;
}

std::string encode(const std::string &s) {
	static const char* code_chars = "~`!@#$%^&*()-_+={}[]:;\"'|\\<>?,./";
	int len = s.size();
	std::string res;
	res.reserve(len * 2);
	for (int i = 0; i < len; i += 1) {
		struct enc {
			unsigned char a:4;
			unsigned char b:4;
		}* encoder = (struct enc *)(s.data() + i);
		char out[2];
		out[0] = code_chars[encoder->a];
		out[1] = code_chars[encoder->b];
		res += std::string(out, sizeof(out));
	}
	return res;
}


int main(int argc, char **argv) {
	if(argc < 3) {
		std::cout << "Useage: ./simple_re [-f] [your flag]" << '\n';
		return 0;
	}

	const char *str = "f:";
	char opt = getopt(argc, argv, str);
	if(__builtin_expect(opt != 'f', 0)) {
		std::cout << "error usage\n";
		return -1;
	}

	if(sem_init(&sem_1, 0, 0) != 0) {
		perror("sem_init");
		return -1;
	}

	if(sem_init(&sem_2, 0, 0) != 0) {
		perror("sem_init");
		return -1;
	}

	// copy flag data to global flag_buf

	memcpy(flag.buf, argv[2], 64);
	flag.buf[64] = '\x00';
	flag.length = strlen(flag.buf);

	pthread_t tid_1, tid_2;
	if(pthread_create(&tid_1, nullptr, thread_func_1, nullptr) != 0) {
		perror("pthread_create");
		return -1;
	}

	if(pthread_create(&tid_2, nullptr, thread_func_2, nullptr) != 0) {
		perror("pthread_create");
		return -1;
	}

	pthread_join(tid_1, nullptr);
	pthread_join(tid_2, nullptr);

	std::cout << "Wait...\n";
	sleep(1);

	if(check_flag()) {
		std::cout << "Congratulations! You did it!\n";
	}else {
		std::cout << "No! You are wrong!\n";
	}
	return 0;
}

```



# write up 

考点: upx壳, 线程的基本认识, 信号量的基本认识,  简单加密算法

### 解壳

使用ida打开,发现只有极少的函数,查看hex view面板

发现是upx压缩过的, 只需下载upx软件解压即可

```
 74 20 28 43 29 20 31 39  39 36 2D 32 30 32 30 20  t (C) 1996-2020 
 74 68 65 20 55 50 58 20  54 65 61 6D 2E 20 41 6C  the UPX Team. Al
 6C 20 52 69 67 68 74 73  20 52 65 73 65 72 76 65  l Rights Reserve
 64 2E 20 24 0A 00 90 90  6A 0E 5A 57 5E EB 01 5E  d. $....j.ZW^...
 6A 02 5F 6A 01 58 0F 05  6A 7F 5F 6A 3C 58 0F 05  j._j.X..j._j<X..
 5F 29 F6 6A 02 58 0F 05  85 C0 78 DC 50 48 8D B7  _)...........H..
```

安装与解压

```
sudo apt install upx
upx -d simple_re  # 进行解压
```



### 分析 main函数

解压后打开解压后使用ida打开二进制文件

首先找到主函数, 如下:

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  int result; // eax
  __int64 v5; // [rsp+20h] [rbp-20h]
  __int64 v6; // [rsp+28h] [rbp-18h]
  const char *v7; // [rsp+30h] [rbp-10h]
  unsigned __int64 v8; // [rsp+38h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  if ( argc > 2 )
  {
    v7 = "f:";
      // 获取参数
    if ( (unsigned __int8)getopt((unsigned int)argc, argv, "f:") == 102 )
    {
        // 初始化信号量1
      if ( (unsigned int)sem_init(&sem_1, 0LL, 0LL) != 0 )
      {
        perror("sem_init");
        result = -1;
      }
        // 初始化信号量2
      else if ( (unsigned int)sem_init(&sem_2, 0LL, 0LL) != 0 )
      {
        perror("sem_init");
        result = -1;
      }
      else
      {
          // 从控制台复制flag到 全局变量的flag
        j_memcpy(&flag, argv[2], 64LL);
        byte_5CF680 = 0;
        dword_5CF688 = j_strlen_ifunc(&flag); // 储存flag长度
         // 创建线程1
        if ( (unsigned int)pthread_create(&v5, 0LL, thread_func_1, 0LL) != 0 )
        {
          perror("pthread_create");
          result = -1;
        }
          // 创建线程2
        else if ( (unsigned int)pthread_create(&v6, 0LL, thread_func_2, 0LL) != 0 )
        {
          perror("pthread_create");
          result = -1;
        }
        else
        {
           // 等待线程运行完毕
          pthread_join(v5, 0LL);
          pthread_join(v6, 0LL);
          std::operator<<<std::char_traits<char>>((std::ostream *)&std::cout);
          sleep(1LL, "Wait...\n");
          if ( (unsigned __int8)check_flag() ) // 检查flag是否正确
            std::operator<<<std::char_traits<char>>((std::ostream *)&std::cout);
          else
            std::operator<<<std::char_traits<char>>((std::ostream *)&std::cout);
          result = 0;
        }
      }
    }
    else
    {
      std::operator<<<std::char_traits<char>>((std::ostream *)&std::cout);
      result = -1;
    }
  }
  else
  {
    v3 = std::operator<<<std::char_traits<char>>((std::ostream *)&std::cout);
    std::operator<<<std::char_traits<char>>(v3, 10LL);
    result = 0;
  }
  return result;
}
```

### 分析线程函数

从main函数就发现使用了线程函数,还用信号量, 那么跟踪到线程函数里,

thread_func_1

```c++
__int64 __fastcall thread_func_1(void *a1)
{
  while ( dword_5CF684 < dword_5CF688 )  // 从main函数中 dword_5CF688该值是储存flag的长度的
  {
    //对flag进行加密
    flag[dword_5CF684] ^= (unsigned __int8)(dword_5CF684 % 16) + 1;
    ++dword_5CF684;   // 某个全局变量的值增加1
    sem_post(&sem_1); // 发送信号量sem_1
    sem_wait(&sem_2); // 等待信号量sem_2
  }
  sem_post(&sem_1); // 发送信号量sem_1
  flag[dword_5CF684] = 0;
  return 0LL;
}
```



thread_func_2

```c++
__int64 __fastcall thread_func_2(void *a1)
{
  while ( dword_5CF684 < dword_5CF688 )
  {
    // 等待信号量sem_1
    sem_wait(&sem_1);
    //对flag进行加密
    flag[dword_5CF684] = (flag[dword_5CF684] ^ dword_5CF684 % 32) + dword_5CF684 % 16;
    ++dword_5CF684;   // 某个全局变量的值增加1
    sem_post(&sem_2); // 发送信号量sem_2
  }
  sem_post(&sem_2);
  flag[dword_5CF684] = 0;
  return 0LL;
}
```

那么从以上可以清晰的看到,这两个创建的子线程互相对flag进行加密, 使用信号量来实现同步, 那最初加密的线程为第一个,然后再到第二个然后再到第一个,依次交替进行加密

回到main函数里, 进入check_flag函数里

### 分析 check_flag函数

为了更好的分析c++的stl, 这里只做一个简单的描述, 大部分c++ stl 都采用构造器来进行内存管理, 再进行stl内构造的时候大多数容器都会事先声明好一个构造器进行传入容器, 容器析构时, 会对构造器也进行析构, 当函数返回对象时, 编译器会以参数的方式传递将要被赋值的对象指针, 这个参数通常是放在函数的第一位

```c++
__int64 check_flag(void)
{
  unsigned int v0; // ebx
  char v2; // [rsp+Fh] [rbp-61h]
  char v3; // [rsp+10h] [rbp-60h]
  char v4; // [rsp+30h] [rbp-40h]
  unsigned __int64 v5; // [rsp+58h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  std::allocator<char>::allocator(&v2); // 创建一个构造器 v2
  // 声明一个 basic_strig, basic_string 是string的一个父类, 将 v2构造器和要储存对象的指针v4还有值flag进行传入
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v4, flag, &v2);    // 将 输入已经加密后的flag 用 basic_string v4储存起来, 然后传入encode中
  encode(&v3, &v4); // 传入v4对输入的flag再次加密, v3是加密后的结果
    // 析构v4对象
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v4);
    // 析构v4 对象的构造器v2
  std::allocator<char>::~allocator(&v2);
    // 判断v3是否与real_flag相等
  v0 = std::operator==<char,std::char_traits<char>,std::allocator<char>>(&v3, real_flag[0]);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v3);
  return v0;
}
```

跟踪encode函数如下:

### 分析encode函数

依次分析如下

```c++
__int64 __fastcall encode(__int64 target, __int64 encode_flag_1)
{
  __int64 str_data_hader_ptr; // rax
  char v4; // [rsp+1Fh] [rbp-51h]
  int i; // [rsp+20h] [rbp-50h]
  int size; // [rsp+24h] [rbp-4Ch]
  _BYTE *current_ptr; // [rsp+28h] [rbp-48h]
  char v8; // [rsp+30h] [rbp-40h]
  char v9; // [rsp+56h] [rbp-1Ah]
  char v10; // [rsp+57h] [rbp-19h]
  unsigned __int64 v11; // [rsp+58h] [rbp-18h]

  v11 = __readfsqword(0x28u);
    // size变量储存获取传入的加密后flag的大小
  size =      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(encode_flag_1);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(target);
    // 改变容器的大小, 不改变容器的有效元素个数, 这里设置为原来大小的2倍
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::reserve(target, 2 * size);
    // 循环进行加密
  for ( i = 0; i < size; ++i )
  {
      // 储存传入的flag的数据头指针
    str_data_hader_ptr = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::data(encode_flag_1);
     // 当前数据偏移的指针
    current_ptr = (_BYTE *)(i + str_data_hader_ptr);
      // v9 储存 code_chars[*curent_ptr & 0xF], 那么code_chars是什么呢, 稍等我们跟踪看看
    v9 = encode(std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>> const&)::code_chars[*current_ptr & 0xF];
      // v10 储存 code_chars[*curent_ptr >> 4]
    v10 = encode(std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>> const&)::code_chars[(unsigned __int8)(*current_ptr >> 4)];
    std::allocator<char>::allocator(&v4);
 //  将v9 储存再v8里, 储存2字节, 由于v9 与v10是连续的, 所以就相当于这里是将v9 和v10储存再 v8中
std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v8, &v9, 2LL, &v4);
   //  将v8 追加到target字符串中
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(target, &v8);
      
 //析构 v8 string     
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v8);
      // 析构v8的构造器
    std::allocator<char>::~allocator(&v4);
  }
  return target;
}
```

上面表达的意思是, 将一个字节分成两个字节, 一个是高位, 另一个是低位.然后根据code_chars获取值放在target容器里.

那么code_chars里储存的是什么? 跟踪进来看看

```
.data:00000000005CD138 _ZZ6encodeRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEE10code_chars dq offset asc_56C060
```

点击 offset_asc_56C060

```
.rodata:000000000056C060 asc_56C060      db '~`!@#$%^&*()-_+={}[]:;"',27h,'|\<>?,./',0
```

可以看到是一个字符串 '~`!@#$%^&*()-_+={}[]:;"',27h,'|\<>?,./', 那么上面的code_chars就是这这个字符串了

encode函数大致加密原理

将一个字符分成两个字符, 一个低位一个高位, 再通过这个值当做索引值去从code_chars表中获取一个值,让后追加到目标 容器里

### 获取加密后的flag

分析以上代码后, 回到check_flag函数里, 下面可以跟踪real_flag变量

```
.data:00000000005CD130 real_flag       dq offset asc_56C010    ; DATA XREF: check_flag(void)+66↑r
.data:00000000005CD130                                         ; "^%+%!%^%+^+%@^)$%$!$#$&%*@-&&@=$!$`!+%%"...
```

再次点击offset asc_56C010进入

```
.rodata:000000000056C010 asc_56C010      db '^%+%!%^%+^+%@^)$%$!$#$&%*@-&&@=$!$`!+%%%#@$^&$=!%$*$&^~&*$=#+@(^+'
.rodata:000000000056C010                                         ; DATA XREF: .data:real_flag↓o
.rodata:000000000056C010                 db '$=@+^%~',0 //到此处0截断
.rodata:000000000056C059                 align 20h
```

 那么可以看到

注意这个real_flag下一行还有值直到0为止, 最终加密后的flag应该为

```
 ^%+%!%^%+^+%@^)$%$!$#$&%*@-&&@=$!$`!+%%%#@$^&$=!%$*$&^~&*$=#+@(^+$=@+^%~
```



分析完毕, 开始逆这窜字符串吧

### 逆向encode函数

先对encode函数进行逆向, 只要根据real_flag的值去找code_chars的索引值然后分别高低位组成一个字节的值即可

exp如下

```c++

#include <iostream>
#include <string>
std::string decode_1(const std::string &real_flag) {
        std::string code_chars = "~`!@#$%^&*()-_+={}[]:;\"',27h,'|\\<>?,./'";
        std::string ret;
        for(int i = 0; i < real_flag.size(); i+= 2) {
                unsigned char c_1 = code_chars.find(real_flag[i]);
                unsigned char c_2 = code_chars.find(real_flag[i + 1]);
                unsigned char c = c_1  + c_2 * 16;
        }
        return ret;
}
```

逆出结果为为gnbg~ns[VRTh9�8_R!nf4uX/VYx�YO>z^?~

```
[logan@arch wp]$ ./a.out 
gnbg~ns[VRTh9�8_R!nf4uX/VYx�YO>z^?~
```



### 逆向线程加密函数

思路是, 两个线程分别交替执行加密, 最先加密的是线程1然后线程2, exp如下

```c++
std::string decode_2(const std::string &encode_flag) {
        std::string flag;
        int pos = 0;
        int length = encode_flag.length();

        while(pos < length) {
                // decode thread 1
                if(pos % 2 == 0 ) {
                        flag += encode_flag[pos] ^ (pos % 16 + 1);
                // decode thread 2
                } else {
                        flag += (encode_flag[pos] - (pos % 16)) ^ (pos % 32);
                }
                ++ pos;
        }

        return flag;
}
```

### Exp

```c++
// g++ exp.cc
// ./a.out

#include <iostream>
#include <string>

std::string decode_1(const std::string &real_flag) {
        std::string code_chars = "~`!@#$%^&*()-_+={}[]:;\"',27h,'|\\<>?,./'";
        std::string ret;
        for(int i = 0; i < real_flag.size(); i+= 2) {
                unsigned char c_1 = code_chars.find(real_flag[i]);
                unsigned char c_2 = code_chars.find(real_flag[i + 1]);
                unsigned char c = c_1  + c_2 * 16;
                ret += c;
        }
        return ret;
}

std::string decode_2(const std::string &encode_flag) {
        std::string flag;
        int pos = 0;
        int length = encode_flag.length();

        while(pos < length) {
                // decode thread 1
                if(pos % 2 == 0 ) {
                        flag += encode_flag[pos] ^ (pos % 16 + 1);
                // decode thread 2
                } else {
                        flag += (encode_flag[pos] - (pos % 16)) ^ (pos % 32);
                }
                ++ pos;
        }

        return flag;
}

int main(int, char**) {
        std::string real_flag = "^%+%!%^%+^+%@^)$%$!$#$&%*@-&&@=$!$`!+%%%#@$^&$=!%$*$&^~&*$=#+@(^+$=@+^%~";
        std::string encode_flag = decode_1(real_flag);
        std::cout << encode_flag << '\n';
        std::string flag = decode_2(encode_flag);
        std::cout << flag << '\n';

        return 0;
}

```



运行结果

````
[logan@arch wp]$ ./a.out 
gnbg~ns[VRTh9�8_R!nf4uX/VYx�YO>z^?~
flag{ltS_@_V4r7_S1mp1e_?_IsnT_1t_?}
````
