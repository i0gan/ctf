# signin

Use gmpz lib to develop, It's obviously to discovery this  encryption algorithm is rsa.
we should decode rsa then get plaintext

read: https://blog.csdn.net/u014044812/article/details/80866759

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char v4; // [rsp+0h] [rbp-4A0h]
  char v5; // [rsp+10h] [rbp-490h]
  char v6; // [rsp+20h] [rbp-480h]
  char v7; // [rsp+30h] [rbp-470h]
  char str; // [rsp+40h] [rbp-460h]
  char v9; // [rsp+B0h] [rbp-3F0h]
  unsigned __int64 v10; // [rsp+498h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  puts("[sign in]");
  printf("[input your flag]: ", a2);
  __isoc99_scanf("%99s", &str);
  sub_96A(&str, (__int64)&v9);
  __gmpz_init_set_str((__int64)&v7, (__int64)"ad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35", 16LL);
  __gmpz_init_set_str((__int64)&v6, (__int64)&v9, 16LL);
  __gmpz_init_set_str(
    (__int64)&v4,
    (__int64)"103461035900816914121390101299049044413950405173712170434161686539878160984549",
    10LL);
  __gmpz_init_set_str((__int64)&v5, (__int64)"65537", 10LL);
  __gmpz_powm((__int64)&v6, (__int64)&v6, (__int64)&v5, (__int64)&v4);
  if ( (unsigned int)__gmpz_cmp((__int64)&v6, (__int64)&v7) )
    puts("GG!");
  else
    puts("TTTTTTTTTTql!");
  return 0LL;
}
```



## exp

```python
import libnum
c = 0xad939ff59f6e70bcbfad406f2494993757eee98b91bc244184a377520d06fc35 # result
n = 103461035900816914121390101299049044413950405173712170434161686539878160984549 # 
e = 65537
p = 282164587459512124844245113950593348271
q = 366669102002966856876605669837014229419

# http://www.factordb.com/index.php
d = libnum.invmod(e, (p - 1) * (q - 1))
m = pow(c, d, n)

s = hex(m)[2:]
i = 0
t = ''
for _ in range(int(len(s) / 2)):
        n  = int(s[i + 0], 16) * 0x10
        n += int(s[i + 1], 16)
        t += chr(n)
        i += 2

print(t)
```