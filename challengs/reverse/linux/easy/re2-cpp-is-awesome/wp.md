# re2-cpp-is-awesome



Decomplied with ida to c:

```c++
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char *v3; // rbx
  __int64 v4; // rax
  __int64 v5; // rdx
  __int64 v6; // rax
  __int64 v7; // rdx
  __int64 v8; // rdx
  __int64 i; // [rsp+10h] [rbp-60h]
  char flag; // [rsp+20h] [rbp-50h]
  char v12; // [rsp+4Fh] [rbp-21h]
  __int64 v13; // [rsp+50h] [rbp-20h]
  int v14; // [rsp+5Ch] [rbp-14h]

  if ( a1 != 2 )
  {
    v3 = *a2;
    v4 = std::operator<<<std::char_traits<char>>(&std::cout, "Usage: ", a3);
    v6 = std::operator<<<std::char_traits<char>>(v4, v3, v5);
    std::operator<<<std::char_traits<char>>(v6, " flag\n", v7);
    exit(0);
  }
  std::allocator<char>::allocator(&v12, a2, a3);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&flag, a2[1], &v12);
  std::allocator<char>::~allocator(&v12);
  v14 = 0;
  for ( i = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::begin(&flag); ; sub_400D7A(&i) )
  {
    v13 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::end(&flag);
    if ( !(unsigned __int8)sub_400D3D(&i, &v13) )// judge is over
      break;
    v8 = *(unsigned __int8 *)get_value((__int64)&i);
    if ( (_BYTE)v8 != off_6020A0[dword_6020C0[v14]] )
      quit((__int64)&i, (__int64)&v13, v8);
    ++v14;
  }
  sub_400B73(&i, &v13);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&flag);
  return 0LL;
}
```

Found that is very simple, just to find a character by dword_6020C0[v14] in off_6020A0

the off_6020A0 map as follow:

```
.rodata:0000000000400E58 aL3tMeT3llY0uS0 db 'L3t_ME_T3ll_Y0u_S0m3th1ng_1mp0rtant_A_{FL4G}_W0nt_b3_3X4ctly_th4t'
.rodata:0000000000400E58                                         ; DATA XREF: .data:off_6020A0↓o
.rodata:0000000000400E58                 db '_345y_t0_c4ptur3_H0wev3r_1T_w1ll_b3_C00l_1F_Y0u_g0t_1t',0
```



## exp

```
arr_1 = [0x24, 0x00, 0x05, 0x36, 0x65, 0x07, 0x27, 0x26, 0x2d, 0x01, 0x03, 0x00,
		0x0d, 0x56, 0x01, 0x03, 0x65, 0x03, 0x2d, 0x16, 0x02, 0x15, 0x03, 0x65, 
		0x00, 0x29, 0x44, 0x44, 0x01, 0x44, 0x2b]

map_ = "L3t_ME_T3ll_Y0u_S0m3th1ng_1mp0rtant_A_{FL4G}_W0nt_b3_3X4ctly_th4t_345y_t0_c4ptur3_H0wev3r_1T_w1ll_b3_C00l_1F_Y0u_g0t_1t"

flag = ''
for i in arr_1:
	flag += map_[i]
	
print(len(arr_1))
print(flag)
```