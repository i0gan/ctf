# hackme



```
__int64 __fastcall sub_400F8E(__int64 a1, __int64 a2)
{
  __int64 v2; // rdx
  __int64 none_1; // rcx
  __int64 v4; // r8
  __int64 v5; // r9
  int len; // eax
  char str[136]; // [rsp+10h] [rbp-B0h]
  int v9; // [rsp+98h] [rbp-28h]
  char none_3; // [rsp+9Fh] [rbp-21h]
  int v11; // [rsp+A0h] [rbp-20h]
  unsigned __int8 v12; // [rsp+A6h] [rbp-1Ah]
  char ch_; // [rsp+A7h] [rbp-19h]
  int none_2; // [rsp+A8h] [rbp-18h]
  int v15; // [rsp+ACh] [rbp-14h]
  unsigned int v16; // [rsp+B0h] [rbp-10h]
  int times; // [rsp+B4h] [rbp-Ch]
  _BOOL4 con; // [rsp+B8h] [rbp-8h]
  int i; // [rsp+BCh] [rbp-4h]

  puts((unsigned __int64)"Give me the password: ");
  scanf((__int64)"%s", str, a2);
  for ( i = 0; str[i]; ++i )
    ;
  con = i == 22;
  times = 10;
  do
  {
    len = sub_406D90((__int64)"%s", (__int64)str, v2, none_1, v4, v5);
    none_1 = (unsigned int)(len % 0x16);
    none_2 = len % 0x16;
    v16 = 0;
    ch_ = byte_6B4270[len % 0x16];
    v12 = str[len % 0x16];
    v11 = len % 0x16 + 1;
    v15 = 0;
    while ( v15 < v11 )
    {
      ++v15;
      v16 = 0x6D01788D * v16 + 0x3039;
    }
    v2 = v16;
    none_3 = v16 ^ v12;
    if ( ch_ != ((unsigned __int8)v16 ^ v12) )
      con = 0;
    --times;
  }
  while ( times );
  if ( con )
    v9 = puts((unsigned __int64)"Congras\n");
  else
    v9 = puts((unsigned __int64)"Oh no!\n");
  return 0LL;
}
```



## exp

```python
map_ = [0x5F, 0xF2 ,0x5E ,0x8B ,0x4E ,0x0E ,0xA3 ,0xAA ,0xC7 ,0x93 ,0x81 ,0x3D , 0x5F ,0x74 ,0xA3 ,0x09
,0x91 ,0x2B ,0x49 ,0x28 ,0x93 ,0x67 ,0x00 ,0x00  ,0x00 ,0x08 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00]
flag = ''
for i in range(22):
	v_ = i + 1;
	j = 0
	r = 0
	while j < v_:
		j += 1
		r = 0x6D01788D * r + 0x3039;
	flag += chr((map_[i] ^ r) & 0xFF)

print(flag)

```

