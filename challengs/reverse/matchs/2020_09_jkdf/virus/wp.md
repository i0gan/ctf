# virus

是一个简单的迷宫题.采用4个迷宫, 需要自己根据字符串长度调整迷宫顺序.

主逻辑代码

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v5; // [esp+14h] [ebp-4Ch]
  int v6; // [esp+3Ch] [ebp-24h]
  int v7; // [esp+40h] [ebp-20h]
  int v8; // [esp+44h] [ebp-1Ch]
  int v9; // [esp+48h] [ebp-18h]
  int v10; // [esp+4Ch] [ebp-14h]
  size_t v11; // [esp+50h] [ebp-10h]
  int len; // [esp+54h] [ebp-Ch]
  int i; // [esp+58h] [ebp-8h]
  int times; // [esp+5Ch] [ebp-4h]

  __main();
  puts("There is a long way to defeat it.");
  scanf("%s", flag);
  len = strlen(flag);
  v6 = 0;
  v7 = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0;
  times = 0;
  v11 = 0;
  for ( i = 0; i < len; ++i )
  {
    if ( flag[i] == '-' )
    {
      v3 = times++;
      *(&v6 + v3) = i;                          // length
    }
    if ( !times )
    {
      *(&v5 + i) = flag[i] - '0';               // check is number
      if ( *(&v5 + i) > 9 || *(&v5 + i) < 0 )
        return 0;
    }
  }
  if ( times != 4 )                             // 4
    return 0;
  v10 = len;
  for ( i = 1; i <= times; ++i )
  {
    v11 = *(&v6 + i) - *(&v6 + i - 1) - 1;
    if ( step[i] != v11 )                       // check length
      return 0;
    strncpy(&road[0xC8 * i], &flag[*(&v6 + i - 1) + 1], v11);
  }
  for ( i = 0; i <= 3; ++i )
  {
    if ( check_flag((int)&global_map + 0xC8 * *(&v5 + i), *(&v5 + i), &road[200 * (i + 1)]) )
    {
      puts("How about try again?");
      return 0;
    }
    if ( i == 3 )
      printf("Great! We will defeat it!!! your flag is flag{%s}", flag);
  }
  return 0;
}
```

解释一下, 要求输入四个'-', 在输入'-'之前必须为数字, 然后在对字符串的进行'-'分割, ‘-’后面的长度分别为: 19, 25, 26, 28.这个从`step[i] != v11`所判断的, 如下:

```
.data:00403468 _step           dd 0                    ; DATA XREF: _main+13F↑r
.data:0040346C                 dd 19
.data:00403470                 dd 25
.data:00403474                 dd 26
.data:00403478                 dd 28
.data:0040347C                 db    0
.data:0040347D                 db    0
.data:0040347E                 db    0
.data:0040347F                 db    0
```

通过以上逻辑, 输入的格式必须满足`  -str1-str2-str3-str4`

接着看check_flag函数:

```
bool __cdecl check_flag(int a1, int a2, char *a3)
{
  bool result; // eax
  signed int length; // [esp+10h] [ebp-18h]
  int width; // [esp+14h] [ebp-14h]
  int hight; // [esp+18h] [ebp-10h]
  signed int i; // [esp+1Ch] [ebp-Ch]

  length = strlen(a3);
  hight = start[2 * a2];
  width = dword_403444[2 * a2];
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= length )
      break;
    switch ( a3[i] )
    {
      case 'w':
        --hight;
        break;
      case 's':
        ++hight;
        break;
      case 'a':
        --width;
        break;
      case 'd':
        ++width;
        break;
      default:
        return 1;
    }
    if ( width < 0 || width > 19 || hight < 0 || hight > 10 ) //迷宫宽度 20, 高度10
      return 1;
    if ( length - 1 == i )
      return *(_BYTE *)(a1 + 20 * hight + width) != 'd';
    if ( *(_BYTE *)(a1 + 20 * hight + width) != '.' )
      return 1;
  }
  return result;
}
```

就是一个典型的迷宫了,使用`wsad`字符来控制.

那么我们所输入的就需要这四个字符来控制了, 先找一下迷宫的地图, 且进行宽度为20进行补齐如下:

```
|||||||||||||||.....
|||||||||||||||.....
|||||||||||||||.....
||s.........|||.....
|||||||||||.|||.....
||d||||||||.|||.....
||.||||||||.|||.....
||.||||||||.|||.....
||..........|||.....
|||||||||||||||.....
|||||||||||||||||||.
||s|||||||||||||d||.
||..|||||||||||..||.
|||..|||||||||..|||.
||||..|||||||..||||.
|||||..|||||..|||||.
||||||..|||..||||||.
|||||||..|..|||||||.
||||||||...||||||||.
|||||||||||||||||||.
|||||||||||||||.....
||.........s|||.....
||.||||||||||||.....
||.||||||||||||.....
||.||||||||||||.....
||.||||||||||||.....
||.||||||||||||.....
||.||||||||||||.....
||.........d|||.....
|||||||||||||||.....
|||||||||||||||.....
|||||||||||||||.....
|||||||||||||||.....
|||..........||.....
|||.||||||||.||.....
|||.||||||||.||.....
|||.||||||||.||.....
|||.||||||||.||.....
|||s||||||||d||.....
|||||||||||||||.....
```

从s出发到d结束, 那么四个迷宫分别步骤如下:

`dddddddddsssssaaaaaaaaawww `

`sdsdsdsdsdsdsddwdwdwdwdwdwdw`

`aaaaaaaaasssssssddddddddd `

`wwwwwdddddddddsssss`

当我输入` -dddddddddsssssaaaaaaaaawww-sdsdsdsdsdsdsddwdwdwdwdwdwdw-aaaaaaaaasssssssddddddddd-wwwwwdddddddddsssss`发现, 在调用check_flag传入map参数执偏离原map很大的一个地址,且进入check_flag函数获取map中的值都是0,原来在输入步骤之前需要指定地图的顺序.

根据前面我们知道每个字符串的长度(19, 25, 26, 28)来指定:

那就是`-wwwwwdddddddddsssss-aaaaaaaaasssssssddddddddd-dddddddddsssssaaaaaaaaawww-sdsdsdsdsdsdsddwdwdwdwdwdwdw`

在确定一下迷宫的顺序为:

4312

那么输入的就是:

`4312-wwwwwdddddddddsssss-aaaaaaaaasssssssddddddddd-dddddddddsssssaaaaaaaaawww-sdsdsdsdsdsdsddwdwdwdwdwdwdw`

那么就出flag啦...

