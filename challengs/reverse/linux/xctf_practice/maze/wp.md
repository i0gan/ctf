# maze

from 



we can use ida64 to decomplie this elf file

this is a maze type reverse challenge

found that:

```
.data:0000000000601060 maze            db '  *******   *  **** * ****  * ***  *#  *** *** ***     *********',0
.data:0000000000601060  
```

This is a maze map.

```
  *******   *  **** * ****  * ***  *#  *** *** ***     *********
```



This C code as follows:

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  const char *v3; // rsi
  signed __int64 v4; // rbx
  signed int v5; // eax
  char v6; // bp
  char v7; // al
  const char *v8; // rdi
  __int64 p; // [rsp+0h] [rbp-28h]

  p = 0LL;
  puts("Input flag:");
  scanf("%s", &flag, 0LL);
  if ( strlen(&flag) != 24 || (v3 = "nctf{", strncmp(&flag, "nctf{", 5uLL)) || *(&byte_6010BF + 24) != 125 )
  {
fail:
    puts("Wrong flag!");
    exit(-1);
  }
  v4 = 5LL;
  if ( strlen(&flag) - 1 > 5 )
  {
    while ( 1 )
    {
      v5 = *(&flag + v4);
      v6 = 0;
      if ( v5 > 'N' ) // contro is up or down 
      {
        v5 = (unsigned __int8)v5;
        if ( (unsigned __int8)v5 == 'O' )
        {
          v7 = sub((_DWORD *)&p + 1);
          goto ok;
        }
        if ( v5 == 'o' )
        {
          v7 = add((int *)&p + 1);
          goto ok;
        }
      }
      else // contro is left or right 
      {
        v5 = (unsigned __int8)v5;
        if ( (unsigned __int8)v5 == '.' )
        {
          v7 = sub_400670(&p, v3);
          goto ok;
        }
        if ( v5 == 48 )
        {
          v7 = sub_400680(&p, v3);
ok:
          v6 = v7;
          goto LABEL_15;
        }
      }
LABEL_15:
      v3 = (const char *)HIDWORD(p);
      if ( !(unsigned __int8)check((__int64)maze, SHIDWORD(p), p) )
        goto fail;
      if ( ++v4 >= strlen(&flag) - 1 )
      {
        if ( v6 )
          break;
LABEL_20:
        v8 = "Wrong flag!";
        goto LABEL_21;
      }
    }
  }
  if ( maze[8 * (signed int)p + SHIDWORD(p)] != '#' )
    goto LABEL_20;
  v8 = "Congratulations!";
LABEL_21:
  puts(v8);
  return 0LL;
}
```

The character will control position, only we get to '#' when 18th step, what we input is our flag.

'o' right

'O' left

'0' down

'.' up

Restore to a two-dimensional maze

```
  ******
*   *  *
*** * **
**  * **
*  *#  *
** *** *
**     *
********
```

Make the position to '#', so we input `o0oo00O000oooo..OO`

now flag is: `nctf{o0oo00O000oooo..OO}`