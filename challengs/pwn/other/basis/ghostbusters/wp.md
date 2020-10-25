# Ghost busters



思路:

调用vsyscall的sys_time函数即可

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // edx
  void (__fastcall *v6)(__int64 *, _QWORD); // [rsp+8h] [rbp-20h]
  __int64 v7; // [rsp+10h] [rbp-18h]
  unsigned __int64 v8; // [rsp+18h] [rbp-10h]

  v8 = __readfsqword(0x28u);
  v7 = 0LL;
  puts("Who you gonna call?");
  v3 = __isoc99_scanf("%p", &v6);
  v4 = 1;
  if ( v3 == 1 )
  {
    LOBYTE(v7) = 110;
    if ( v6 )
      v6(&v7, &v6);
    if ( (_BYTE)v7 == 0x6E )
    {
      puts("I ain't afraid of no ghost!");
      v4 = 0;
    }
    else
    {
      if ( (_BYTE)v7 == 121 )
        execl("/bin/sh", "sh", 0LL);
      v4 = 0;
    }
  }
  return v4;
}
```

在调用 v6(&v7, &v6), 传入第一个参数为v7,则若能修改v7为121,就可以实现调用execl函数.

time函数是获取一个时间搓

```c
time_t time(time_t *tloc);
```

且v7与121是先转化为byte类型, 再i进行比较,所以打通几率为1 / 256



