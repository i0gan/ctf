# 流浪者



```c
int __thiscall sub_401890(CWnd *this)
{
  struct CString *v1; // ST08_4
  CWnd *v2; // eax
  int v3; // eax
  int v5[26]; // [esp+4Ch] [ebp-74h]
  int i; // [esp+B4h] [ebp-Ch]
  char *Str; // [esp+B8h] [ebp-8h]
  CWnd *v8; // [esp+BCh] [ebp-4h]

  v8 = this;
  v1 = (CWnd *)((char *)this + 100);
  v2 = CWnd::GetDlgItem(this, 1002);
  CWnd::GetWindowTextA(v2, v1);
  v3 = sub_401A30((char *)v8 + 100);
  Str = CString::GetBuffer((CWnd *)((char *)v8 + 100), v3);
  if ( !strlen(Str) )
    return CWnd::MessageBoxA(v8, "输入pass!", 0, 0);
  for ( i = 0; Str[i]; ++i )
  {
    if ( Str[i] > '9' || Str[i] < '0' )
    {
      if ( Str[i] > 'z' || Str[i] < 'a' )
      {
        if ( Str[i] > 'Z' || Str[i] < 'A' )
          sub_4017B0(); // fail
        else
          v5[i] = Str[i] - 29;
      }
      else
      {
        v5[i] = Str[i] - 'W';
      }
    }
    else
    {
      v5[i] = Str[i] - '0';
    }
  }
  return sub_4017F0((int)v5);
}
```




```c
BOOL __cdecl sub_4017F0(int a1)
{
  BOOL result; // eax
  char Str1[28]; // [esp+D8h] [ebp-24h]
  int v3; // [esp+F4h] [ebp-8h]
  int i_; // [esp+F8h] [ebp-4h]

  i_ = 0;
  v3 = 0;
  while ( *(_DWORD *)(a1 + 4 * i_) < 62 && *(_DWORD *)(a1 + 4 * i_) >= 0 )
  {
    Str1[i_] = aAbcdefghiabcde[*(_DWORD *)(a1 + 4 * i_)];
    ++i_;
  }
  Str1[i_] = 0;
  if ( !strcmp(Str1, "KanXueCTF2019JustForhappy") )
    result = sub_401770();
  else
    result = sub_4017B0();
  return result;
}

```



## exp

```python
tabel = 'abcdefghiABCDEFGHIJKLMNjklmn0123456789opqrstuvwxyzOPQRSTUVWXYZ'
code = 'KanXueCTF2019JustForhappy'
idx = []

for i in code:
	n = tabel.find(i)
	j = n + 48
	if(j <= ord('9') and j >= ord('0')):
		idx.append(j)
		continue
	j = n + 87
	if(j <= ord('z') and j >= ord('a')):
		idx.append(j)
		continue
	j = n + 29
	if(j <= ord('Z') and j >= ord('A')):
		idx.append(j)
		continue
	print('fail!')

flag = ''
for i in idx:
	flag += chr(i)
print(flag)
```



j0rXI4bTeustBiIGHeCF70DDM