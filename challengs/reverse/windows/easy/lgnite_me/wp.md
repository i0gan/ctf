

# lgnite_me



```c

int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *v3; // eax
  int v4; // edx
  void *v5; // eax
  int result; // eax
  void *v7; // eax
  void *v8; // eax
  void *v9; // eax
  size_t i; // [esp+4Ch] [ebp-8Ch]
  char str[4]; // [esp+50h] [ebp-88h]
  char v12[28]; // [esp+58h] [ebp-80h]
  char v13; // [esp+74h] [ebp-64h]

  v3 = (void *)puts((int)&unk_446360, (int)"Give me your flag:");
  sub_4013F0(v3, (int (__cdecl *)(void *))sub_403670);
  input((int)&dword_4463F0, v4, (int)v12, 127);
  if ( strlen(v12) < 0x1E && strlen(v12) > 4 )
  {
    strcpy(str, "EIS{");
    for ( i = 0; i < strlen(str); ++i )
    {
      if ( v12[i] != str[i] )
      {
        v7 = (void *)puts((int)&unk_446360, (int)"Sorry, keep trying! ");
        sub_4013F0(v7, (int (__cdecl *)(void *))sub_403670);
        return 0;
      }
    }
    if ( v13 == '}' )
    {
      if ( check(v12) )
        v9 = (void *)puts((int)&unk_446360, (int)"Congratulations! ");
      else
        v9 = (void *)puts((int)&unk_446360, (int)"Sorry, keep trying! ");
      sub_4013F0(v9, (int (__cdecl *)(void *))sub_403670);
      result = 0;
    }
    else
    {
      v8 = (void *)puts((int)&unk_446360, (int)"Sorry, keep trying! ");
      sub_4013F0(v8, (int (__cdecl *)(void *))sub_403670);
      result = 0;
    }
  }
  else
  {
    v5 = (void *)puts((int)&unk_446360, (int)"Sorry, keep trying!");
    sub_4013F0(v5, (int (__cdecl *)(void *))sub_403670);
    result = 0;
  }
  return result;
}

bool __cdecl check(char *str)
{
  size_t v2; // eax
  signed int v3; // [esp+50h] [ebp-B0h]
  char v4[32]; // [esp+54h] [ebp-ACh]
  int v5; // [esp+74h] [ebp-8Ch]
  int v6; // [esp+78h] [ebp-88h]
  size_t i; // [esp+7Ch] [ebp-84h]
  char v8[128]; // [esp+80h] [ebp-80h]

  if ( strlen(str) <= 4 )
    return 0;
  i = 4;
  v6 = 0;
  while ( i < strlen(str) - 1 )
    v8[v6++] = str[i++];
  v8[v6] = 0;
  v5 = 0;
  v3 = 0;
  memset(v4, 0, 0x20u);
  for ( i = 0; ; ++i )
  {
    v2 = strlen(v8);
    if ( i >= v2 )
      break;
    if ( v8[i] >= 'a' && v8[i] <= 'z' )
    {
      v8[i] -= 32;
      v3 = 1;
    }
    if ( !v3 && v8[i] >= 'A' && v8[i] <= 'Z' )
      v8[i] += 32;
    v4[i] = byte_4420B0[i] ^ sub_4013C0(v8[i]);
    v3 = 0;
  }
  return strcmp("GONDPHyGjPEKruv{{pj]X@rF", v4) == 0;
}

int __cdecl sub_4013C0(int a1)
{
  return (a1 ^ 0x55) + 72;
}
```





## exp

```python

c = 'GONDPHyGjPEKruv{{pj]X@rF'
m_1 = [0x0D,0x13,0x17,0x11,0x02,0x01,0x20,0x1D,0x0C,0x02,0x19,0x2F,0x17,0x2B,0x24,0x1F,
	0x1E,0x16,0x09,0x0F,0x15,0x27,0x13,0x26,0x0A,0x2F,0x1E,0x1A,0x2D,0x0C,0x22,0x04]
m_2 = []

f = []
#c[i] == m_1[i] ^ ((f[i] ^ 0x55) + 72)

i = 0
for _ in c:
	f.append(((ord(c[i]) ^ m_1[i]) - 72) ^ 0x55)
	i += 1

flag = ''
for o in f:
	n = o + 32		
	if(n >= ord('a') and n <= ord('z')):
		flag += chr(n)
		continue
	n = o - 32
	if(n >= ord('A') and n <= ord('Z')):
		flag += chr(n)
		continue
	
	flag += chr(o)
print('EIS{' + flag + '}')

```

