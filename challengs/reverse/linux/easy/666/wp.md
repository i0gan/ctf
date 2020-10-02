# 666



```
int __fastcall encode(const char *a1, __int64 s)
{
  char v3[32]; // [rsp+10h] [rbp-70h]
  char v4[32]; // [rsp+30h] [rbp-50h]
  char v5[40]; // [rsp+50h] [rbp-30h]
  int v6; // [rsp+78h] [rbp-8h]
  int i; // [rsp+7Ch] [rbp-4h]

  i = 0;
  v6 = 0;
  if ( strlen(a1) != key )
    return puts("Your Length is Wrong");
  for ( i = 0; i < key; i += 3 )
  {
    v5[i] = key ^ (a1[i] + 6);
    v4[i + 1] = (a1[i + 1] - 6) ^ key;
    v3[i + 2] = a1[i + 2] ^ 6 ^ key;
    *(_BYTE *)(s + i) = v5[i];
    *(_BYTE *)(s + i + 1LL) = v4[i + 1];
    *(_BYTE *)(s + i + 2LL) = v3[i + 2];
  }
  return s;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-1E0h]
  char v5; // [rsp+F0h] [rbp-F0h]

  memset(&s, 0, 0x1EuLL);
  printf("Please Input Key: ", 0LL);
  __isoc99_scanf("%s", &v5);
  encode(&v5, (__int64)&s);
  if ( strlen(&v5) == key )
  {
    if ( !strcmp(&s, enflag) )
      puts("You are Right");
    else
      puts("flag{This_1s_f4cker_flag}");
  }
  return 0;
}
```

## exp

```
code = 'izwhroz""w"v.K".Ni'
key = 0x12
flag = ''
i = 0
while(True):
	if(i >= key):
		break
	flag += chr((ord(code[i + 0]) ^ key) - 6)
	flag += chr((ord(code[i + 1]) ^ key) + 6)
	flag += chr(ord(code[i + 2]) ^ 6 ^ key)
	i = i + 3
print(flag)

```