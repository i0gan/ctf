# srm-50

Main code as follow:

```
BOOL __stdcall DialogFunc(HWND hDlg, UINT a2, WPARAM a3, LPARAM a4)
{
  HMODULE v5; // eax
  HICON v6; // eax
  HMODULE v7; // eax
  HCURSOR v8; // ST20_4
  HWND v9; // eax
  CHAR str_1; // [esp+8h] [ebp-340h]
  CHAR str_2[4]; // [esp+108h] [ebp-240h]
  char v12; // [esp+10Ch] [ebp-23Ch]
  char v13; // [esp+10Dh] [ebp-23Bh]
  char v14; // [esp+10Eh] [ebp-23Ah]
  char v15; // [esp+10Fh] [ebp-239h]
  char v16; // [esp+110h] [ebp-238h]
  char v17; // [esp+111h] [ebp-237h]
  char v18; // [esp+112h] [ebp-236h]
  char v19; // [esp+113h] [ebp-235h]
  char v20; // [esp+114h] [ebp-234h]
  char v21; // [esp+115h] [ebp-233h]
  char v22; // [esp+116h] [ebp-232h]
  char v23; // [esp+117h] [ebp-231h]
  CHAR Text; // [esp+208h] [ebp-140h]
  char Src[16]; // [esp+308h] [ebp-40h]
  __int128 v26; // [esp+318h] [ebp-30h]
  int v27; // [esp+328h] [ebp-20h]
  __int128 v28; // [esp+32Ch] [ebp-1Ch]
  int v29; // [esp+33Ch] [ebp-Ch]
  __int16 v30; // [esp+340h] [ebp-8h]

  if ( a2 == 16 )
  {
    EndDialog(hDlg, 0);
    return 0;
  }
  if ( a2 == 272 )
  {
    v5 = GetModuleHandleW(0);
    v6 = LoadIconW(v5, (LPCWSTR)0x67);
    SetClassLongA(hDlg, -14, (LONG)v6);
    v7 = GetModuleHandleW(0);
    v8 = LoadCursorW(v7, (LPCWSTR)0x66);
    v9 = GetDlgItem(hDlg, 1);
    SetClassLongA(v9, -12, (LONG)v8);
    return 1;
  }
  if ( a2 != 273 || (unsigned __int16)a3 != 1 )
    return 0;
  memset(&str_1, (unsigned __int16)a3 - 1, 0x100u);
  memset(str_2, 0, 0x100u);
  memset(&Text, 0, 0x100u);
  GetDlgItemTextA(hDlg, 1001, &str_1, 256);
  GetDlgItemTextA(hDlg, 1002, str_2, 256);
  if ( strstr(&str_1, "@") && strstr(&str_1, ".") && strstr(&str_1, ".")[1] && strstr(&str_1, "@")[1] != '.' )
  {
    v28 = xmmword_410AA0;
    v29 = 1701999980;
    *(_OWORD *)Src = xmmword_410A90;
    v30 = 46;
    v26 = xmmword_410A80;
    v27 = ':si';
    if ( strlen(str_2) != 16
      || str_2[0] != 67
      || v23 != 88
      || str_2[1] != 90
      || str_2[1] + v22 != 155
      || str_2[2] != 57
      || str_2[2] + v21 != 155
      || str_2[3] != 100
      || v20 != 55
      || v12 != 109
      || v19 != 71
      || v13 != 113
      || v13 + v18 != 170
      || v14 != 52
      || v17 != 103
      || v15 != 99
      || v16 != 56 )
    {
      strcpy_s(&Text, 0x100u, (const char *)&v28);
    }
    else
    {
      strcpy_s(&Text, 0x100u, Src);
      strcat_s(&Text, 0x100u, str_2);
    }
  }
  else
  {
    strcpy_s(&Text, 0x100u, "Your E-mail address in not valid.");
  }
  MessageBoxA(hDlg, &Text, "Registeration", 0x40u);
  return 1;
}
```





## decode

```
code = [67, 90, 57, 100, 109, 113, 52, 99, 56, 103, 170 - 113, 71, 55, 155 - 57, 155 - 90, 88]
flag = ''
for i in code:
	flag += chr(i)
print(len(flag))
print(flag)
```

