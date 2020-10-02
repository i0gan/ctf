# Mysterious


```c
int __stdcall main__(HWND hWnd, int a2, int a3, int a4)
{
  char v5; // [esp+50h] [ebp-310h]
  CHAR Text[4]; // [esp+154h] [ebp-20Ch]
  char v7; // [esp+159h] [ebp-207h]
  __int16 v8; // [esp+255h] [ebp-10Bh]
  char v9; // [esp+257h] [ebp-109h]
  int v10; // [esp+258h] [ebp-108h]
  CHAR String; // [esp+25Ch] [ebp-104h]
  char v12; // [esp+25Fh] [ebp-101h]
  char v13; // [esp+260h] [ebp-100h]
  char v14; // [esp+261h] [ebp-FFh]

  memset(&String, 0, 0x104u);
  v10 = 0;
  if ( a2 == 16 )
  {
    DestroyWindow(hWnd);
    PostQuitMessage(0);
  }
  else if ( a2 == 0x111 )
  {
    if ( a3 == 1000 )
    {
      GetDlgItemTextA(hWnd, 1002, &String, 260);
      strlen(&String);
      if ( strlen(&String) > 6 )
        ExitProcess(0);
      v10 = atoi(&String) + 1;
      if ( v10 == 0x7B && v12 == 0x78 && v14 == 0x7A && v13 == 0x79 )
      {
        strcpy(Text, "flag");
        memset(&v7, 0, 0xFCu);
        v8 = 0;
        v9 = 0;
        _itoa(v10, &v5, 10);
        strcat(Text, "{");
        strcat(Text, &v5);
        strcat(Text, "_");
        strcat(Text, "Buff3r_0v3rf|0w");
        strcat(Text, "}");
        MessageBoxA(0, Text, "well done", 0);
      }
      SetTimer(hWnd, 1u, 0x3E8u, TimerFunc);
    }
    if ( a3 == 1001 )
      KillTimer(hWnd, 1u);
  }
  return 0;
}
```



It's so easy to debugger setting the logic for printing flag

Use ollydebg to print it!

```

CPU Stack
Address   Value      ASCII Comments
0018F5F0   00000000
0018F5F4   0018F96C  lи┤
0018F5F8   004012A3  бъ@   ; RETURN from USER32.MessageBoxA to Mysterious.004012A3
0018F5FC  /00000000        ; |hOwner = NULL
0018F600  |0018F760  `б┬   ; |Text = "flag{123_Buff3r_0v3rf|0w}"
0018F604  |0042201C   B   ; |Caption = "well done"
0018F608  |00000000        ; \Type = MB_OK|MB_DEFBUTTON1|MB_APPLMODAL
0018F60C  |00000000
0018F610  |0040100A  
@
0018F614  |00000001  
0018F618  |CCCCCCCC  имимимим
0018F61C  |CCCCCCCC  имимимим
0018F620  |CCCCCCCC  имимимим
0018F624  |CCCCCCCC  имимимим
0018F628  |CCCCCCCC  имимимим
0018F62C  |CCCCCCCC  имимимим
0018F630  |CCCCCCCC  имимимим
0018F634  |CCCCCCCC  имимимим
0018F638  |CCCCCCCC  имимимим
0018F63C  |CCCCCCCC  имимимим
0018F640  |CCCCCCCC  имимимим
0018F644  |CCCCCCCC  имимимим
0018F648  |CCCCCCCC  имимимим
0018F64C  |CCCCCCCC  имимимим
0018F650  |CCCCCCCC  имимимим
0018F654  |CCCCCCCC  имимимим
0018F658  |00000111  
0018F65C  |00333231  123
0018F660  |CCCCCCCC  имимимим
```
