 

## easy-so

来源:攻防世界



使用夜神模拟器运行该apk文件, 发现需要输入flag

zip解压apk文件, 用 dex2jar反编译 classes.dex文件得到classes-dex2jar.jar,

```
d2j-dex2jar.bat classes.dex
```

 再用jd-gui打开classes-dex2jar.jar反编译为java代码.

```java
public class MainActivity extends AppCompatActivity {
  protected void onCreate(Bundle paramBundle) {
    super.onCreate(paramBundle);
    setContentView(2131296283);
    ((Button)findViewById(2131165218)).setOnClickListener(new View.OnClickListener() {
          public void onClick(View param1View) {
            if (cyberpeace.CheckString(((EditText)MainActivity.this.findViewById(2131165233)).getText().toString()) == 1) {
              Toast.makeText((Context)MainActivity.this, ", 1).show();
              return;
            } 
            Toast.makeText((Context)MainActivity.this, ", 1).show();
          }
        });
  }
}
```

在这里可以发现, cyberpeace加载了'cyberpeace'动态库, CheckString函数是native层的, 这个函数的实现就在libcyberpeace.so文件中

```
package com.testjava.jack.pingan2;

public class cyberpeace {
  static {
    System.loadLibrary("cyberpeace");
  }
  
  public static native int CheckString(String paramString);
}

```

使用ida打开lib/x86/libcyberpeace.so文件, 找到 _BOOL4 __cdecl Java_com_testjava_jack_pingan2_cyberpeace_CheckString(int a1, int a2, int a3)函数, 该函数实现如下:

```
_BOOL4 __cdecl Java_com_testjava_jack_pingan2_cyberpeace_CheckString(int a1, int a2, int a3)
{
  const char *get_str; // ST1C_4
  size_t len; // edi
  char *str; // esi
  size_t i; // edi
  char v7; // al
  char v8; // al
  size_t v9; // edi
  char v10; // al

  get_str = (const char *)(*(int (__cdecl **)(int, int, _DWORD))(*(_DWORD *)a1 + 676))(a1, a3, 0); // 从java层获取所输入的字符串
  len = strlen(get_str);
  str = (char *)malloc(len + 1);
  memset(&str[len], 0, len != -1);
  memcpy(str, get_str, len);
  if ( strlen(str) >= 2 ) // 加密1
  {
    i = 0;
    do
    {
      v7 = str[i];
      str[i] = str[i + 16];
      str[i++ + 16] = v7;
    }
    while ( i < strlen(str) >> 1 );
  }
  // 加密2
  v8 = *str;
  if ( *str )
  {
    *str = str[1];
    str[1] = v8;
    if ( strlen(str) >= 3 )
    {
      v9 = 2;
      do
      {
        v10 = str[v9];
        str[v9] = str[v9 + 1];
        str[v9 + 1] = v10;
        v9 += 2;
      }
      while ( v9 < strlen(str) );
    }
  }
  return strcmp(str, "f72c5a36569418a20907b55be5bf95ad") == 0; // 与字符串作比较
}
```

从以上发现, 对我们所输入的字符串进行了加密, 然后再与f72c5a36569418a20907b55be5bf95ad进行比较. 现在只需逆一下以上代码即可得到flag, exp代码如下

```
#include <stdio.h>
#include <string.h>

int main(void) {
	char str[] = "f72c5a36569418a20907b55be5bf95ad";
	int i, v7, v8, v9, v10;
	v8 = *str;
	if ( *str ) {
		*str = str[1];
		str[1] = v8;
		if ( strlen(str) >= 3 ) {
      		v9 = 2;
      		do {
        		v10 = str[v9];
        		str[v9] = str[v9 + 1];
        		str[v9 + 1] = v10;
        		v9 += 2;
      		} while ( v9 < strlen(str) );
		}
	}
	
	// 交换 
	if ( strlen(str) >= 2 )	{
   	 i = 0;
    	do {
      		v7 = str[i];
      		str[i] = str[i + 16];
     		str[i++ + 16] = v7;
   	 	} while ( i < strlen(str) >> 1 );
	}
	printf("%s", str);
  
	return 0;
}

```

运行以上代码即可获取flag