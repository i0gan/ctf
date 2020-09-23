# easyjni

来源:攻防世界



反编译java如下:

```
class MainActivity$1
  implements View.OnClickListener
{
  MainActivity$1(MainActivity paramMainActivity, Context paramContext) {}
  
  public void onClick(View paramView)
  {
    paramView = (EditText)((MainActivity)this.a).findViewById(2131427445);
    if (MainActivity.a(this.b, paramView.getText().toString())) {
      Toast.makeText(this.a, "You are right!", 1).show();
    }
    for (;;)
    {
      return;
      Toast.makeText(this.a, "You are wrong! Bye~", 1).show();
    }
  }
}
```



```
public class MainActivity
  extends c
{
  static
  {
    System.loadLibrary("native");
  }
  
  private boolean a(String paramString)
  {
    try
    {
      a locala = new com/a/easyjni/a;
      locala.<init>();
      bool = ncheck(locala.a(paramString.getBytes()));
      return bool;
    }
    catch (Exception paramString)
    {
      for (;;)
      {
        boolean bool = false;
      }
    }
  }
  
  private native boolean ncheck(String paramString);
```



从以上代码可以看到, 对输入的数据先进行base64加密, 然后调用native层的ncheck函数判断是否正确.

ida打开libnative.so文件, 反编译ncheck函数如下:

```
signed int __fastcall Java_com_a_easyjni_MainActivity_ncheck(JNIEnv *a1, int a2, int a3)
{
  int v3; // r8
  JNIEnv *v4; // r5
  int v5; // r8
  const char *str; // r6
  int i; // r0
  char *v8; // r2
  char v9; // r1
  int v10; // r0
  bool v11; // nf
  unsigned __int8 v12; // vf
  int v13; // r1
  signed int result; // r0
  char en_str[32]; // [sp+3h] [bp-35h]
  char v16; // [sp+23h] [bp-15h]
  int v17; // [sp+28h] [bp-10h]

  v17 = v3;
  v4 = a1;
  v5 = a3;
  str = (const char *)((int (__fastcall *)(JNIEnv *, int, _DWORD))(*a1)->GetStringUTFChars)(a1, a3, 0);
  if ( strlen(str) == 32 )
  {
    i = 0;
    do
    {
      v8 = &en_str[i];
      en_str[i] = str[i + 16];
      v9 = str[i++];
      v8[16] = v9;
    }
    while ( i != 16 );
    ((void (__fastcall *)(JNIEnv *, int, const char *))(*v4)->ReleaseStringUTFChars)(v4, v5, str);
    v10 = 0;
    do
    {
      v12 = __OFSUB__(v10, 30);
      v11 = v10 - 30 < 0;
      v16 = en_str[v10];
      en_str[v10] = en_str[v10 + 1];
      en_str[v10 + 1] = v16;
      v10 += 2;
    }
    while ( v11 ^ v12 );
    v13 = memcmp(en_str, "MbT3sQgX039i3g==AQOoMQFPskB1Bsc7", 0x20u);
    result = 0;
    if ( !v13 )
      result = 1;
  }
  else
  {
    ((void (__fastcall *)(JNIEnv *, int, const char *))(*v4)->ReleaseStringUTFChars)(v4, v5, str);
    result = 0;
  }
  return result;
}
```

以上代码经过了两次加密, 先进行str[i]与str[i + 16]的交换, 再进行str[i]与str[i + 1]进行交换.

解密脚本如下:

```
#include <stdio.h>
void decode() {
        char code[] = "MbT3sQgX039i3g==AQOoMQFPskB1Bsc7";
        for(int i = 0; i < 32;  i += 2) {
                char ch = code[i];
                code[i] = code[i + 1];
                code[i + 1] = ch;
        }
        //printf("%s", code);
        for(int i = 0; i < 16; i ++) {
                char ch = code[i];
                code[i] = code[i + 16];
                code[i + 16] = ch;
        }
        printf("%s", code);

}
void show_arr() {
        char arr[] = { 105, 53, 106, 76, 87, 55, 83, 48, 71, 88, 54, 117, 102, 49, 99, 118, 51, 110, 121, 52, 113, 56, 101, 115, 50, 81, 43, 98, 100, 107, 89, 103, 75, 79, 73, 84, 47, 116, 65, 120, 85, 114, 70, 108, 86, 80, 122, 104, 109, 111, 119, 57, 66, 72, 67, 77, 68, 112, 69, 97, 74, 82, 90, 78, 0 };
        printf("%s\n", arr);
}
int main(void) {
        show_arr();
        decode();
        return 0;
}
```

解密base64

```
import base64
import string

str1 = "QAoOQMPFks1BsB7cbM3TQsXg30i9g3=="

string1 = "i5jLW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tAxUrFlVPzhmow9BHCMDpEaJRZN"
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


print (b'code: ' + base64.b64decode(str1.translate(str.maketrans(string1,string2))))
```

 