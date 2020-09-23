# Ph0en1x-100

[下载](https://adworld.xctf.org.cn/media/task/attachments/f6adc401d0eb472892a4ac4481f76a85.apk)

来源:攻防世界



程序流程, 输入flag



jd-gui反编译如下:

```
 public void onGoClick(View paramView)
  {
    paramView = this.etFlag.getText().toString();
    if (getSecret(getFlag()).equals(getSecret(encrypt(paramView)))) {
      Toast.makeText(this, "Success", 1).show();
    }
    for (;;)
    {
      return;
      Toast.makeText(this, "Failed", 1).show();
    }
  }
```

getFlag函数与encrypt函数是native层

```
  static
  {
    System.loadLibrary("phcm");
  }
  
  public native String encrypt(String paramString);
  
  public native String getFlag();
```



反编译libphcm.so文件

```
int __cdecl Java_com_ph0en1x_android_1crackme_MainActivity_encrypt(JNIEnv *a1, int a2, int a3)
{
  size_t i; // esi
  const char *s; // edi

  i = 0;
  for ( s = (*a1)->GetStringUTFChars(a1, (jstring)a3, 0); i < strlen(s); --s[i++] )
    ;
  return (*a1)->NewStringUTF(a1, s);
}
```

以上加密就是对字符串中的每个字符-1



```
int __cdecl Java_com_ph0en1x_android_1crackme_MainActivity_getFlag(JNIEnv *a1)
{
  signed int v1; // esi
  char *v2; // edi
  char v3; // al
  int result; // eax
  int v5; // [esp+26h] [ebp-46h]
  int v6; // [esp+2Ah] [ebp-42h]
  int v7; // [esp+2Eh] [ebp-3Eh]
  __int16 v8; // [esp+32h] [ebp-3Ah]
  int v9; // [esp+34h] [ebp-38h]
  int v10; // [esp+38h] [ebp-34h]
  int v11; // [esp+3Ch] [ebp-30h]
  int v12; // [esp+40h] [ebp-2Ch]
  int v13; // [esp+44h] [ebp-28h]
  int v14; // [esp+48h] [ebp-24h]
  int v15; // [esp+4Ch] [ebp-20h]
  int v16; // [esp+50h] [ebp-1Ch]
  int v17; // [esp+54h] [ebp-18h]
  int v18; // [esp+58h] [ebp-14h]
  unsigned int v19; // [esp+5Ch] [ebp-10h]

  v1 = 38;
  v2 = (char *)&v18 + 2;
  v9 = 1279407662;
  v10 = 987807583;
  v19 = __readgsdword(0x14u);
  v11 = 1663091624;
  v12 = 482391945;
  v13 = 683820061;
  v14 = 235072895;
  v15 = 2559534685;
  v16 = 382777269;
  v17 = 4227367757;
  v18 = 4670209;
  v5 = 1819043144;
  v6 = 1750081647;
  v7 = 829318448;
  v8 = 120;
  do
  {
    v3 = *v2--;
    v2[1] = (*((_BYTE *)&v5 + v1-- % 13) ^ (v3 + 1 - *v2)) - 1;
  }
  while ( v1 );
  LOBYTE(v9) = (v9 ^ 0x48) - 1;
  result = (int)(*a1)->NewStringUTF(a1, (const char *)&v9);
  if ( __readgsdword(0x14u) != v19 )
    sub_4B0();
  return result;
}
```

这个加密稍微有点复杂. 若想获取flag, 先对上面这给逆出来, 在对encrypt加密加密函数给再逆出来即可获得flag, 但是, 我写了一个c脚本, 上面这个有问题, 主要是LOBYTE(v9) = (v9 ^ 0x48) - 1;这个语句不好写.换另一种思路.动态调试(瞎弄半天, 啥也没弄出来), 再换另一种, 就是使用Android killer修改smali源码, 将其getFlag函数的字符串给打印出来, 只需将打印失败逻辑添加一下getFlag函数, 将getFlag字符串覆盖为打印失败的字符串, 复制上面调用getFlag的即可, 再更变一下变量, 如下

```
 .line 37
    :cond_0
    const-string v1, "Failed"
    
    invoke-virtual {p0}, Lcom/ph0en1x/android_crackme/MainActivity;->getFlag()Ljava/lang/String;

    move-result-object v1   // getFlag()函数的返回值,(字符串)
    
    invoke-static {p0, v1, v3}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object v1

    invoke-virtual {v1}, Landroid/widget/Toast;->show()V
```

然后点击Android->编译, 即可再次编译为apk文件, 安装再nox中运行, 随便输入就会出现ek`fz@q2^x/t^fn0mF^6/^rb`qanqntfg^E`hq|

再次让每个字符+1就可得到flag

```
#include <stdio.h>
#include <string.h>

int main(void) {
	char flag[] = "ek`fz@q2^x/t^fn0mF^6/^rb`qanqntfg^E`hq|";
	for(int i = 0; i < strlen(flag); ++i) {
		putchar(++flag[i]);
	}

	return 0;
} 
```
