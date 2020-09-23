# app2

来源:攻防世界



对输入的账号和密码在SecondActivity类中进行加密判断, 而加密调用了native层的加密函数

```
protected void onCreate(Bundle paramBundle) {
    super.onCreate(paramBundle);
    setContentView(2130903041);
    Intent intent = getIntent();
    String str1 = intent.getStringExtra("ili");
    String str2 = intent.getStringExtra("lil");
    if (Encryto.doRawData(this, str1 + str2).equals("VEIzd/V2UPYNdn/bxH3Xig==")) {
      intent.setAction("android.test.action.MoniterInstallService");
      intent.setClass((Context)this, MoniterInstallService.class);
      intent.putExtra("company", "tencent");
      intent.putExtra("name", "hacker");
      intent.putExtra("age", 18);
      startActivity(intent);
      startService(intent);
    } 
    SharedPreferences.Editor editor = getSharedPreferences("test", 0).edit();
    editor.putString("ilil", str1);
    editor.putString("lili", str2);
    editor.commit();
  }
```

IDA反编译doRawData函数, 因为a为对象, 选择a按下y 键 然后输入 JNIEnv*就可以显示对象的函数调用, 如下

```
int __cdecl doRawData(JNIEnv *a1, int a2, int a3, int a4)
{
  char *v4; // esi
  const char *v5; // ST10_4
  int result; // eax
  char *v7; // esi
  jstring (*v8)(JNIEnv *, const jchar *, jsize); // ST10_4
  size_t v9; // eax
  int v10; // [esp+4h] [ebp-28h]
  int v11; // [esp+8h] [ebp-24h]
  int v12; // [esp+Ch] [ebp-20h]
  int v13; // [esp+10h] [ebp-1Ch]
  char v14; // [esp+14h] [ebp-18h]
  unsigned int v15; // [esp+18h] [ebp-14h]

  v15 = __readgsdword(0x14u);
  if ( checkSignature((int)a1, a2, a3) == 1 )
  {
    v14 = 0;
    v13 = 0x3D3D7965;
    v12 = 0x6B747365;
    v11 = 0x74617369;
    v10 = 0x73696874;
    v4 = (char *)(*a1)->GetStringUTFChars(a1, (jstring)a4, 0);
    v5 = (const char *)AES_128_ECB_PKCS5Padding_Encrypt(v4, (int)&v10);
    (*a1)->ReleaseStringUTFChars(a1, (jstring)a4, v4);
    result = (int)(*a1)->NewStringUTF(a1, v5);
  }
  else
  {
    v7 = UNSIGNATURE[0];
    v8 = (*a1)->NewString;
    v9 = strlen(UNSIGNATURE[0]);
    result = (int)v8(a1, (const jchar *)v7, v9);
  }
  return result;
}
```

可以发现, 加密方式为aes加密, key 为 v10中的内容.为thisisatestkey==

对VEIzd/V2UPYNdn/bxH3Xig== 解密为aimagetencent, 发现提交flag错误, 重新找另一个字符串,在FileDataActivity类中找到如下.

```
public class FileDataActivity extends a {
  private TextView c;
  
  protected void onCreate(Bundle paramBundle) {
    super.onCreate(paramBundle);
    setContentView(2130903042);
    this.c = (TextView)findViewById(2131165184);
    this.c.setText(Encryto.decode(this, "9YuQ2dk8CSaCe7DTAmaqAA=="));
  }
}
```

调用了decode函数, 而decode函数与doRawData实现一样, 直接与之前一样的AES ecb解密, 得到flag 