# app1 

来源:攻防世界



```
 public void onClick(View paramView)
  {
    for (;;)
    {
      try
      {
        str = this.this$0.text.getText().toString();
        PackageInfo localPackageInfo = this.this$0.getPackageManager().getPackageInfo("com.example.yaphetshan.tencentgreat", 16384);
        paramView = localPackageInfo.versionName;
        int i = localPackageInfo.versionCode;
        j = 0;
        if ((j >= str.length()) || (j >= paramView.length())) {
          continue;
        }
        if (str.charAt(j) != (paramView.charAt(j) ^ i))
        {
          Toast.makeText(this.this$0, "再接再励~", 1).show();
          return;
        }
      }
      catch (PackageManager.NameNotFoundException paramView)
      {
        String str;
        int j;
        Toast.makeText(this.this$0, "不要玩小聪明", 1).show();
        continue;
      }
      j++;
      continue;
      if (str.length() != paramView.length()) {
        continue;
      }
      Toast.makeText(this.this$0, "恭喜开启芝麻之门", 1).show();
    }
  }
```



在BuildConfig class中找到versionName和versionCode

```
package com.example.yaphetshan.tencentgreat;

public final class BuildConfig
{
  public static final String APPLICATION_ID = "com.example.yaphetshan.tencentgreat";
  public static final String BUILD_TYPE = "debug";
  public static final boolean DEBUG = Boolean.parseBoolean("true");
  public static final String FLAVOR = "";
  public static final int VERSION_CODE = 15;
  public static final String VERSION_NAME = "X<cP[?PHNB<P?aj";
}

```

解密脚本

```
#include <stdio.h>
#include <string.h>
int main(void) {
	char name[] = "X<cP[?PHNB<P?aj";
	for(int i = 0; i < strlen(name); ++i)
		putchar(name[i] ^15);

	return 0;
}

```

 