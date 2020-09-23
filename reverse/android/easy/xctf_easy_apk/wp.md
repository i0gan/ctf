# easy apk

来源: 攻防世界

```
class MainActivity$1
  implements View.OnClickListener
{
  MainActivity$1(MainActivity paramMainActivity) {}
  
  public void onClick(View paramView)
  {
    paramView = ((EditText)this.this$0.findViewById(2131427445)).getText().toString();
    if (new Base64New().Base64Encode(paramView.getBytes()).equals("5rFf7E2K6rqN7Hpiyush7E6S5fJg6rsi5NBf6NGT5rs=")) {
      Toast.makeText(this.this$0, "验证通过!", 1).show();
    }
    for (;;)
    {
      return;
      Toast.makeText(this.this$0, "验证失败!", 1).show();
    }
  }
}

```

base64加密如下

```
public class Base64New
{
  private static final char[] Base64ByteToStr = { 118, 119, 120, 114, 115, 116, 117, 111, 112, 113, 51, 52, 53, 54, 55, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 121, 122, 48, 49, 50, 80, 81, 82, 83, 84, 75, 76, 77, 78, 79, 90, 97, 98, 99, 100, 85, 86, 87, 88, 89, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 56, 57, 43, 47 };
  private static final int RANGE = 255;
  private static byte[] StrToBase64Byte = new byte['?'];
  
  public String Base64Encode(byte[] paramArrayOfByte)
  {
    StringBuilder localStringBuilder = new StringBuilder();
    for (int i = 0; i <= paramArrayOfByte.length - 1; i += 3)
    {
      byte[] arrayOfByte = new byte[4];
      int j = 0;
      int k = 0;
      if (k <= 2)
      {
        if (i + k <= paramArrayOfByte.length - 1) {
          arrayOfByte[k] = ((byte)(byte)((paramArrayOfByte[(i + k)] & 0xFF) >>> k * 2 + 2 | j));
        }
        for (j = (byte)(((paramArrayOfByte[(i + k)] & 0xFF) << (2 - k) * 2 + 2 & 0xFF) >>> 2);; j = 64)
        {
          k++;
          break;
          arrayOfByte[k] = ((byte)j);
        }
      }
      arrayOfByte[3] = ((byte)j);
      j = 0;
      if (j <= 3)
      {
        if (arrayOfByte[j] <= 63) {
          localStringBuilder.append(Base64ByteToStr[arrayOfByte[j]]);
        }
        for (;;)
        {
          j++;
          break;
          localStringBuilder.append('=');
        }
      }
    }
    return localStringBuilder.toString();
  }
}
```

以上加密是对输入进行了一个base64换表的加密

解密脚本如下

```
import base64
import string


base_table = [ 118, 119, 120, 114, 115, 116, 117, 111, 112, 113, 51, 52, 53, 54, 55, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 121, 122, 48, 49, 50, 80, 81, 82, 83, 84, 75, 76, 77, 78, 79, 90, 97, 98, 99, 100, 85, 86, 87, 88, 89, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 56, 57, 43, 47 ];
string1 = ''
code = '5rFf7E2K6rqN7Hpiyush7E6S5fJg6rsi5NBf6NGT5rs='

for i in range(len(base_table)):
    string1 += chr(base_table[i])


string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

print(base64.b64decode(code.translate(str.maketrans(string1,string2))))
```

