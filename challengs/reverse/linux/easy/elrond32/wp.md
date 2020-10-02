

We just make n == default then break; we can use number 10 as condition to break loop;

```c
signed int __cdecl loop(_BYTE *in, int n)
{
  signed int result; // eax

  switch ( n )
  {
    case 0:
      if ( *in == 'i' )
        goto ok;
      result = 0;
      break;
    case 1:
      if ( *in == 'e' )
        goto ok;
      result = 0;
      break;
    case 3:
      if ( *in == 'n' )
        goto ok;
      result = 0;
      break;
    case 4:
      if ( *in == 'd' )
        goto ok;
      result = 0;
      break;
    case 5:
      if ( *in == 'a' )
        goto ok;
      result = 0;
      break;
    case 6:
      if ( *in == 'g' )
        goto ok;
      result = 0;
      break;
    case 7:
      if ( *in == 's' )
        goto ok;
      result = 0;
      break;
    case 9:
      if ( *in == 'r' )
ok:
        result = loop(in + 1, 7 * (n + 1) % 11);
      else
        result = 0;
      break;
    default:
      result = 1;
      break;
  }
  return result;
}


```






```python

def pr(n):
    if(n == 0):
        return 'i'
    elif(n == 1):
        return 'e'
    elif(n == 3):
        return 'n'
    elif(n == 4):
        return 'd'
    elif(n == 5):
        return 'a'
    elif(n == 6):
        return 'g'
    elif(n == 7):
        return 's'
    elif(n == 9):
        return 'r'
    return '  No'
num = []
def loop(n):
    global num
    if(n == 10):
        return 
    else:
        a = 7 * (n + 1) % 11
        num.append(a)
        loop(a)
loop(0)
flag = 'i'
for i in num:
    flag += pr(i)
print(flag)

```




```sh
root@kali:~/Downloads# python re.py 
isengard  No  No
root@kali:~/Downloads# ./rev300 isengard
Access granted
flag{s0me7hing_S0me7hinG_t0lki3n}

```
