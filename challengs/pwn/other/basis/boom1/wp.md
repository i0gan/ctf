# Boom1

## 来源
~


## 难度

3 / 10

## 保护

 ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```

## 简单描述

c语言解释器

## vul

```c
申请的局部变量在紧挨着libc地址, 可以直接获取libc地址, 也可以通过对指针进行操作, 直接写入目标内存
```



## 知识点

c语言

