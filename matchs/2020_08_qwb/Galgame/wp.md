 # Galgame



## Vul

```
 if ( p_addr[atoi((const char *)&buf)] )
          {
            printf("movie name >> ", &buf);
            v4 = atoi((const char *)&buf); //对v4没有进行溢出检查, 也可以对p_addr附近存在的地址进行写入
            read(0, (void *)(p_addr[v4] + 0x60), 0x10uLL);// 溢出8字节漏洞
            puts("\nHotaru: What a good movie! I like it~\n");
            puts("[ You've gained a lot favor of her! ]");
          }
```



先通过8字节溢出修改top chunk size, 开辟0x1000不够, 则实现free功能泄漏libc, 在通过v4没有检查漏洞可进行数组越界和退出输入配合实现任意地址写入, 修改libc puts中*ABS*+0x9dce0plt 跳转的 got表打one_gadget