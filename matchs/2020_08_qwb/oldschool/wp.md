# WP

先使用堆块布局泄漏libc, 然后通过mmap_edit 中的漏洞实现高地址写入, 修改 exit_hook   

 _rtld_lock_unlock_recursive 为mmap开辟的地址, 然后调用exit时跳转到mmap开辟的地址执行shellcode

mmap_edit漏洞: 



## Vul

```
void mmap_edit(){
    if(g_ptr == NULL){
        printf("Mmap first!");
        return;
    }
    unsigned value;
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    
    if(g_ptr + idx < g_ptr && (unsigned)(g_ptr + idx) < ADDR_HIGH){ //漏洞
        puts("Invalid idx");
        return;
    }
    printf("Value: ");
    value = get_int(); 
    g_ptr[idx] = value;
}
```

