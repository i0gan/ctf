// Ubuntu 18.04, GCC -m32 -O3
#include<stdlib.h>
#include<stdio.h>
#include<unistd.h>
#include<sys/mman.h>
#include<sys/types.h>

#define NUM 0x10

#define ADDR_LOW    0xe0000000
#define ADDR_HIGH   0xf0000000

char* chunks[NUM];
unsigned sizes[NUM];

int* g_ptr = NULL;

void init_io(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

unsigned get_int(){
    unsigned res;
    if(scanf("%u", &res) != 1) exit(0);
    return res;
}

void mmap_delete(){
    if(g_ptr != NULL) return;

    munmap(g_ptr, 0x1000);

    g_ptr = 0;
}

void mmap_allocate(){
    if(g_ptr != NULL) return;

    printf("Where do you want to start: ");
    unsigned idx;
    idx = get_int(); 

    idx = (idx >> 12) << 12;

    if(idx >= (ADDR_HIGH - ADDR_LOW) ) return;

    g_ptr =  mmap(ADDR_LOW + idx, ADDR_HIGH - ADDR_LOW - idx, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); 

    if(g_ptr != (ADDR_LOW + idx)){
        exit(0);
    }
}

void mmap_edit(){
    if(g_ptr == NULL){
        printf("Mmap first!");
        return;
    }

    unsigned value;
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    
    if(g_ptr + idx < g_ptr && (unsigned)(g_ptr + idx) < ADDR_HIGH){ // vul
        puts("Invalid idx");
        return;
    }

    printf("Value: ");

    value = get_int(); 
    g_ptr[idx] = value;
}

void allocate(){
    unsigned size;
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx]){
        return ;
    }

    printf("Size: ");
    size = get_int() & 0x1FF;

    char* buf = malloc(size);
    if(buf == NULL){
        puts("allocate failed");
        return;
    }
    chunks[idx] = buf;
    sizes[idx] = size;
    puts("Done!");
}

void delete(){
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx] == NULL){
        return ;
    }
    
    free(chunks[idx]);
    chunks[idx] = NULL;
    sizes[idx] = 0;
}

void show(){
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx] == NULL){
        return ;
    }
    
    printf("Content: %s\n", chunks[idx]);
}

void readn(char* s, unsigned size){
    for(unsigned i = 0; i < size; i++){
        read(0, s + i, 1);
        if(s[i] == '\n')break;
    }
}
void edit(){
    unsigned idx;
    printf("Index: ");
    idx = get_int(); 
    if(idx >= NUM || chunks[idx] == NULL){
        return ;
    }
    printf("Content: "); 
    readn(chunks[idx], sizes[idx]);
}

void menu(){
    puts("1. allocate");
    puts("2. edit");
    puts("3. show");
    puts("4. delete");
    puts("5. exit");
    printf("Your choice: ");
}

int main(){
    init_io();
    while(1){
        menu();
        unsigned choice = get_int();
        switch(choice){
            case 1:
                allocate();
                break;
            case 2:
                edit();
                break;
            case 3:
                show();
                break;
            case 4:
                delete();
                break;
            case 5:
                exit(0);
                break;
            case 6:
                mmap_allocate();
                break;
            case 7:
                mmap_edit();
                break;
            case 8:
                mmap_delete();
                break;
            default:
                puts("Unknown");
                break;
        }
    }
    return 0;
}
