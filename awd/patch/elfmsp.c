// ref: https://seclists.org/vuln-dev/2002/Jan/3
// Modify the segment's permission flag in elf, surport the arch 32 or 64
// Modified by i0gan
// Date: 2021-06-09
// Project Name: elfmsp
//
#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

int mod_elf32(void *pcFileAddr, int iSegNo, unsigned long ulPerm) {
    char sElfMagic[] = "\x7f" "ELF";
    Elf32_Ehdr *ptElf32Hdr;
    Elf32_Phdr *ptElf32PHdr;
    ptElf32Hdr = (Elf32_Ehdr *) pcFileAddr;
    if (memcmp(&(ptElf32Hdr->e_ident), sElfMagic, sizeof(sElfMagic) - 1)) {
        fprintf(stderr, "This file does not appear to be an 64 ELF file\n");
        return 0;
    }

    /* Does this file have the segment they requested?                 */
    if ((iSegNo < 0) || (iSegNo >= ptElf32Hdr->e_phnum)) {
        printf("Segment %d does not exist in the executable, e_phnum: %d\n", iSegNo, ptElf32Hdr->e_phnum);
        return 0;
    }
    /* Get the segment header for the specified segment                */
    ptElf32PHdr = (Elf32_Phdr *) ((char *) pcFileAddr + ptElf32Hdr->e_phoff +
                                (ptElf32Hdr->e_phentsize * iSegNo));
    /* Set the permissions as specified                                */
    ptElf32PHdr->p_flags = ulPerm;
    return 1;
}

int mod_elf64(void *pcFileAddr, int iSegNo, unsigned long ulPerm) {
    char sElfMagic[] = "\x7f" "ELF";
    Elf64_Ehdr *ptElf64Hdr;
    Elf64_Phdr *ptElf64PHdr;
    ptElf64Hdr = (Elf64_Ehdr *) pcFileAddr;
    if (memcmp(&(ptElf64Hdr->e_ident), sElfMagic, sizeof(sElfMagic) - 1)) {
        fprintf(stderr, "This file does not appear to be an 64 ELF file\n");
        return 0;
    }

    /* Does this file have the segment they requested?                 */
    if ((iSegNo < 0) || (iSegNo >= ptElf64Hdr->e_phnum)) {
        printf("Segment %d does not exist in the executable, e_phnum: %d\n", iSegNo, ptElf64Hdr->e_phnum);
        return 0;
    }
    /* Get the segment header for the specified segment                */
    ptElf64PHdr = (Elf64_Phdr *) ((char *) pcFileAddr + ptElf64Hdr->e_phoff +
                                (ptElf64Hdr->e_phentsize * iSegNo));
    /* Set the permissions as specified                                */
    ptElf64PHdr->p_flags = ulPerm;
    return 1;
}

/* Change the permissions on a segment */
int main(int argc, char *argv[]) {
    char *sInFile;
    int iSegNo, iInFd, i;
    char *pcFileAddr;
    struct stat tStatBuf;
    off_t tMapSize;
    unsigned long ulPerm = 0;

    if (argc != 4) {
        fprintf(stderr, "Usage: elfmsp <elf file> <segment no> <segment permissions (e.g rwx)>\n", argv[0]);
        exit(1);
    }

    i = 0;

    while (argv[3][i]) {
       switch(argv[3][i]) {
          case 'x':
             ulPerm |= PF_X;
          case 'r':
             ulPerm |= PF_R;
          case 'w':
             ulPerm |= PF_W;
       }
       i++;
    }

    sInFile = argv[1];
    iSegNo = atoi(argv[2]);
    if (-1 == (iInFd = open(sInFile, O_RDWR))) {
        fprintf(stderr, "Could not open %s, %d %s\n", sInFile, errno, strerror(errno));
        exit(-1);
    }
    if (fstat(iInFd, &tStatBuf)) {
        fprintf(stderr, "Could not stat %s, %d %s\n", sInFile, errno, strerror(errno));
        close(iInFd);
        exit(-1);
    }
    tMapSize = tStatBuf.st_size;

    if (!(pcFileAddr = mmap(0, tMapSize, PROT_READ | PROT_WRITE, MAP_SHARED, iInFd, 0))) { fprintf(stderr, "Could not mmap %s, %d %s\n", sInFile, errno, strerror(errno));
        close(iInFd);
        exit(-1);
    }

    //printf("File %s mapped at %p for %lu bytes\n", sInFile, pcFileAddr, tMapSize);
 
    int ret = 0;
    // check arch is 32
    if(pcFileAddr[4] == 0x01) {
        ret = mod_elf32(pcFileAddr, iSegNo, ulPerm);
    }else if(pcFileAddr[4] == 0x02) { // 64
        ret = mod_elf64(pcFileAddr, iSegNo, ulPerm);
    }else {
        puts("arch error");
    }

    if(ret = 1) {
        puts("This file modified!");
    }

    munmap(pcFileAddr, tMapSize);
    close(iInFd);
    return (0);
}
