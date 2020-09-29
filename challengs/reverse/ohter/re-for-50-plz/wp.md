# re-fo-50-plz-50



It needs ghidra tool to decomplie this mips arch program



```c

undefined4 main(undefined4 param_1,int param_2)

{
  int local_10;
  local_10 = 0;
  while (local_10 < 0x1f) {
    if (meow[local_10] != (*(byte *)(*(int *)(param_2 + 4) + local_10) ^ 0x37)) {
      print("NOOOOOOOOOOOOOOOOOO\n");
      exit_funct();
    }
    local_10 = local_10 + 1;
  }
  puts("C0ngr4ssulations!! U did it.");
  exit_funct();
  return 1;
}

```



ida to decomplie

```
.text:004013C8  # ---------------------------------------------------------------------------
.text:004013C8
.text:004013C8 loc_4013C8:                              # CODE XREF: main+A4↓j
.text:004013C8                 lui     $v0, 0x4A
.text:004013CC                 addiu   $v1, $v0, (meow - 0x4A0000)  # "cbtcqLUBChERV[[Nh@_X^D]X_YPV[CJ"
.text:004013D0                 lw      $v0, 0x28+var_10($fp)
.text:004013D4                 addu    $v0, $v1, $v0
.text:004013D8                 lb      $v1, 0($v0)
.text:004013DC                 lw      $v0, 0x28+arg_4($fp)
.text:004013E0                 addiu   $v0, 4
.text:004013E4                 lw      $a0, 0($v0)
.text:004013E8                 lw      $v0, 0x28+var_10($fp)
.text:004013EC                 addu    $v0, $a0, $v0
.text:004013F0                 lb      $v0, 0($v0)
.text:004013F4                 xori    $v0, 0x37
.text:004013F8                 sll     $v0, 24
.text:004013FC                 sra     $v0, 24
.text:00401400                 beq     $v1, $v0, loc_401428
.text:00401404                 move    $at, $at
.text:00401408                 lui     $v0, 0x47
.text:0040140C                 addiu   $a0, $v0, (aNooooooooooooo - 0x470000)  # "NOOOOOOOOOOOOOOOOOO\n"
.text:00401410                 jal     print
.text:00401414                 move    $at, $at
.text:00401418                 lw      $gp, 0x28+var_18($fp)
.text:0040141C                 jal     exit_funct
.text:00401420                 move    $at, $at
.text:00401424                 lw      $gp, 0x28+var_18($fp)
.text:00401428
.text:00401428 loc_401428:                              # CODE XREF: main+68↑j
.text:00401428                 lw      $v0, 0x28+var_10($fp)
.text:0040142C                 addiu   $v0, 1
.text:00401430                 sw      $v0, 0x28+var_10($fp)
.text:00401434
.text:00401434 loc_401434:                              # CODE XREF: main+28↑j
.text:00401434                 lw      $v0, 0x28+var_10($fp)
.text:00401438                 slti    $v0, 0x1F
.text:0040143C                 bnez    $v0, loc_4013C8
.text:00401440                 move    $at, $at
.text:00401444                 lui     $v0, 0x47
.text:00401448                 addiu   $a0, $v0, (aC0ngr4ssulatio - 0x470000)  # "C0ngr4ssulations!! U did it."
.text:0040144C                 la      $v0, puts
.text:00401450                 move    $t9, $v0
.text:00401454                 jalr    $t9 ; puts
.text:00401458                 move    $at, $at
.text:0040145C                 lw      $gp, 0x28+var_18($fp)
.text:00401460                 jal     exit_funct
.text:00401464                 move    $at, $at
.text:00401468                 lw      $gp, 0x28+var_18($fp)
.text:0040146C                 li      $v0, 1
.text:00401470                 move    $sp, $fp
.text:00401474                 lw      $ra, 0x28+var_4($sp)
.text:00401478                 lw      $fp, 0x28+var_8($sp)
.text:0040147C                 addiu   $sp, 0x28
.text:00401480                 jr      $ra
.text:00401484                 move    $at, $at
.text:00401484  # End of function main
```



This is easy to analyses

```python
code = "cbtcqLUBChERV[[Nh@_X^D]X_YPV[CJ"
flag = ''
for i in code:
	flag += chr(ord(i) ^ 0x37)
print(flag)
```

