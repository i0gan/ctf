# Siri

格式化字符串漏洞, 泄漏elf_base和libc_base, got表不能修改, 只能先泄漏stack地址, 修改ret地址打one_gadget了,  (已经可以修改ret地址了, 打one_gagdgt 打通了, 不知啥原因, execve函数会跳转到read函数, 导致输入token会出错, 原因: io已经处于shutdown状态)

另一种劫持,劫持libc中的got表地址, puts函数中存在plt跳转,修改该跳转函数的got地址为one_gadget即可. 