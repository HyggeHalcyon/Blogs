# Privilege Escalation

## modprobe

```bash
└──╼ [★]$ python                                                                                                                                                                                                         
>>> from pwn import *                                                                                                                                                                                                                                                           
>>> kernel = ELF('./vmlinux')                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
>>> hex(next(kernel.search(b'/sbin/modprobe\x00')))                                                                                                                                                                                                                             
'0xffffffff81e38180'

/ $ cat / proc/kallsyms | grep modprobe_path
```

## core\_pattern

```bash
└──╼ [★]$ python                                                                                                                                                                                                         
>>> from pwn import *                                                                                                                                                                                                                                                           
>>> kernel = ELF('./vmlinux')                                                                                                                                                                                                                                                                                                                                                                                                                                                                    
>>> hex(next(kernel.search(b'/core\x00')))
'0xffffffff81d6904c'

/ $ cat /proc/sys/kernel/core_pattern
core
```

## task\_struct

* [https://slavaim.blogspot.com/2017/09/linux-kernel-debugging-with-gdb-getting.html](https://slavaim.blogspot.com/2017/09/linux-kernel-debugging-with-gdb-getting.html)
