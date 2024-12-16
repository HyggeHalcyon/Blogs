# Structures

## `_IO_FILE`

this is the basic structure that then be extended to other structure and definition which can be seen in the source code here:

one can use pwntools built-in class to craft FILE payloads

```python
from pwn import *
file = FileStructure(0x0)
file.flags = 0xFBAD0000
io.sendline(bytes(file))
```

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L324" %}

***

## `_IO_jump_t`

this is an array or look up tables of methods and macros that is being used by the FILE structure. these tables have the same methods, these are (in order of the array):&#x20;

1. dummy
2. dummy2
3. finish
4. overflow
5. underflow
6. uflow
7. pbackfail
8. xsputn
9. xsgetn
10. seekoff
11. seekpos
12. setbuf
13. sync
14. doallocate
15. read
16. write
17. seek
18. close
19. stat
20. showmanyc
21. imbu

those are basically the interfaces that all FILEs can call, however there are multiple vtables that are composed of these methods but they point to a different function and thus have a different implementation, those list can be seen in the source code below:

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/fileops.c#L1433" %}

***

## `_IO_wide_data`

this is somewhat similar but not the same to `_IO_FILE` and I think is built to handle wide characters.

unlike `_IO_FILE` pwntools doesn't have a class that support this structure, however I made this boilerplate to craft fake `wide_data` structure:

```python
# some structures inside _wide_data
# 1. wchar_t (2 bytes)
# 2. __mbstate_t (8 bytes) 
#    https://codebrowser.dev/glibc/glibc/wcsmbs/bits/types/__mbstate_t.h.html#__mbstate_t
# 3. _IO_codecvt (8+8+8+4+4+4+8+11)*2 (alligned to 0x70)
#    https://codebrowser.dev/glibc/glibc/libio/libio.h.html#_IO_codecvt

fake_wide_data = flat([
    p64(0x0) * 3,           # [WIDE DATA] read_*
    p64(0x0),               # [WIDE DATA] write_base
    p64(0x0),               # [WIDE DATA] write_ptr
    p64(0x0),               # [WIDE DATA] write_end
    p64(0x0),               # [WIDE DATA] buf_base
    p64(0x0),               # [WIDE DATA] buf_end 
    p64(0x0),               # [WIDE DATA] save_base
    p64(0x0),               # [WIDE DATA] backup_base 
    p64(0x0),               # [WIDE DATA] save_end
])
fake_wide_data += b'\x00' * 8       # [WIDE DATA] state
fake_wide_data += b'\x00' * 8       # [WIDE DATA] last_state
fake_wide_data += p64(0x0).ljust(0x70, b'\x00') # [WIDE DATA] codecvt
fake_wide_data += p64(0x0)          # [WIDE DATA] wchar_t shortbuf[1] (alligned to 8 bytes)
fake_wide_data += p64(0x0)       # [WIDE DATA] vtable
```

{% embed url="https://codebrowser.dev/glibc/glibc/libio/libio.h.html#121" %}
