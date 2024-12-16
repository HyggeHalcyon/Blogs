# Arbitrary Read/Write

## Arbitrary Read

### fwrite

* Set the `_fileno` to the file descriptor of `stdout`
* Set `_flag & ~_IO_NO_WRITES`
* Set `_flag |= _IO_CURRENTLY_PUTTING`
* Set the `write_base` and `write_ptr` to memory address which you want to read
* Set `_IO_read_end` equal to `_IO_write_base`

or though not always reliable, in pwntools:

```python
fp = FileStructure(0x0)
payload = fp.read(addr, 0x120)
io.send(payload)
```

{% embed url="https://hackmd.io/@whoisthatguy/Hke0xJaLWp#2-leak-libc" %}

***

### fclose

upon `fclose()`, if buffer is not empty, it will be flushed (written to the `_fileno`)

* Set the `_fileno` to the file descriptor of choice
* Set `write_base` to the start of write address
* Set `write_ptr` to the end of write address

{% hint style="warning" %}
be careful of closing if `_fileno` is set to `stdout` or `stdin`
{% endhint %}

explained in-depth in this writeup:

{% embed url="https://atum.li/2017/11/08/babyfs/#info-leak" %}

we can trace the function calls as the following,

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/iofclose.c#L78" %}

```c
int
_IO_new_fclose (FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

  // ... 

  /* First unlink the stream.  */
  if (fp->_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  
  // ...
  
  _IO_FINISH (fp); // <-- OUR INTEREST
  
  // ...
  
  _IO_deallocate_file (fp);
  return status;
}

versioned_symbol (libc, _IO_new_fclose, _IO_fclose, GLIBC_2_1);
strong_alias (_IO_new_fclose, __new_fclose)
versioned_symbol (libc, __new_fclose, fclose, GLIBC_2_1);
```

which then calls `_IO_FINISH()`,

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L139" %}

```c
typedef void (*_IO_finish_t) (FILE *, int); /* finalize */
#define _IO_FINISH(FP) JUMP1 (__finish, FP, 0)
#define _IO_WFINISH(FP) WJUMP1 (__finish, FP, 0)
```

referring to the [jump table](structures.md#io_jump_t), we can see that the implementation for `__finish` is `_IO_new_file_finish()`

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/fileops.c#L168" %}

```c
void
_IO_new_file_finish (FILE *fp, int dummy)
{
  if (_IO_file_is_open (fp))
    {
      _IO_do_flush (fp); // <-- OUR INTEREST
      if (!(fp->_flags & _IO_DELETE_DONT_CLOSE))
	_IO_SYSCLOSE (fp);
    }
  _IO_default_finish (fp, 0);
}
libc_hidden_ver (_IO_new_file_finish, _IO_file_finish)
```

which will call the flush macro `_IO_do_flush()` and is defined as follows:&#x20;

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L507" %}

```c
#define _IO_do_flush(_f) \
  ((_f)->_mode <= 0							      \
   ? _IO_do_write(_f, (_f)->_IO_write_base,				      \
		  (_f)->_IO_write_ptr-(_f)->_IO_write_base)		      \
   : _IO_wdo_write(_f, (_f)->_wide_data->_IO_write_base,		      \
		   ((_f)->_wide_data->_IO_write_ptr			      \
		    - (_f)->_wide_data->_IO_write_base)))
```

which writes `write_base` up until `write_ptr`&#x20;

***

### puts

refer to [fwrite](arbitrary-read-write.md#fwrite).

***

## Arbitrary Write

### fread

* Set the `_fileno` to file descriptor of `stdin`
* Set `_flag &~ _IO_NO_READS`
* Set `_flag |= _IO_CURRENTLY_PUTTING`
* Set `read_base` equals to `read_ptr` to `NULL`
* Set the `buf_base` and `buf_end` to memory address which you want to write
* `buf_end - buf_base` > size of fread (BUFFER SIZE > READ SIZE) (or other function, scanf, etc)

or though not always reliable, in pwntools:

```python
fp = FileStructure(0x0)
payload = fp.write(addr, 0x120)
io.send(payload)
```

***

### fwrite

`fwrite(const void *buf, size_t size, size_t count, FILE *fp);`

* Set `fp->_flags` to `_IO_MAGIC | ~_IO_LINE_BUF | ~_IO_CURRENTLY_PUTTING`
* Set `buf` to the data wish to be written
* Set `fp->write_ptr` to the start of write address
* Set `fp->write_end` to the end of write address

we can trace the function calls as the following,

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/iofwrite.c#L30" %}

```c
size_t
_IO_fwrite (const void *buf, size_t size, size_t count, FILE *fp)
{
  // ...
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request); // <-- OUR INTEREST
  // ...
}
libc_hidden_def (_IO_fwrite)
```

which calls `_IO_sputn()` macro:

```c
// https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L379
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)

// https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L176
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
#define _IO_WXSPUTN(FP, DATA, N) WJUMP2 (__xsputn, FP, DATA, N)
```

referring to the [jump table](structures.md#io_jump_t), we can see that the implementation for `__xsputn` is `_IO_new_file_xsputn()`

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/fileops.c#L1197" %}

```c
size_t
_IO_new_file_xsputn (FILE *f, const void *data, size_t n)
{
  // ....
  size_t to_do = n;
  // ....
  size_t count = 0;
  // ....
  
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING)) // [0]
    {
      // .. 
    }
  else if (f->_IO_write_end > f->_IO_write_ptr) // <-- NEEDS TO BE SATISFIED [1]
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0) // <-- NEEDS TO BE SATISFIED [2]
    {
      if (count > to_do) // <-- NEEDS TO BE SATISFIED [3]
	count = to_do;
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count); // <-- OUR INTEREST
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0)
    {
     // ...  
    }
  return n - to_do;
}
libc_hidden_ver (_IO_new_file_xsputn, _IO_file_xsputn)

```

our interest lies in `__mempcpy (f->_IO_write_ptr, s, count);` where it will do `memcpy` of destination `write_ptr` and source `s` (buf).&#x20;

first, note that initially `count` and `to_do` is set to 0 as default, then modified over the course of the function execution.&#x20;

at \[3] we need `count` to be bigger than `to_do` which can be easily done because it is 0 as default, so we just need to somehow able to change `count` to be bigger than 0 which also a condition in \[2]

though the block at \[0] also modifies `count`, I think its the route at \[1] is more trivial and intuitive. so we need to satisfy \[1] while dissatisfy \[0].

when all of those requirements are fulfilled, it will then call `memcpy` which corresponds to write profit.

***
