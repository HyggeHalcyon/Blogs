# Vtable Hijack

## concept

in newer version of libc, we can no longer overwrite the `file->vtable` address with our fake vtable, this because libc has introduced a mitigation `IO_validate_vtable` that will check whether the vtable that is stored in the `FILE` is in the correct region or not.

`_wide_data` is a struct which is similar to `_IO_FILE` which is created to handle `WCHAR` or unicodes. Both struct have vtables, `_wide_data` uses `_IO_wfile_jumps` vtable while `_IO_FILE` uses `_IO_file_jumps`.

There's two macro that is being used to call these methods within the vtables:

* `_IO_JUMPS_FUNC`
* `_IO_WIDE_JUMPS_FUNC`

the `IO_validate_vtable` mitigation only exist in the `_IO_JUMPS_FUNC` macro.

one thing to note is that `_IO_wfile_jumps.__overflow` method will eventually calls `file->_wide_data->_wide_vtable->__doallocate`.&#x20;

This if way we can:&#x20;

* `file->vtable = file->_wide_data->_wide_vtable`
* `file->_wide_data->_wide_vtable = &fake_wide_vtable`&#x20;

and because the calls to `_wide_data->_wide_vtable` don't have any checks, we can take control of execution.

***

## fwrite

### summary

1. Set `f->flags` to `_IO_MAGIC & ~_IO_CURRENTLY_PUTTING & ~_IO_UNBUFFERED` which is `0xFBAD0000 & ~0x0800 & ~0x0002`
2. Set `f->wide_data` to a controllable fake `wide_data`
3. Set `f->wide_data->_IO_buf_base` and `f->wide_data->_IO_write_base` to 0x0
4. Set `f->vtable` to `_IO_wfile_jumps`
5. Set `f->wide_data->wide_vtable` to a controllabe fake `wide_vtable`
6. Set `f->wide_data->wide_vtable->__doallocate` to `system` or `win`

{% hint style="info" %}
note:

* If space is limited, fake `wide_data` and fake `wide_vtable` can be overlapped
* make sure `f->_lock` contains a valid address that points to NULL
{% endhint %}

### call trace

we can start from it's definition and implementation:&#x20;

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/iofwrite.c#L54" %}

```c
size_t
_IO_fwrite (const void *buf, size_t size, size_t count, FILE *fp)
{
  // ...
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request); // <-- OUR INTEREST
  _IO_release_lock (fp);
  // ...
}
```

which then calls `_IO_sputn()` which is a jump to `__xsputn` section of the `f->vtable`

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L176" %}

```c
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
```

and assuming, we have overwritten `f->vtable` with `_IO_WIDE_JUMPS_FUNC` it will call `_IO_wfile_xsputn()`

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/wfileops.c#L957" %}

```c
size_t
_IO_wfile_xsputn (FILE *f, const void *data, size_t n)
{
  // ...

  if (n <= 0)
    return 0;

  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      // ...
      if (count >= n)
	{
	  const wchar_t *p;
	  for (p = s + n; p > s; )
	    {
	      if (*--p == L'\n')
		{
                  // ...
		}
	    }
	}
    }
  
  if (count > 0)
    {
      if (count > to_do)
	// ...
      if (count > 20)
	{
	  // ...
	}
      else
	{
		// ...
	}
      to_do -= count;
    }
  if (to_do > 0)
    to_do -= _IO_wdefault_xsputn (f, s, to_do); // <-- OUR INTEREST
  
  // ...
}
```

which then calls `_IO_wdefault_xsputn()`

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/wgenops.c#L284" %}

```c
size_t
_IO_wdefault_xsputn (FILE *f, const void *data, size_t n)
{
  // ..
  if (more <= 0)
    return 0;
  for (;;)
    {
      // ..
      if (count > 0)
	{
	  // ..
        }
      if (more == 0 || __woverflow (f, *s++) == WEOF) // <-- OUR INTEREST
      
      // ..
}
```

which then calls `__woverflow()`

```c
wint_t
__woverflow (FILE *f, wint_t wch)
{
  if (f->_mode == 0)
    _IO_fwide (f, 1);
  return _IO_OVERFLOW (f, wch); // <-- OUR INTEREST
}
```

when calls `_IO_OVERFLOW ();`&#x20;

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L146" %}

```c
typedef int (*_IO_overflow_t) (FILE *, int);
#define _IO_OVERFLOW(FP, CH) JUMP1 (__overflow, FP, CH)
#define _IO_WOVERFLOW(FP, CH) WJUMP1 (__overflow, FP, CH)
```

again, remember we have overwritten `f->vtable` with `_IO_WIDE_JUMPS_FUNC` and because of it the `__overflow` section of `f->vtable` will refer to `_IO_wfile_overflow()` and so the execution continues from there on

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/wfileops.c#L408" %}

```c
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0) // <-- NEEDS TO BE SATISFIED
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0) // <-- NEEDS TO BE SATISFIED
	{
	  _IO_wdoallocbuf (f);		      // <-- OUR INTEREST
	  // stuff
	  if (f->_IO_write_base == NULL)
	    {
	      // stuff
	    }
	}
     // ... not rlly relevant
}
libc_hidden_def (_IO_wfile_overflow)
```

assuming we set the correct `f->flags` and other requirement it will eventually call `_IO_wdoallocbuf()`&#x20;

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/wgenops.c#L366" %}

```c
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base) // <-- NEEDS TO BE SATISFIED
    return;
  if (!(fp->_flags & _IO_UNBUFFERED)) // <-- NEEDS TO BE SATISFIED
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF) // <-- OUR INTEREST
      return;
  // stuff
}
libc_hidden_def (_IO_wdoallocbuf)
```

again, setting the correct requirements that satisfied the if statements will call `_IO_WDOALLOCATE()`

{% embed url="https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/libioP.h#L223" %}

```c
typedef int (*_IO_doallocate_t) (FILE *);
#define _IO_DOALLOCATE(FP) JUMP0 (__doallocate, FP)
#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)
```

which will then call `f->wide_data->wide_vtable->__doallocate`. and since its within our control, we control the execution.

***

## others

### todo
