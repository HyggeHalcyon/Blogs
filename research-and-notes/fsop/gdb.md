# GDB

## Existing FILEs

some of the common `_IO_FILE` :

```bash
pwndbg> print _IO_2_1_stdout_
pwndbg> print _IO_2_1_stdin_
pwndbg> print _IO_2_1_stderr_
pwndbg> print _IO_wide_data_1
```

## Existing Vtables

some of the common `libvio_vtable`:

```
pwndbg> print _IO_file_jumps
pwndbg> print _IO_wfile_jumps
```

## Casting

```bash
pwndbg> print {FILE} <address>
pwndbg> # todo for vtable
pwndbg> # todo for other structs if possible
```
