# Libc Leak

all libc leak is gained through the heap memory region is through the chunk being linked to the unsorted bin. this can be achieved in different ways.

for the examples below, we'll assume we have the following pseudo code function to interface with the challenges:

```python
def alloc(idx: int, size: int, data: byte):
    pass

def free(idx: int):
    pass
```

## natural way

so called natural way is to allocate a chunk of an unsorted bin size, and free it to link it to the unsorted bin as it's implementation, in this case I wouldn't call it an exploitation but rather a misuse. However this might not be always possible due to the environment that may limits the chunk allocation size.

```python
alloc(0, 0x500, b'cawk') # <- victim
alloc(1, 0x10, b'wilderness consolidation protect')
free(0) # links chunk-0 to unsorted bin
```

## tcache fill

in case where allocation size is not enough to link directly to the unsorted bin, another way is to fill the tcache of a certain size to its maximum capacity. any further link attempt to said full tcache bin, will be put into the unsorted bin instead.

```python
for idx in range(7):
    alloc(idx, 0x20, f'idx-{idx}'.encode())
alloc(idx+1, 0x20, b'victim') # <- victim
alloc(idx+2, 0x10, b'wilderness consolidation protect')

for idx in range(7):
    free(idx)
free(idx+1) # links chunk-7 to unsorted bin
```

## unsorted bin splitting

the aforementioned methods are quite easy to use and profit from but they requires UAF primitives that allows us to read free's chunks. Depending on the environment this is not always available.

> TODO ELABORATE MORE ON ANGSTORM 2024 - HEAPIFY AS EXAMPLE

{% embed url="https://github.com/HyggeHalcyon/CTFs/blob/main/2024/%C3%A5ngstrom/heapify/exploit.py" %}

However one thing to note is that this technique requires us to have heap overflow or some other write primitive that allows us to change an adjacent chunk size.

## House Of Orange

the aforementioned methods requires at least a free functionality to success, in this technique no free is required.

{% embed url="https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/house_of_orange/" %}

> TODO ELABORATE MORE ON ANGSTORM 2024 - THEMECTL AS EXAMPLE

{% embed url="https://github.com/HyggeHalcyon/CTFs/blob/main/2024/%C3%A5ngstrom/themectl/exploit.py" %}

the need for an heap overflow or write primitive, even though convenient, is not mandatory. Although that I haven't tested that statement myself yet, I theorized it would work just as fine as you can deplete the wilderness by requesting more heap memory. this is left as an improvisation for future encounters lol.
