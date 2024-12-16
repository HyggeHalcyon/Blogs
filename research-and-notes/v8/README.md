# V8

## Introduction

* [https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/)
* [https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-1/](https://www.madstacks.dev/posts/V8-Exploitation-Series-Part-1/)
* [https://www.youtube.com/watch?v=Uyrv2F6wI-E](https://www.youtube.com/watch?v=Uyrv2F6wI-E)

## Debug Commands

```bash
└──╼ [★]$ gdb-pwndbg d8
pwndbg> set args --allow-natives-syntax
pwndbg> run
V8 version 12.7.1    
d8> var test = [1.1]                 
undefined                                                                             
d8> %DebugPrint(test)   
DebugPrint: 0x26c100042ae5: [JSArray]                 
    # ...snippet                             
d8> %SystemBreak()                                                                                         
Thread 1 "d8" received signal SIGTRAP, Trace/breakpoint trap.

└──╼ [★]$ gdb-pwndbg d8
pwndbg> set args --allow-natives-syntax --shell <script.js>
```

## Helpers

```javascript
/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function dp(x){ %DebugPrint(x); }
function bp() { %SystemBreak(); }

function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

function addrOf(obj) {

}

function fakeObj(addr) {

}
```

#### Example use case

```bash
└──╼ [★]$ gdb-pwndbg d8
pwndbg> set args --allow-natives-syntax --shell <script.js>
d8> Number(ftoi(val)).toString(16)
# .. some hex
```
