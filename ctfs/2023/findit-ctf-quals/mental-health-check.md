# Mental Health Check

## Problem

<details>

<summary>Description</summary>

Mental health is important. We're checking yours before you start competing.

</details>

## Solution

A quick string check with the following command immediately reveal the flag

```bash
$ strings -n 8 mentalhealthcheck.exe | grep "FindITCTF"Flag
```

## Flag

> _**FindITCTF{everyone\_asks\_who\_are\_you\_but\_not\_how\_are\_you}**_
