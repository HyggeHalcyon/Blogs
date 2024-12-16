# CRYptograPI

## Problem

<details>

<summary>Description</summary>

A Ngawi Spy was arrested in Lempuyangan Railway Station while eating a bread. He was arrested becuse he wanted to deliver an encrypted secret message to another spy. It was known that the message is encrypted by bitwise operating the message with decimal digits of Pi. Can you decrypt the secret message?

</details>

<details>

<summary>Message.txt</summary>

75 5b 5f 12 4d 12 51 50 47 15 5b 58 42 5e 5b 46 12 18 60 5e 5b 45 14 5a 40 18 47 5a 52 19 53 5c 53 5f 02 14 77 50 59 55 7f 6d 70 6d 7f 48 44 06 53 04 7c 73 5c 69 0d 68 5e 0d 5a 0d 74 57 6d 67 03 45 54 05 5a 61 6f 0f 77 5f 02 70 04 50 44

</details>

<details>

<summary>Hints</summary>

* How many bitwise operation do you know?
* Pi has unending decimal digits...

</details>

## Solution

Quite straightforward, we search up for the decimal digits up to the same length as the ciphertext. Then we XOR each digits with the corresponding hex values. Initially I was a bit confused since I XORed each of the ciphertext with <mark style="color:green;">**`int(pi[i])`**</mark> but it doesn't work.&#x20;

{% code title="Solve.py" lineNumbers="true" fullWidth="false" %}
```python
cipher = '755b5f124d12515047155b58425e5b461218605e5b45145a4018475a5219535c535f0214775059557f6d706d7f48440653047c735c690d685e0d5a0d74576d67034554055a616f0f775f0270045044'
pi = '1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821480865132823066470938446095505822317253594081284811174502840'

byte_cipher = bytes.fromhex(cipher)
decoded = []

for i in range(len(byte_cipher)):
    decoded.append(byte_cipher[i] ^ ord(pi[i]))

print(''.join(chr(i) for i in decoded))
```
{% endcode %}

## Flag

> _**FindITCTF{s3b4IKnY4\_j4n9An\_T3rl4lU\_9Eg4B4h}**_
