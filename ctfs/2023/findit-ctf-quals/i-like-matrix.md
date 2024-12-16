# I Like Matrix

## Problem

<details>

<summary>Description</summary>

A student named Bob really likes studying Linear Algebra. While he was studying this, he was very fond of a mathematician named David HillBert and his favorite matrix was the Fibonacci matrix. When practicing questions, he always starts with a a 2x2 matrix that contains positive numbers with one digit. At one point he had an important message. Due to his interest, he tries to encrypt the message twice but once it is encrypted, he forgets the message. Help him find the message.

</details>

<details>

<summary>EncryptedMessage.txt</summary>

NigvPZDPZ{YYWamFwHmL\_cJ\_hjS\_xIjh\_JzdQmw}

</details>

<details>

<summary>Hints</summary>

* Fibonacci matrix itu maksudnya fibonacci matrix dengan pangkat 1 |1 1| |1 0|
* Pada kalimat ke-3, itu maksudnya matrix 2x2 dengan masing-masing elemennya berisi bilangan positif satu digit

</details>

## Solution

Based on the Description we know that:

* The encryption algorithm used is Hill Cipher
* It was Encrypted twice
* The matrix key is a 2x2 Fibonacci's matrix

There's a few configurations for Hill Cipher namely,

* Alphabet (26 let. A=0) ABCDEFGHIJKLMNOPQRSTUVWXYZ
* Alphabet (26 let. A=1) ZABCDEFGHIJKLMNOPQRSTUVWXY&#x20;
* Alphabet (27 char. A=0) ABCDEFGHIJKLMNOPQRSTUVWXYZ\_&#x20;
* Alphabet (27 char. A=1) \_ABCDEFGHIJKLMNOPQRSTUVWXYZ

We tried deciphering using Fibonacci's matrix with every configurations possible but no result alas we had to revert to brute force approach and using online tools, eventually we found the flag with the following configurations&#x20;

{% tabs %}
{% tab title="First Decryption" %}
Ciphertext = NigvPZDPZ{YYWamFwHmL\_cJ\_hjS\_xIjh\_JzdQmw}

Config: {0,5,1,2} (A=0)

Plaintext = IndwTDTLO{FCKmaUbErI\_xT\_heH\_ePth\_LhuLms}
{% endtab %}

{% tab title="Second Decryption" %}
Ciphertext = IndwTDTLO{FCKmaUbErI\_xT\_heH\_ePth\_LhuLms}

Config: {0,1,3,3} (A=0)

Plaintext = FindITCTF{OKComPuTeR\_iS\_thE\_bEst\_AlbUum}
{% endtab %}
{% endtabs %}

## Flag

> _**FindITCTF{OKComPuTeR\_iS\_thE\_bEst\_AlbUum}**_
