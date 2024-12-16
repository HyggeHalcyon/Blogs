# Bypass the Py

## Problem

<details>

<summary>Description</summary>

An adventurer found this when he fought the great beast named Python. It seems to be locked by something no locksmith has ever opened, wrapped by something that's called a "PyInstaller". Can you find a way to get around this?

</details>

## Solution

Since I have little to no experience when it comes to dealing with window's PE executable, my initial thought is to run it and see what I'm dealing with. Running it will prompt us with a password input.

<figure><img src="../../../.gitbook/assets/image_2023-05-15_004318136.png" alt=""><figcaption><p>Chall.exe Prompt</p></figcaption></figure>

I try to give the most common password and the first that passes through my mind was `password`

<figure><img src="../../../.gitbook/assets/image_2023-05-15_004459852.png" alt="" width="308"><figcaption><p>???</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image_2023-05-15_004622123.png" alt="" width="328"><figcaption></figcaption></figure>

Welp I guess I'm just lucky :P

## Flag

> _**FindITCTF{t4ngl3D\_w1tH\_pyTh0n\_4nd\_5stuff}**_
