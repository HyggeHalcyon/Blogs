# Discovered

## Problem

<details>

<summary>Description</summary>

Bob finds a pdf file. He is sure there is important content in it but the pdf file is locked. Can you help him? (Bracket the flag with FindITCTF{})

</details>

## Solution

We're given a PDF with password protected. Let's extract the hash and crack the password using John The Ripper

```bash
$ pdf2john secret.pdf > hash
$ cat hash
```

> secret.pdf:$pdf$&#x34;_&#x34;_&#x31;28\*-106&#x30;_&#x31;_&#x31;&#x36;_&#x66;ce8559bd3fcc84ba72dbad5638fcc2&#x30;_&#x33;&#x32;_&#x63;71748896b9831a45b01a477b9970c980000000000000000000000000000000&#x30;_&#x33;2\*167b0cd8e21bbd37be65e1df44df6a7043f29c342635c1754fa81bc7fc029f7b

Next, we need to cut out the secret.pdf bit so it would look like this

> $pdf$&#x34;_&#x34;_&#x31;28\*-106&#x30;_&#x31;_&#x31;&#x36;_&#x66;ce8559bd3fcc84ba72dbad5638fcc2&#x30;_&#x33;&#x32;_&#x63;71748896b9831a45b01a477b9970c980000000000000000000000000000000&#x30;_&#x33;2\*167b0cd8e21bbd37be65e1df44df6a7043f29c342635c1754fa81bc7fc029f7b

With that done, we can start to crack the hash using john, we'll use the standard rockyou wordlist

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
$ john --show hash
```

> ?:LimitedEdition
>
> 1 password hash cracked, 0 left

Now we have retrieved the password, we can take a look of what's inside of the pdf file

<figure><img src="../../../.gitbook/assets/image_2023-05-15_022949519.png" alt="" width="548"><figcaption><p>pdf contents</p></figcaption></figure>

Looks like we're presented with a emote cipher. After an intensive look up and bunch of wrong tool on the internet, we eventually stumbled upon this tool [`https://codepen.io/NostraDavid/pen/JjGBmxd`](https://codepen.io/NostraDavid/pen/JjGBmxd). There we can supply the emotes and it'll do the job for us

{% hint style="info" %}
in case anyone wants to copy the emotes

😐👴🤔 \_ 👽😐 \_ 🤯🤑👴🤔\_🥶🔠😔🥵🤯🤖 \_ 👴😐🤥🥱 \_ 😐🤯🤯🤤 \_ 🤔👴 \_ 🍤🔠😐🤤 \_ 🤔🥵🤯\_😔👽🤔🤔🤯🤖😐
{% endhint %}

## Flag

> _**FindITCTF{not\_an\_emot\_cipher\_only\_need\_to\_find\_the\_pattern}**_
