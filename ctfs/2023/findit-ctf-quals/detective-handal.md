# Detective Handal

## Problem

<details>

<summary>Description</summary>

Drian is known as a great detective. He always solved the problem he found. One day, Drian is assigned to solve a problem. He got a mysterious code that maybe lead to something. He also got a machine that possible to go to the past. The machine is called "Blow Fish". But, to operate the machine, he needs a key. The one who give him the machine tell Drian, the key is a "line" that assigned you to solve all the problems here. The one who assigned the task also tell him to go back to the past when Drian still in "IV" grade. In that time Drian is asked to figure out "when was the first episode of AOT is release?". Oh ya, the one who assigned task for Drian is always play "Crash Team Racing". Usually, he eats a "Raw" meat. He also love a girl named "Hex"sa. Can you help him solve the problems?

Notes: 17 March 2023 will be write as "17032023" and "line" is an id of an social media

</details>

<details>

<summary>Mysterious_Code.txt</summary>

82bd6ecc67a3fc5a1dbc5156a5dfc007a7774558e8adee71d08b66ced52e6d04c1c25c

</details>

## Solution

Analysing the description we obtained the following information

* The encryption algorithm is <mark style="color:green;">**BlowFish**</mark>
* The key is an ID Line of the one who tasked Drian with this task which is the event organiser itself. A quick tour to their Instagram profile will reveal their Line ID which is <mark style="color:green;">hqx0844o</mark>
* "<mark style="color:green;">C</mark>rash <mark style="color:green;">T</mark>eam <mark style="color:green;">R</mark>acing" can be abbreviated as <mark style="color:green;">CTR</mark> which is the BlowFish encryption mode that was used to encrypt the message
* The IV is Attack on Titan's first episode, which aired on 07 April 2013. Thus can be written as <mark style="color:green;">07042013</mark>

With the information gathered, we can head to [<mark style="color:blue;">CyberChef</mark>](https://gchq.github.io/CyberChef/#recipe=Blowfish_Decrypt\(%7B'option':'UTF8','string':'hqx0844o'%7D,%7B'option':'UTF8','string':'07042013'%7D,'CTR','Hex','Raw'\)\&input=ODJiZDZlY2M2N2EzZmM1YTFkYmM1MTU2YTVkZmMwMDdhNzc3NDU1OGU4YWRlZTcxZDA4YjY2Y2VkNTJlNmQwNGMxYzI1Yw) with said configuration to decrypt it.

## Flag

> _**FindITCF{y0u\_4r3\_a\_gr3at\_d3tect1ve}**_
