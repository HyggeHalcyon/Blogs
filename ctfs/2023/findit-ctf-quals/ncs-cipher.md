# NCS Cipher

## Problem

<details>

<summary>Description</summary>

listening to NCS music takes me back to my childhood and teenage years. I remember discovering the NoCopyrightSound YouTube channel and being amazed by the variety of electronic music available. NCS music was everywhere in the early 2010s, especially among gamers, YouTubers, and content creators. For me, NCS was the soundtrack of my youth. The energetic beats and catchy melodies of NCS songs made studying, gaming, and hanging out with friends more enjoyable. Whenever I listen to NCS music now, it brings back memories of the carefree times of my youth, and I'm reminded of the friendships and experiences that defined that period of my life. NCS music will always hold a special place in my heart and take me back to a time when life was simpler and full of possibilities. Anyways, lately we find that a lot of ways to hide an information is a little bit boring. So I made this cipher method using NCS music. Well, it may be easy to break and figure out the hidden message, but atleast it's fun to listen to right?

</details>

## Solution

We're given a mp3 file which is mix of songs appended collected randomly from [`https://raw.githubusercontent.com/dundorma/TinDog-WebDev-Bootcamp/master/random-data/NoCopyrightSounds.json`](https://raw.githubusercontent.com/dundorma/TinDog-WebDev-Bootcamp/master/random-data/NoCopyrightSounds.json). To decrypt we use music finder tools such as Shazam to find the music title. Then we math the title to its corresponding `seqId` within the JSON. Lastly, we map the gathered `seqId` values to ASCII letters in order of their appearances within the mp3. &#x20;

Thanks to Aeryx, he wrote the following script to split can cut the mp3 into parts of different musics it made of

{% code title="Split.py" lineNumbers="true" %}
```python
from pydub import AudioSegment


# Load the music file
audio = AudioSegment.from_file("flag.mp3")


# Define the segment duration in milliseconds (5 seconds = 5000 milliseconds)
segment_duration = 5000


# Split the audio into segments of the defined duration
segments = [audio[i:i+segment_duration] for i in range(0, len(audio), segment_duration)]


# Export each segment to individual files
for i, segment in enumerate(segments):
   segment.export(f"segment_{i+1}.mp3", format="mp3")
```
{% endcode %}

1. Paul Flint - Savage \[NCS Release] -> seqId : 109
2. Waysons - Eternal Minds \[NCS Release] -> seqId :  51
3. Cartoon feat. Jüri Pootsmann - I Remember U (Xilent Remix) \[NCS Release] -> seqId :  77
4. JJD - Adventure \[NCS Release] -> seqId : 111
5. Kadenza - Harpuia \[NCS Release] -> seqId : 114
6. Ship Wrek - Pain (feat. Mia Vaile) \[NCS Release] -> seqId : 105
7. Rob Gasser & Laura Brehm - Vertigo \[NCS Release] -> seqId : 101
8. Different Heaven - Far Away \[NCS Release] -> seqId : 53
9. SKYL1NK - The Wizard \[NCS Release] -> seqId : 95
10. Mendum - Red Hands (feat. Omri) \[NCS Release] -> seqId 85
11. Elektronomia - Energy \[NCS Release] -> seqId : 110
12. Phantom Sage - Silence (feat. Byndy) \[NCS Release] -> seqId : 76
13. Cartoon - Immortality (feat. Kristel Aaslaid) \[Futuristik Remix] | NCS Release -> seqId : 48
14. Blazars - Polaris \[NCS Release] -> seqId : 99
15. K-391 - Earth \[NCS Release] -> seqId : 75
16. Inukshuk - We Were Infinite \[NCS Release] -> seqId : 69
17. Chime & Adam Tell - Whole \[NCS Release] -> seqId : 100

{% code title="Solve.py" lineNumbers="true" %}
```python
seqid = [109, 51, 77, 111, 114, 105, 101, 53, 95, 85, 110, 76, 48, 99, 75, 69, 100] 
flag = []

for i in range(len(seqid)):
    if(isinstance(seqid[i], int)):
        flag.append(chr(seqid[i]))  
    else:
        flag.append(seqid[i])

print(''.join(flag))
```
{% endcode %}

## Flag

> _**FindITCTF{m3Morie5\_UnL0cKEd}**_
