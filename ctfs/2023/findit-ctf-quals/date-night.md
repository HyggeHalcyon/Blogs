# Date Night

## Problem

<details>

<summary>Description</summary>

Suasana senja yang indah menjadi saksi perjalanan kami berdua, aku dan ayang. Kami berjalan bersama di atas jalan setapak yang mengelilingi taman kota yang ramai. Sinar matahari terbenam yang merah jambu menyinari wajah ayang yang cantik membuatku terpesona seketika. Kami berbicara tentang hal-hal kecil yang membuat hati kami senang dan tertawa bersama. Sambil berjalan, kami menyaksikan anak-anak yang bermain di taman dan memandang langit yang semakin gelap. Saat itulah aku merasa betapa beruntungnya aku memiliki ayang di sisiku, menjalani perjalanan hidup bersama-sama, berbagi cerita, bahagia dan sedih, serta saling mendukung satu sama lain. Perjalanan yang singkat tapi penuh makna bersama ayang membuatku merasa hidup ini lebih indah.

Anyway busway, perform Forensics Analysis to get the flag.

</details>

## Solution

Simply run strings on the document shall do the job

```bash
$ strings -n 8 challenge.docx | grep "FindITCTF"
```

## Flag

> _**FindITCTF{j4lan\_bar3ng\_ay4ng\_739397}**_
