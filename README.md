# cyptra
C++ encryption library made in an hour.

It’s pretty shitcoded and the internals are kind of a mess, so don’t expect architecture or a perfectly organized file. The focus was mainly on keeping the library lightweight and extremely easy to use.

Despite the questionable structure, it’s fast to integrate, simple to understand, and does the job without forcing a bunch of boilerplate onto the user. Just drop it in and use it. (just like the original)

The main focus on this library was the encryption keys. The original encryption keys were 2 characters and obviously that wasn't very secure so I added a lot more randomness per build).
The other biggest change is the actual decryption/encryption.
The original
`_storage[i] = data[i] ^ (_key1 + i % (1 + _key2));`

Is VERY insecure and there are lots of public projects showing how to decrypt it.
The new one:
`Key1 + ((i * Key2) & 0xFF)`

This creates non-repeating linear progression, larger effective keyspace, and better diffusion. Its
still technically xor based but it but its less pattern, repetition, and better against most string scanners. There is still lots more changes but I don't want to rant about every new line.

Hope you guys can find some flaws and fix them or just integrate for your projects protection

UC link: https://www.unknowncheats.me/forum/c-and-c-/753972-cryptra.html#post4686627

## string example
### example code:
```cpp
#include "cryptra.hxx"

int main() {
	auto str1 = _("testing!!"); // encrypted string (with `_` macro)
	printf("%s\n", str1);
	str1.clear(); // clears str from runtime memory
}
```
### example ida output:
```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rbx
  unsigned __int64 v4; // rdi
  _QWORD *v5; // rsi
  size_t v6; // rax
  void *v7; // rax
  size_t v8; // rcx
  void **v9; // rax
  void *v10; // rcx
  __int64 Src; // [rsp+30h] [rbp-19h] BYREF
  __int16 v13; // [rsp+38h] [rbp-11h]
  char v14; // [rsp+3Ah] [rbp-Fh]
  __int128 v15; // [rsp+50h] [rbp+7h]
  __int128 v16; // [rsp+60h] [rbp+17h]
  void *Block[2]; // [rsp+70h] [rbp+27h] BYREF
  __int128 v18; // [rsp+80h] [rbp+37h]

  v13 = -14268;
  v14 = 1;
  Src = 0x23F852B00260D539i64;
  sub_140001440(&Src, &Src, envp);
  *(_OWORD *)Block = 0i64;
  v3 = -1i64;
  do
    ++v3;
  while ( *((_BYTE *)&Src + v3) );
  v4 = 0x7FFFFFFFFFFFFFFFi64;
  if ( v3 > 0x7FFFFFFFFFFFFFFFi64 )
    sub_140001210();
  if ( v3 <= 0xF )
  {
    *(_QWORD *)&v18 = v3;
    *((_QWORD *)&v18 + 1) = 15i64;
    memcpy(Block, &Src, v3);
    *((_BYTE *)Block + v3) = 0;
    v4 = *((_QWORD *)&v18 + 1);
    v5 = Block[0];
    goto LABEL_19;
  }
  if ( (v3 | 0xF) > 0x7FFFFFFFFFFFFFFFi64 )
  {
    v6 = 0x8000000000000027ui64;
LABEL_8:
    v7 = operator new(v6);
    if ( !v7 )
      goto LABEL_24;
    v5 = (_QWORD *)(((unsigned __int64)v7 + 39) & 0xFFFFFFFFFFFFFFE0ui64);
    *(v5 - 1) = v7;
    goto LABEL_18;
  }
  v4 = v3 | 0xF;
  if ( (v3 | 0xF) < 0x16 )
    v4 = 22i64;
  v8 = v4 + 1;
  if ( v4 == -1i64 )
  {
    v5 = 0i64;
  }
  else
  {
    if ( v8 >= 0x1000 )
    {
      v6 = v4 + 40;
      if ( v4 + 40 <= v4 + 1 )
        sub_140001170();
      goto LABEL_8;
    }
    v5 = operator new(v8);
  }
LABEL_18:
  Block[0] = v5;
  *(_QWORD *)&v18 = v3;
  *((_QWORD *)&v18 + 1) = v4;
  memcpy(v5, &Src, v3);
  *((_BYTE *)v5 + v3) = 0;
LABEL_19:
  v15 = *(_OWORD *)Block;
  v16 = v18;
  sub_140001010("%s\n");
  v9 = Block;
  if ( v4 > 0xF )
    v9 = (void **)v5;
  *(_BYTE *)v9 = 0;
  if ( *((_QWORD *)&v18 + 1) > 0xFui64 )
  {
    v10 = Block[0];
    if ( (unsigned __int64)(*((_QWORD *)&v18 + 1) + 1i64) >= 0x1000 )
    {
      v10 = (void *)*((_QWORD *)Block[0] - 1);
      if ( (unsigned __int64)(Block[0] - v10 - 8) > 0x1F )
LABEL_24:
        invoke_watson(0i64, 0i64, 0i64, 0, 0i64);
    }
    j_j_free(v10);
  }
  return 0;
}
```

## int example
### example code:
```cpp
#include "cryptra.hxx"

int main() {
	printf("%d\n", _int(0x5)); // `_int` encrypts the value `0x5`
}
```
### example ida output:
```cpp
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // r10
  unsigned int v4; // r9d
  unsigned __int64 i; // rcx
  int v6; // eax
  int v7; // edx
  int v8; // eax
  int v9; // r9d

  v3 = 0i64;
  v4 = 398551824;
  for ( i = 0i64; i < 0x20; i += 8i64 )
  {
    v6 = 86 * v3++;
    v7 = (v6 + 21) ^ (v4 >> i);
    v8 = v4 & ~(255 << i);
    v9 = (unsigned __int8)v7 << i;
    v4 = v8 | v9;
  }
  sub_140001010("%d\n");
  return 0;
}
```
