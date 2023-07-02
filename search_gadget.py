from pwn import ELF, asm
elf = ELF("linux-5.15.103/vmlinux")
# 0x170 + 0x50
assems = elf.search(asm("pop rdi; ret;" ,arch = 'amd64', os = 'linux'))
for assem in assems:
    print(hex(assem))
