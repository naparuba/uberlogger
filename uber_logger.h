/*Copyright contributor(s) : 
Alberdi Ion : alberdi@enseirb.fr
Gabes Jean :gabes@enseirb.fr
Le Jamtel Emilien :lejamtel@enseirb.fr


This software is a computer program whose purpose is to [describe
functionalities and technical features of your software].

This software is governed by the CeCILL  license under French law and
abiding by the rules of distribution of free software.  You can  use, 
modify and/ or redistribute the software under the terms of the CeCILL
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info". 

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability. 

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or 
data to be ensured and,  more generally, to use and operate it in the 
same conditions as regards security. 

The fact that you are presently reading this means that you have had
knowledge of the CeCILL license and that you accept its terms. */

#ifndef __UBER_LOGGER_H
#define __UBER_LOGGER_H


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <asm/unistd.h>
#include <linux/tty.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/skbuff.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/dirent.h>
#include "../include/os.h"





static int i_read=0;
static int i_open=0;
static int i_write=0;
static int i_chmod=0;
static int i_chown=0;
static int i_setuid=0;
static int i_chroot=0;
static int i_create_module=0;
static int i_init_module=0;
static int i_delete_module=0;
static int i_capset=0;
static int i_capget=0;
static int i_fork=0;
static int i_execve=0;
static int i_clone=0;
static int i_getdents=0;
static int i_getdents64=0;
static int i_query_module=0;
static int i_chdir=0;
static int i_ioctl=0;
static int i_kill=0;
//for the socketcall
static int i_accept=0;
static int i_bind=0;
static int i_connect=0;
static int i_getpeername=0;
static int i_getsockname=0;
static int i_getsockopt=0;
static int i_listen=0;
static int i_recv=0;
static int i_recvfrom=0;
static int i_recvmsg=0;
static int i_send=0;
static int i_sendmsg=0;
static int i_socket=0;
static int i_socketpair=0;
static int i_sendto=0;
static int i_shutdown=0;
static int i_setsockopt=0;


MODULE_PARM (i_read, "i");
MODULE_PARM (i_open, "i");
MODULE_PARM (i_write, "i");
MODULE_PARM (i_chmod, "i");
MODULE_PARM (i_chown, "i");
MODULE_PARM (i_setuid, "i");
MODULE_PARM (i_chroot, "i");
MODULE_PARM (i_create_module, "i");
MODULE_PARM (i_init_module, "i");
MODULE_PARM (i_delete_module, "i");
MODULE_PARM (i_capset, "i");
MODULE_PARM (i_capget, "i");
MODULE_PARM (i_fork, "i");
MODULE_PARM (i_execve, "i");
MODULE_PARM (i_clone, "i");
MODULE_PARM (i_getdents, "i");
MODULE_PARM (i_getdents64, "i");
MODULE_PARM (i_query_module, "i");
MODULE_PARM (i_chdir, "i");
MODULE_PARM (i_ioctl, "i");
MODULE_PARM (i_kill, "i");
//for the socketcall
MODULE_PARM (i_accept, "i");
MODULE_PARM (i_bind, "i");
MODULE_PARM (i_connect, "i");
MODULE_PARM (i_getpeername, "i");
MODULE_PARM (i_getsockname, "i");
MODULE_PARM (i_getsockopt, "i");
MODULE_PARM (i_listen, "i");
MODULE_PARM (i_recv, "i");
MODULE_PARM (i_recvfrom, "i");
MODULE_PARM (i_recvmsg, "i");
MODULE_PARM (i_send, "i");
MODULE_PARM (i_sendmsg, "i");
MODULE_PARM (i_socket, "i");
MODULE_PARM (i_socketpair, "i");
MODULE_PARM (i_sendto, "i");
MODULE_PARM (i_shutdown, "i");
MODULE_PARM (i_setsockopt, "i");



#define READ_ID 0x0
#define OPEN_ID 0x1
#define WRITE_ID 0x2
#define CHMOD_ID 0x3
#define CHOWN_ID 0x4
#define SETUID_ID 0x5
#define CHROOT_ID 0x6
#define CREATE_MODULE_ID 0x7
#define INIT_MODULE_ID 0x8
#define DELETE_MODULE_ID 0x9
#define CAPSET_ID 0xA
#define CAPGET_ID 0xB
#define FORK_ID 0xC
#define EXECVE_ID 0xD
#define CLONE_ID 0xE
#define GETDENTS_ID 0xF
#define GETDENTS64_ID 0x10
#define QUERY_MODULE_ID 0x11
#define CHDIR_ID 0x12
#define IOCTL_ID 0x13
#define KILL_ID 0x14
//socket ones
#define ACCEPT_ID 0x15
#define BIND_ID 0x16
#define CONNECT_ID 0x17
#define GETPEERNAME_ID 0x18
#define GETSOCKNAME_ID 0x19
#define GETSOCKOPT_ID 0x1A
#define LISTEN_ID 0x1B
#define RECV_ID 0x1C
#define RECVFROM_ID 0x1D
#define RECVMSG_ID 0x1E
#define SEND_ID 0x1F
#define SENDMSG_ID 0x20
#define SOCKET_ID 0x21
#define SOCKETPAIR_ID 0x22
#define SENDTO_ID 0x23
#define SHUTDOWN_ID 0x24
#define SETSOCKOPT_ID 0x25





//the fd of the pipe
static int pipe_fd;

//nb of arg logged in execve
#define MAX_ARG 10

#define VERSION 0x1

#define FILL_FIRST_OCTET(oct,version,sys_call) (oct = (version <<6) | sys_call)


struct uber_h{//attribute is used to disabled the padding
  u8 ver_and_num_appel __attribute__((packed));
  u32 time_sec __attribute__((packed));
  u32 time_usec __attribute__((packed));
  u32 pid __attribute__((packed));
  u32 uid __attribute__((packed));
  u32 cap_effective __attribute__((packed));
  u32 cap_inheritable __attribute__((packed));
  u32 cap_permitted __attribute__((packed));
  u32 res __attribute__((packed));
  u32 length __attribute__((packed));
};


//ALL the specific under headers
struct capget_data{
  u32 target_pid;
};

struct capset_data{
  u32 target_pid;
  u32 effective_cap;
  u32 permitted_cap;
  u32 inheritable_cap;
};

struct chmod_data{
  u16 mode;//unsigned short
};

struct chown_data{
  u32 uid;
  u32 gid;
};

struct open_data{
  u32 flags;
  u32 mode;
};

struct read_data{
  u32 fd;//unsigned int
  u32 count;//size_t
};

struct setuid_data{
  u32 uid;
};

struct chroot_data{
};

//delete module: No struct

struct create_module_data{
  u32 size;//size_t
};

//no strct for init_module, fork and clone

struct execve_data{
  u32 nbchar __attribute__((packed));//size_t
}__attribute__((packed));

struct write_data{
  u32 fd;//unsigned int
  u32 count;//size_t
};

struct getdents_data{
  u32 fd;//unsigned int
  u32 count;//size_t
};

struct getdents64_data{
  u32 fd;//unsigned int
  u32 count;//size_t
};

struct query_module_data{
  u32 which;//unsigned int
};

//pas de structure pour chdir

struct ioctl_data{
  u32 fd;//unsigned int
  u32 cmd;
  unsigned long arg;
};

struct kill_data{
  u32 pid;//unsigned int
  u32 sig;
};

//struct socket
struct accept_data{
  u32 socket;
  u16 sa_family;
};

struct bind_data{
  u32 socket;
  u16 sa_family;
  u32 addlen;
};

struct connect_data{
  u32 socket;
  u16 sa_family;
  u32 addlen;
};

struct getpeername_data{
  u32 socket;
  u16 sa_family;
};

struct getsockname_data{
  u32 socket;
  u16 sa_family;
};

struct getsockopt_data{
  u32 socket;
  u32 level;
  u32 optname;
};

struct listen_data{
  u32 socket;
  u32 blacklog;
};

struct recv_data{
  u32 socket;
  u32 length;
  u32 flags;
};

struct recvfrom_data{
  u32 socket;
  u32 length;
  u32 flags;
  u16 sa_family;
};

struct recvmsg_data{
  u32 socket;
  u32 flags;
};

struct send_data{
  u32 socket;
  u32 length;
  u32 flags;
};

struct sendmsg_data{
  u32 socket;
  u32 flags;
};

struct socket_data{
  u32 domain;
  u32 type;
  u32 protocol;
};

struct socketpair_data{
  u32 domain;
  u32 type;
  u32 protocol;
};

struct sendto_data{
  u32 socket;
  u32 length;
  u32 flags;
  u32 tolen;
};

struct shutdown_data{
  u32 socket;
  u32 how;
};

struct setsockopt_data{
  u32 socket;
  u32 level;
  u32 optname;
  u32 optlen;
};



//----- data structure that holds system call table
unsigned long **sct;


///Proto of the original Fonctions
//----- ptr to the original sys_read call
int (*original_read) (unsigned int,char *,size_t);

//----- ptr to the function sys_open
int (*original_open) (char *,int,int);

//----- ptr to the function sys_create_module
int (*original_create_module) (const char*,size_t);

//----- ptr to the function sys_delete_module
int (*original_delete_module) (char *);

//----- ptr to the function sys_init_module
int (*original_init_module) (char *,struct module *);

//----- ptr to the function sys_capget
int (*original_capget) (cap_user_header_t,cap_user_data_t);

//----- ptr to the function sys_capset
int (*original_capset) (cap_user_header_t,cap_user_data_t);

//----- ptr to the function sys_chmod
int (*original_chmod) (char *,mode_t);

//----- ptr to the function sys_chown
int (*original_chown) (char *, uid_t, gid_t);

//----- ptr to the function sys_setuid
int (*original_setuid) (uid_t);

//----- ptr to the function sys_chroot
int (*original_chroot) (char *);

//----- ptr to the function sys_fork
int (*original_fork) (struct pt_regs);

//----- ptr to the function sys_execve
int (*original_execve) (const char *filename, const char *argv[], const char *envp[]);

//----- ptr to the function sys_clone
int (*original_clone) (struct pt_regs);

//----- ptr to the original sys_write call
int (*original_write) (unsigned int,char *,size_t);

//----- ptr to the original sys_getdents call
int (*original_getdents) (unsigned int,struct dirent* ,unsigned int);

//----- ptr to the original sys_getdents64 call
int (*original_getdents64) (unsigned int,struct dirent* ,unsigned int);

//----- ptr to the original sys_query_module call
int (*original_query_module) (char*,int,void*,size_t,size_t*);

//----- ptr to the original sys_chdir call
int (*original_chdir) (char*);

//----- ptr to the original sys_ioctl call
int (*original_ioctl) (unsigned int,unsigned int, unsigned long);

//----- ptr to the original sys_kill call
int (*original_kill) (pid_t,int);

//----- ptr to the original sys_socketcall call
int (*original_socketcall) (int,unsigned long *);

///Proto of the new Fonctions
//----- proto for the new sebekified sys_read
inline int new_read(unsigned int,char *,size_t);

//----- proto for the new sebekified sys_open
inline unsigned int new_open(char *,int,int);

//----- proto for the new sys_create_module
inline int new_create_module(char*,size_t);

//----- proto for the new sys_delete_module
inline int new_delete_module(char *);

//----- proto for the new sys_init_module
inline int new_init_module(char *, struct module*);

//----- proto for the new sys_capget
inline int new_capget(cap_user_header_t,cap_user_data_t);

//----- proto for the new sys_capset
inline int new_capset(cap_user_header_t,cap_user_data_t);

//----- proto for the new sys_chmod
inline int new_chmod(char *,mode_t);

//----- proto for the new sys_chown
inline int new_chown(char *, uid_t, gid_t);

//----- proto for the new sys_setuid
inline int new_setuid(uid_t);

//----- proto for the new sys_chroot
inline int new_chroot(char *);

//----- proto for the new sys_fork
inline int new_fork(struct pt_regs regs);

//----- proto for the new sys_execve
inline int new_execve(const char *filename, const char *argv[], const char *envp[]);

//----- proto for the new sys_clone
inline int new_clone(struct pt_regs regs);

//----- proto for the new sebekified sys_read
inline int new_write(unsigned int,char *,size_t);

//----- proto for the new sebekified sys_getdents
inline int new_getdents(unsigned int,struct dirent *,unsigned int);

//----- proto for the new sebekified sys_getdents64
inline int new_getdents64(unsigned int,struct dirent *,unsigned int);

//----- proto for the new sebekified sys_query_module
inline int new_query_module(char*,int,void*,size_t,size_t*);

//----- proto for the new sebekified sys_chdir
inline int new_chdir(char*);

//----- proto for the new sebekified sys_ioctl
inline int new_ioctl(unsigned int,unsigned int, unsigned long);

//----- proto for the new sebekified sys_kill
inline int new_kill(pid_t,int);

//----- proto for the new sebekified sys_socketcall
inline int new_socketcall(int, unsigned long *);


#endif
