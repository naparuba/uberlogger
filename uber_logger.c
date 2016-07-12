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

#define MODULE 
#define __KERNEL__


#include "uber_logger.h"


void uber_write_log(char * buf, size_t count){
  int res;
  
  res=os_write_file(pipe_fd,buf,count);
  if(res==-1)
    printk("Error in writing.\n");
  return;
}


/*Fonction utilisee par log*/
inline struct uber_h* gn_pkt(u8 ver_and_num_appel,
			     u32 time_sec, u32 time_usec, 
			     u32 pid,u32 uid,u32 res, 
			     u32 cap_effective,u32 cap_inheritable,u32 cap_permitted,
			     u32 length,void* buffer){

  struct uber_h *pkt;
  int pkt_size = sizeof(struct uber_h) + length;
  
  if (!(pkt = (struct uber_h *)kmalloc(pkt_size,GFP_KERNEL))){
    return NULL;
  }
  
  pkt->ver_and_num_appel=ver_and_num_appel;
  pkt->time_sec=time_sec;
  pkt->time_usec=time_usec;
  pkt->pid = pid;
  pkt->uid = uid;
  pkt->res = res;
  pkt->cap_effective = cap_effective;
  pkt->cap_inheritable = cap_inheritable;
  pkt->cap_permitted = cap_permitted;
  pkt->length = length;
  memcpy((u_char*)pkt+sizeof(struct uber_h),buffer,length);
  kfree(buffer);
  return pkt;
}



/*proto
 *qui devre etre utilise par chaque nvlle fonction
 *chaque fonction du faire:
 *construire le sous_header
 *apeler la fonction log,lentgh et buffer etant les param du sous header
 */
void log_pkt(u8 ver_and_num_appel,u32 res,u32 length,void* buffer){
  struct timeval time;
  struct uber_h* pkt;
  do_gettimeofday(&time);
  pkt = gn_pkt(ver_and_num_appel,
			      time.tv_sec,time.tv_usec,
			      current->pid,current->uid,
			      current->cap_effective,current->cap_inheritable,current->cap_permitted,
			      res,length,buffer);
  uber_write_log((char*)pkt,(size_t)(sizeof(struct uber_h)+length));
}



//----- new_read:  New Read, this calls the old read call
inline int new_read (unsigned int fd, char *buf, size_t count) {
  int r,len_buf=0,data_size;
  u8 first_octet;
  struct read_data* data;

  r = original_read(fd, buf, count);
  if (r >=0){
    char* buffer_pointer;
    len_buf = (int)r;
    data_size = sizeof(struct read_data)+len_buf;
    data = (struct read_data*)kmalloc(data_size,GFP_KERNEL);
    data->fd = (u32)fd;
    data->count = (u32)len_buf;
    buffer_pointer = (char*)data+sizeof(struct read_data);
    strncpy_from_user(buffer_pointer,buf,len_buf);
    //We generate the paket
    FILL_FIRST_OCTET(first_octet,VERSION,READ_ID);
    log_pkt(first_octet,(u32)r,data_size,(void*)data);
    }
  return r;
}

//----- New Open
inline unsigned int new_open(char * buf,int flags ,int mode){
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  struct open_data* data;
  
  r=original_open(buf, flags, mode);
  strlen_buf = strlen_user(buf) + 1;
  data_size = sizeof(struct open_data)+strlen_buf;
  data = (struct open_data*)kmalloc(data_size,GFP_KERNEL);
  data->flags = (u32)flags;
  data->mode = (u32)mode;
  strncpy_from_user((char*)data+sizeof(struct open_data),buf,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,OPEN_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}

//----- New sys_create_module
inline int new_create_module(char* buf,size_t size){
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  struct create_module_data* data;
  
  r=original_create_module(buf,size);
  strlen_buf = strlen_user(buf) + 1;
  data_size = sizeof(struct create_module_data)+strlen_buf;
  data = (struct create_module_data*)kmalloc(data_size,GFP_KERNEL);
  data->size = (u32)size;
  strncpy_from_user((char*)data+sizeof(struct create_module_data),buf,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,CREATE_MODULE_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}

//----- New sys_delete_module
inline int new_delete_module(char* buf){
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  char * data;
  
  
  r=original_delete_module(buf);
  data_size = strlen_user(buf) + 1;
  data = (char*)kmalloc(data_size,GFP_KERNEL);
  strncpy_from_user((char*)data,buf,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,READ_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}

//----- New sys_init_module
inline int new_init_module(char *buf, struct module * mod){
  int r,strlen_buf=0,strlen_name=0,data_size;
  u8 first_octet;
  char * data;
  
  r=original_init_module(buf,mod);
  strlen_buf = strlen_user(buf);
  strlen_name = strlen_user(mod->name);
  data_size = strlen_buf + strlen_name;
  data = (char*)kmalloc(data_size,GFP_KERNEL);
  strncpy_from_user((char*)data,buf,strlen_buf);
  strncpy_from_user((char*)(data+strlen_buf),mod->name,strlen_name);
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,INIT_MODULE_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}


//----- New sys_capget 
inline int new_capget(cap_user_header_t cap_header,cap_user_data_t cap_data){
  int r;
  struct capget_data data;
  u8 first_octet;
  r=original_capget(cap_header,cap_data);
  
  //We create the capget specific data field
  copy_from_user(&(data.target_pid),&(cap_header->pid),sizeof(int));

  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,CAPGET_ID);
  log_pkt(first_octet,(u32)r,sizeof(struct capget_data),&data);
  return r;
}

//----- New sys_capset 
inline int new_capset(cap_user_header_t cap_header,cap_user_data_t cap_data){
  int r;
  struct capset_data data;
  struct __user_cap_data_struct imported_data;
  u8 first_octet;
  r=original_capset(cap_header,cap_data);
  
  //We create the capset specific data field
  copy_from_user(&(data.target_pid),&(cap_header->pid),sizeof(int));
  copy_from_user(&imported_data,cap_data,sizeof(struct __user_cap_header_struct));
  data.effective_cap = imported_data.effective;
  data.permitted_cap = imported_data.permitted;
  data.inheritable_cap = imported_data.inheritable;
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,CAPSET_ID);
  log_pkt(first_octet,(u32)r,sizeof(struct capset_data),&data);
  return r;
}

//----- New sys_chmod 
inline int new_chmod(char * buf ,mode_t m){
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  struct chmod_data* data;
  r=original_chmod(buf,m);
  strlen_buf = strlen_user(buf);
  data_size = sizeof(struct chmod_data)+strlen_buf;
  data = (struct chmod_data*)kmalloc(data_size,GFP_KERNEL);
  data->mode = (u16)m;
  strncpy_from_user((char*)data+sizeof(struct chmod_data),buf,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,CHMOD_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}


//----- New sys_chown
inline int new_chown(char * buf, uid_t u, gid_t g){
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  struct chown_data* data;

  r=original_chown(buf,u,g);  
  strlen_buf = strlen_user(buf);
  data_size = sizeof(struct chown_data)+strlen_buf;
  data = (struct chown_data*)kmalloc(data_size,GFP_KERNEL);
  data->uid = (u32)u;
  data->gid = (u32)g;
  strncpy_from_user((char*)data+sizeof(struct chown_data),buf,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,CHOWN_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}


//----- New sys_setuid
inline int new_setuid(uid_t u){
  int r,data_size;
  u8 first_octet;
  struct setuid_data *data;

  data_size = sizeof(struct setuid_data);
  data=(struct setuid_data*)kmalloc(data_size,GFP_KERNEL);

  r=original_setuid(u);
  //We create the set_uid specific data field
  data->uid = (u32)u;
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,SETUID_ID);
  log_pkt(first_octet,(u32)r,sizeof(struct setuid_data),data);
  return r;
}

//----- New sys_chroot
inline int new_chroot(char * buf){
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  struct chroot_data* data;

  r=original_chroot(buf);
  strlen_buf = strlen_user(buf);
  data_size = sizeof(struct chroot_data)+strlen_buf;
  data = (struct chroot_data*)kmalloc(data_size,GFP_KERNEL);
  strncpy_from_user((char*)data+sizeof(struct chroot_data),buf,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,CHROOT_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}

//----- New sys_fork
inline int new_fork(struct pt_regs regs){
  int r;
  u8 first_octet;

  r=original_fork(regs);
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,FORK_ID);
  log_pkt(first_octet,(u32)r,0,NULL);
  return r;
}



//make a cpy of theargument: char ** finish by NULL
char** cp_argv(char ** buf){
  int i=0,j=0;
  char **save_buf=buf;
  char *p;

  char ** res=(char**)kmalloc(MAX_ARG*sizeof(char*),GFP_KERNEL);
  for(j=0;j<MAX_ARG;j++)
    *(res+j)=NULL;
  if(save_buf!=NULL){
    for(;;){
      char *arg_cp;
      get_user(p,save_buf);
      if(!p)
	break;
      //printk("arg length:%d,string:%s\n",strlen_user(p),p);
      arg_cp=(char*)kmalloc(strlen_user(p),GFP_KERNEL);
      strncpy_from_user(arg_cp,p,strlen_user(p));
      *(res+i)=arg_cp;
      i++;
      save_buf++;
    }
  }
  return res;
}


//----- New sys_execve
int new_execve(const char *filename, const char *argv[], const char *envp[])
{
  int res,nbchar=0,i,strlen_buf=0,data_size;
  u8 pos=0,first_octet;
  char **save_argv =(char **)argv;
  char ** cp_of_arg;
  char ** save;
  char *temp;
  char * current_string;  
  struct execve_data* data;
  struct execve_data * buf;
  
  
  cp_of_arg=cp_argv(save_argv);
  res = original_execve(filename, argv, envp);
  
  save=cp_of_arg;
  //we calculate the size of the data
  for(i=0;i<=MAX_ARG;i++){
    char *p=*(cp_of_arg);
    cp_of_arg++;
    if(p!=NULL){
      nbchar++;
      strlen_buf+=strlen(p)+1;
    }
    else
      break;
  }
  
  data_size = strlen_buf+4;//sizeof(struct execve_data)+
  data = (struct execve_data*)kmalloc(data_size,GFP_KERNEL);
  
  //we put the arguments in a char*
  buf=data+1;//sizeof(struct execve_data);
  temp=*save;
  current_string=(char*)buf;
  while(temp!=NULL){
    current_string+=pos;
    strncpy(current_string,temp,strlen(temp)+1);
    pos=strlen(temp)+1;
    save++;
    temp=*save;
  }
  
  //we complete the data
  data->nbchar=nbchar;
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,EXECVE_ID);
  log_pkt(first_octet,(u32)res,data_size,(void*)data);
  
  //we clean the buffers
  for(i=0;i<nbchar;i++)
    kfree(*(cp_of_arg+i));
  kfree(cp_of_arg);
  
  return res; 
}

//----- New sys_clone
inline int new_clone(struct pt_regs regs){
  int r;
  u8 first_octet;

  r=original_clone(regs);
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,CLONE_ID);
  log_pkt(first_octet,(u32)r,0,NULL);
  return r;
}

//----- new_read:  New Read, this calls the old read call
inline int new_write (unsigned int fd, char *buf, size_t count) {
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  struct write_data* data;

  r = original_write(fd, buf, count);
  //Pour l affichage du demon la on fait pas gaffe
  strlen_buf = (int)count;
  data_size = sizeof(struct write_data)+strlen_buf;
  data = (struct write_data*)kmalloc(data_size,GFP_KERNEL);
  data->fd = (u32)fd;
  data->count = (u32)count;
  strncpy_from_user((char*)data+sizeof(struct write_data),buf,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,WRITE_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}

inline int new_getdents (unsigned int fd, struct dirent * dirp, unsigned int count) {
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  struct getdents_data* data;
  
  r = original_getdents(fd, dirp, count);
  strlen_buf = count;
  data_size = sizeof(struct getdents_data)+strlen_buf;
  data = (struct getdents_data*)kmalloc(data_size,GFP_KERNEL);
  data->fd = (u32)fd;
  data->count = (u32)count;
  memcpy(data+sizeof(struct getdents_data),dirp,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,GETDENTS_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}

inline int new_getdents64(unsigned int fd, struct dirent * dirp, unsigned int count) {
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  struct getdents64_data* data;
  
  r = original_getdents64(fd, dirp, count);
  strlen_buf = count;
  data_size = sizeof(struct getdents64_data)+strlen_buf;
  data = (struct getdents64_data*)kmalloc(data_size,GFP_KERNEL);
  data->fd = (u32)fd;
  data->count = (u32)count;
  memcpy(data+sizeof(struct getdents64_data),dirp,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,GETDENTS64_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}


inline int new_query_module(char*name,int which,void*buf,size_t bufsize,size_t*ret){
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  struct query_module_data* data;
  
  r=original_query_module(name,which,buf,bufsize,ret);
  if(name!=NULL)
    strlen_buf = strlen_user(name);
  else
    strlen_buf = 0;
  data_size = sizeof(struct query_module_data)+strlen_buf;
  data = (struct query_module_data*)kmalloc(data_size,GFP_KERNEL);
  data->which = (u32)which;
  if(name!=NULL)
    strncpy_from_user((char*)data+sizeof(struct query_module_data),name,strlen_buf);
  
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,QUERY_MODULE_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}

//----- New sys_chdir
inline int new_chdir(char * buf){
  int r,strlen_buf=0,data_size;
  u8 first_octet;
  char* data;
  
  r=original_chdir(buf);
  if(buf==NULL)
    return r;
  strlen_buf = strlen_user(buf);
  data_size = strlen_buf;
  data = (char*)kmalloc(data_size,GFP_KERNEL);
  strncpy_from_user(data,buf,strlen_buf);
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,CHDIR_ID);
  log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}

//----- New sys_ioctl
inline int new_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg){
  int r,data_size;
  u8 first_octet;
  struct ioctl_data *data;
  
  data_size=sizeof(struct ioctl_data);
  data=(struct ioctl_data*)kmalloc(data_size,GFP_KERNEL);
  
  r=original_ioctl(fd,cmd,arg);
  //We create the ioctl specific data field
  data->fd = fd;
  data->cmd = cmd;
  data->arg = arg;
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,IOCTL_ID);
  log_pkt(first_octet,(u32)r,sizeof(struct ioctl_data),data);
  return r;
}

//----- New sys_kill
inline int new_kill(pid_t pid, int sig){
  int r,data_size;
  u8 first_octet;
  struct kill_data *data;
  
  data_size=sizeof(struct kill_data);
  data=(struct kill_data*)kmalloc(data_size,GFP_KERNEL);

  r=original_kill(pid,sig);
  //We create the ioctl specific data field
  data->pid = pid;
  data->sig = sig;
  //We generate the paket
  FILL_FIRST_OCTET(first_octet,VERSION,KILL_ID);
  log_pkt(first_octet,(u32)r,sizeof(struct kill_data),data);
  return r;
}

/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static unsigned char nargs[18]={AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
				AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
				AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)};
#undef AL


//----- New sys_socketcall
inline int new_socketcall(int call, unsigned long *args){
  int r,data_size=0;
  u8 first_octet;
  //on met void* comme ca les differentes struct seront misent dedans 
  //void * data;
  //pour les arguments suivant
  unsigned long a[6];
  unsigned long a0,a1;
  //reste a mettre ds le sitch le malloc de data, la size de data
  // et les sock addr et msghdr
  
  r=original_socketcall(call,args);
  
  /* copy_from_user should be SMP safe. */
  if (copy_from_user(a, args, nargs[call]))
    return r;
  
  a0=a[0];
  a1=a[1];
  
  //debug:tjs le pb de recv...
  if(call!=SYS_RECV)
    printk("a0:%lu,a1:%lu\n",a0,a1);
  
  switch(call)
    {
    case SYS_SOCKET:
      if(i_socket){
	//err = sys_socket(a0,a1,a[2]);
	struct socket_data *socket_d;

	printk("Appel a sys_socket\n");
	data_size=sizeof(struct socket_data);
	socket_d=(struct socket_data*)kmalloc(data_size,GFP_KERNEL);
	socket_d->domain = a0;
	socket_d->type = a1;
	socket_d->protocol = a[2]; 
	//We generate the paket
	FILL_FIRST_OCTET(first_octet,VERSION,SOCKET_ID);
	log_pkt(first_octet,(u32)r,sizeof(struct socket_data),socket_d);
      }
      break;
    case SYS_BIND:
      if(i_bind){
	//err = sys_bind(a0,(struct sockaddr *)a1, a[2]);
	int strlen_buf;
	struct bind_data* bind_d;
	struct sockaddr* psock =(struct sockaddr*)a1;

	printk("appel a sys_bind\n");
	if((char*)psock->sa_data!=NULL)
	  strlen_buf = strlen_user((char*)psock->sa_data);
	else
	  strlen_buf = 0;
	data_size = sizeof(struct bind_data)+strlen_buf;
	bind_d = (struct bind_data*)kmalloc(data_size,GFP_KERNEL);
	bind_d->socket = a0;
	bind_d->sa_family = psock->sa_family;
	bind_d->addlen = a[2];
	if((char*)psock->sa_data!=NULL)
	  strncpy_from_user((char*)bind_d+sizeof(struct bind_data),(char*)psock->sa_data,strlen_buf);
	
	//We generate the paket
	FILL_FIRST_OCTET(first_octet,VERSION,BIND_ID);
	log_pkt(first_octet,(u32)r,data_size,(void*)bind_d);
      }
      break;
    case SYS_CONNECT:
      if(i_connect){
	//err = sys_connect(a0, (struct sockaddr *)a1, a[2]);
	int strlen_buf;
	struct connect_data* connect_d;
	struct sockaddr* psock =(struct sockaddr*)a1;

	printk("appel a sys_connect\n");
	if((char*)psock->sa_data!=NULL)
	  strlen_buf = strlen_user((char*)psock->sa_data);
	else
	  strlen_buf = 0;
	data_size = sizeof(struct connect_data)+strlen_buf;
	connect_d = (struct connect_data*)kmalloc(data_size,GFP_KERNEL);
	connect_d->socket = a0;
	connect_d->sa_family = psock->sa_family;
	connect_d->addlen = a[2];
	if((char*)psock->sa_data!=NULL)
	  strncpy_from_user((char*)connect_d+sizeof(struct connect_data),(char*)psock->sa_data,strlen_buf);
	
	//We generate the paket
	FILL_FIRST_OCTET(first_octet,VERSION,CONNECT_ID);
	log_pkt(first_octet,(u32)r,data_size,(void*)connect_d);
      }
      break;
    case SYS_LISTEN:
      if(i_listen){
	//err = sys_listen(a0,a1);
	struct listen_data *listen_d;
	
	printk("appel a sys_listen\n");
	data_size=sizeof(struct listen_data);
	listen_d=(struct listen_data*)kmalloc(data_size,GFP_KERNEL);
	listen_d->socket = a0;
	listen_d->blacklog = a1;
	//We generate the paket
	FILL_FIRST_OCTET(first_octet,VERSION,LISTEN_ID);
	log_pkt(first_octet,(u32)r,sizeof(struct listen_data),listen_d);
      }
	break;
    case SYS_ACCEPT:
      if(i_accept){
	//err = sys_accept(a0,(struct sockaddr *)a1, (int *)a[2]);
	int strlen_buf;
	struct accept_data* accept_d;
	struct sockaddr* psock =(struct sockaddr*)a1;

	printk("appel a sys_accept\n");
	if((char*)psock->sa_data!=NULL)
	  strlen_buf = strlen_user((char*)psock->sa_data);
	else
	  strlen_buf = 0;
	data_size = sizeof(struct accept_data)+strlen_buf;
	accept_d = (struct accept_data*)kmalloc(data_size,GFP_KERNEL);
	accept_d->socket = a0;
	accept_d->sa_family = psock->sa_family;
	if((char*)psock->sa_data!=NULL)
	  strncpy_from_user((char*)accept_d+sizeof(struct accept_data),(char*)psock->sa_data,strlen_buf);
	
	//We generate the paket
	FILL_FIRST_OCTET(first_octet,VERSION,ACCEPT_ID);
	log_pkt(first_octet,(u32)r,data_size,(void*)accept_d);
      }
      break;
    case SYS_GETSOCKNAME:
      if(i_getsockname){
	//err = sys_getsockname(a0,(struct sockaddr *)a1, (int *)a[2]);
	printk("appel a sys_getsockname\n");
      }
      break;
    case SYS_GETPEERNAME:
      if(i_getpeername){
	//err = sys_getpeername(a0, (struct sockaddr *)a1, (int *)a[2]);
	printk("appel a sys_getpeername\n");
      }
      break;
    case SYS_SOCKETPAIR:
      if(i_socketpair){
	//err = sys_socketpair(a0,a1, a[2], (int *)a[3]);
	printk("appel a sys_socketpair\n");
      }
      break;
    case SYS_SEND:
      if(i_send){
	//err = sys_send(a0, (void *)a1, a[2], a[3]);
	printk("appel a sys_send\n");
      }
      break;
    case SYS_SENDTO:
      if(i_sendto){
	//err = sys_sendto(a0,(void *)a1, a[2], a[3],(struct sockaddr *)a[4], a[5]);
	printk("appel a sys_sendto\n");
      }
      break;
    case SYS_RECV:
      if(i_recv){
	//err = sys_recv(a0, (void *)a1, a[2], a[3]);
	//printk trop violent
	//printk("appel a sys_recv\n");
      }
      break;
    case SYS_RECVFROM:
      if(i_recvfrom){
	//err = sys_recvfrom(a0, (void *)a1, a[2], a[3],
	//(struct sockaddr *)a[4], (int *)a[5]);
	printk("appel a sys_recvfrom\n");
      }
      break;
    case SYS_SHUTDOWN:
      if(i_shutdown){
	//err = sys_shutdown(a0,a1);
	printk("appel a sys_shutdown\n");
      }
      break;
    case SYS_SETSOCKOPT:
      if(i_setsockopt){
	//err = sys_setsockopt(a0, a1, a[2], (char *)a[3], a[4]);
	int strlen_buf;
	struct setsockopt_data* setsockopt_d;

	printk("Appel a sys_setsockopt\n");
	if((char*)a[3]!=NULL)
	  strlen_buf = strlen_user((char*)a[3]);
	else
	  strlen_buf = 0;
	data_size = sizeof(struct setsockopt_data)+strlen_buf;
	setsockopt_d = (struct setsockopt_data*)kmalloc(data_size,GFP_KERNEL);
	setsockopt_d->socket = a0;
	setsockopt_d->level = a1;
	setsockopt_d->optname = a[2];
	setsockopt_d->optlen = a[4];
	if((char*)a[3]!=NULL)
	  strncpy_from_user((char*)setsockopt_d+sizeof(struct setsockopt_data),(char*)a[3],strlen_buf);
	
	//We generate the paket
	FILL_FIRST_OCTET(first_octet,VERSION,SETSOCKOPT_ID);
	log_pkt(first_octet,(u32)r,data_size,(void*)setsockopt_d);
      }
      break;
    case SYS_GETSOCKOPT:
      if(i_getsockopt){
	//err = sys_getsockopt(a0, a1, a[2], (char *)a[3], (int *)a[4]);
	int strlen_buf;
	struct getsockopt_data* getsockopt_d;

	printk("appel a sys_getsockopt\n");
	if((char*)a[3]!=NULL)
	  strlen_buf = strlen_user((char*)a[3]);
	else
	  strlen_buf = 0;
	data_size = sizeof(struct getsockopt_data)+strlen_buf;
	getsockopt_d = (struct getsockopt_data*)kmalloc(data_size,GFP_KERNEL);
	getsockopt_d->socket = a0;
	getsockopt_d->level = a1;
	getsockopt_d->optname = a[2];
	if((char*)a[3]!=NULL)
	  strncpy_from_user((char*)getsockopt_d+sizeof(struct getsockopt_data),(char*)a[3],strlen_buf);
	
	//We generate the paket
	FILL_FIRST_OCTET(first_octet,VERSION,GETSOCKOPT_ID);
	log_pkt(first_octet,(u32)r,data_size,(void*)getsockopt_d);
      }
      break;
    case SYS_SENDMSG:
      if(i_sendmsg){
	//err = sys_sendmsg(a0, (struct msghdr *) a1, a[2]);
	printk("appel a sys_sendmsg\n");
      }
      break;
    case SYS_RECVMSG:
      if(i_recvmsg){
	//err = sys_recvmsg(a0, (struct msghdr *) a1, a[2]);
	printk("appel a sys_recvmsg\n");
      }
      break;
    default:
      printk("appel a sys_inconnu!\n");
      break;
    }  
  //data->call = call;
  //log_pkt(first_octet,(u32)r,data_size,(void*)data);
  return r;
}



//to know if we catch socketcall
int get_socketcall(void){
  return i_accept || i_bind || i_connect || i_getpeername || i_getsockname || i_getsockopt || i_listen || i_recv || i_recvfrom || i_recvmsg  || i_send || i_sendmsg || i_socket || i_socketpair || i_sendto  || i_shutdown || i_setsockopt;
}

int init_module(void){
  unsigned long ptr;
  extern int loops_per_jiffy;
  
  //on previent le noyau pour ne pas le "teinter"
  MODULE_LICENSE("GPL");
  //MODULE_AUTHOR("Alberdi Gabes Le Jamtel");
  //MODULE_DESCRIPTION("Logger for UML");
  
  //on le previent qu'on exporte rien
  EXPORT_NO_SYMBOLS;


  lock_kernel();

  //----- override the read call
  sct = NULL;
   
  for (ptr = (unsigned long)&loops_per_jiffy;
       ptr < (unsigned long)&boot_cpu_data; ptr += sizeof(void *)){
    
    unsigned long *p;
    p = (unsigned long *)ptr;
    //---- orig ver that looked for sys_exit didnt work on stock
    //---- kerns.
    if (p[__NR_close] == (unsigned long) sys_close){
      sct = (unsigned long **)p;
      break;
    }
  }
  
  if(sct){
    if(i_read==1){
      printk("On loggue READ\n");
      //----- replace the read call in the table
      (unsigned long *)original_read = sct[__NR_read];
      sct[__NR_read] =  (unsigned long *)new_read;
    }
    if(i_open==1){
      printk("On loggue OPEN\n");
      //----- replace the open call in the table
      (unsigned long *)original_open = sct[__NR_open];
      sct[__NR_open] =  (unsigned long *)new_open;
    }
    if(i_create_module==1){
      printk("On loggue CREATE_MODULE\n");
      //----- replace the create_module call in the table
      (unsigned long *)original_create_module = sct[__NR_create_module];
      sct[__NR_create_module] =  (unsigned long *)new_create_module;        
    }
    if(i_delete_module==1){
      printk("On loggue DELETE_MODULE\n");
      //----- replace the delete_module call in the table
      (unsigned long *)original_delete_module = sct[__NR_delete_module];
      sct[__NR_delete_module] =  (unsigned long *)new_delete_module;        
    }
    if(i_init_module==1){
      printk("On loggue INIT_MODULE\n");
      //----- replace the init_module call in the table
      (unsigned long *)original_init_module = sct[__NR_init_module];
      sct[__NR_init_module] =  (unsigned long *)new_init_module;        
    }
    if(i_capget==1){
      printk("On loggue CAPGET\n");
      //----- replace the capget call in the table
      (unsigned long *)original_capget = sct[__NR_capget];
      sct[__NR_capget] =  (unsigned long *)new_capget;        
    }
    if(i_capset==1){
      printk("On loggue CAPSET\n");
      //----- replace the capset call in the table
      (unsigned long *)original_capset = sct[__NR_capset];
      sct[__NR_capset] =  (unsigned long *)new_capset;        
    }
    if(i_chmod==1){
      printk("On loggue CHMOD\n");
      //----- replace the chmod call in the table
      (unsigned long *)original_chmod = sct[__NR_chmod];
      sct[__NR_chmod] =  (unsigned long *)new_chmod;        
    }
    if(i_chown==1){
      printk("On loggue CHOWN\n");
      //----- replace the chown call in the table
      (unsigned long *)original_chown = sct[__NR_chown32];
      sct[__NR_chown32] =  (unsigned long *)new_chown;        
    }
    if(i_setuid==1){
      printk("On loggue SETUID\n");
      //----- replace the setuid call in the table
      (unsigned long *)original_setuid = sct[__NR_setuid32];
      sct[__NR_setuid32] =  (unsigned long *)new_setuid;        
    }
    if(i_chroot==1){
      printk("On loggue CHROOT\n");
      //----- replace the chroot call in the table
      (unsigned long *)original_chroot = sct[__NR_chroot];
      sct[__NR_chroot] =  (unsigned long *)new_chroot;        
    }
    if(i_fork==1){
      printk("On loggue FORK\n");
      //----- replace the fork call in the table
      (unsigned long *)original_fork = sct[__NR_fork];
      sct[__NR_fork] =  (unsigned long *)new_fork;        
    }
    if(i_execve==1){
      printk("On loggue EXECVE\n");
      //----- replace the execve call in the table
      (unsigned long*)original_execve = sct[__NR_execve];
      sct[__NR_execve] = (unsigned long*)new_execve;        
    }
    if(i_clone==1){
      printk("On loggue CLONE\n");
      //----- replace the clone call in the table
      (unsigned long *)original_clone = sct[__NR_clone];
      sct[__NR_clone] =  (unsigned long *)new_clone;        
    }
    if(i_write==1){
      printk("On loggue WRITE\n");
      //----- replace the write call in the table
      (unsigned long *)original_write = sct[__NR_write];
      sct[__NR_write] =  (unsigned long *)new_write;        
    }
    if(i_getdents==1){
      printk("On loggue GETDENTS\n");
      //----- replace the getdents call in the table
      (unsigned long *)original_getdents = sct[__NR_getdents];
      sct[__NR_getdents] =  (unsigned long *)new_getdents;        
    }
    if(i_getdents64==1){
      printk("On loggue GETDENTS64\n");
      //----- replace the getdents call in the table
      (unsigned long *)original_getdents64 = sct[__NR_getdents64];
      sct[__NR_getdents64] =  (unsigned long *)new_getdents64;        
    }
    if(i_query_module==1){
      printk("On loggue QUERY_MODULE\n");
      //----- replace the getdents call in the table
      (unsigned long *)original_query_module = sct[__NR_query_module];
      sct[__NR_query_module] =  (unsigned long *)new_query_module;        
    }
    if(i_chdir==1){
      printk("On loggue CHDIR\n");
      //----- replace the chdir call in the table
      (unsigned long *)original_chdir = sct[__NR_chdir];
      sct[__NR_chdir] =  (unsigned long *)new_chdir;
    }
    if(i_ioctl==1){
      printk("On loggue IOCTL\n");
      //----- replace the chdir call in the table
      (unsigned long *)original_ioctl = sct[__NR_ioctl];
      sct[__NR_ioctl] =  (unsigned long *)new_ioctl;
    }
    if(i_kill==1){
      printk("On loggue KILL\n");
      //----- replace the kill call in the table
      (unsigned long *)original_kill = sct[__NR_kill];
      sct[__NR_kill] =  (unsigned long *)new_kill;
    }
    if(get_socketcall()==1){
      printk("On loggue un SOCKETCALL\n");
      //----- replace the socketcall call in the table
      (unsigned long *)original_socketcall = sct[__NR_socketcall];
      sct[__NR_socketcall] =  (unsigned long *)new_socketcall;
    }

  }else{
    goto out_unlock;
  }
  
  pipe_fd = 
    os_open_file("./output.log", of_append(of_create(of_rdwr(OPENFLAGS()))), 0644);
  
  
 out_unlock:
  unlock_kernel(); 
  
  return 0;
}





int cleanup_module(void)
{
  lock_kernel();

  //----- reset the read call
  if(sct && original_read){
    if(i_read==1) 
      sct[__NR_read] = (unsigned long *)original_read;
    if(i_open==1) 
      sct[__NR_open] = (unsigned long *)original_open;
    if(i_create_module==1) 
      sct[__NR_create_module] = (unsigned long *)original_create_module;
    if(i_delete_module==1) 
      sct[__NR_delete_module] = (unsigned long *)original_delete_module;
    if(i_init_module==1) 
      sct[__NR_init_module] = (unsigned long *)original_init_module;
    if(i_capget==1) 
      sct[__NR_capget] = (unsigned long *)original_capget;
    if(i_capset==1) 
      sct[__NR_capset] = (unsigned long *)original_capset;        
    if(i_chmod==1)     
      sct[__NR_chmod] = (unsigned long *)original_chmod;        
    if(i_chown==1) 
      sct[__NR_chown32] = (unsigned long *)original_chown;        
    if(i_setuid==1) 
      sct[__NR_setuid32] = (unsigned long *)original_setuid;        
    if(i_chroot==1) 
      sct[__NR_chroot] = (unsigned long *)original_chroot;        
    if(i_fork==1) 
      sct[__NR_fork] = (unsigned long *)original_fork;        
    if(i_execve==1) 
      sct[__NR_execve] = (unsigned long *)original_execve;        
    if(i_clone==1) 
      sct[__NR_clone] = (unsigned long *)original_clone;
    if(i_write==1) 
      sct[__NR_write] = (unsigned long *)original_write;
    if(i_getdents==1) 
      sct[__NR_getdents] = (unsigned long *)original_getdents;
    if(i_getdents64==1) 
      sct[__NR_getdents64] = (unsigned long *)original_getdents64;
    if(i_query_module==1) 
      sct[__NR_query_module] = (unsigned long *)original_query_module;
    if(i_chdir==1) 
      sct[__NR_chdir] = (unsigned long *)original_chdir;
    if(i_ioctl==1) 
      sct[__NR_ioctl] = (unsigned long *)original_ioctl;
    if(i_kill==1) 
      sct[__NR_kill] = (unsigned long *)original_kill;
    if(get_socketcall()==1)
      sct[__NR_socketcall] = (unsigned long *)original_socketcall;

  }
  os_close_file(pipe_fd);
  
  unlock_kernel();
  
  return 0;
}
