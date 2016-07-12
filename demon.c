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


#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>

#define HEADER_SIZE 40

/*Used types*/
typedef char u8;
typedef long u32;
typedef unsigned short u16;

/*All the logged system calls*/
typedef enum{
  read_id,open_id,write_id,chmod_id,chown_id,setuid_id,chroot_id,
    create_module_id,init_module_id,delete_module_id,capset_id,
    capget_id,fork_id,execve_id,clone_id,getdents_id,getdents64_id,
    query_module_id,chdir_id,ioctl_id,kill_id,accept_id,bind_id,
    connect_id,getpeername_id,getsockname_id,getsockopt_id,listen_id,
    recv_id,recvfrom_id,recvmsg_id,send_id,sendmsg_id,socket_id,
    socketpair_id,sendto_id,shutdown_id,setsockopt_id
    } syscall_type;


/*Main header*/
struct uber_h{//attribute is used to disable the padding
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

/*Sub headers*/
struct chmod_data{
  u16 mode; /*unsigned short*/
};

struct capget_data{
  u32 target_pid;
};

struct capset_data{
  u32 target_pid;
  u32 effective_cap;
  u32 permitted_cap;
  u32 inheritable_cap;
};

struct chown_data{
  u32 uid;
  u32 gid;
};

struct setuid_data{
  u32 uid;
};

struct chroot_data{
};

struct open_data{
  u32 flags;
  u32 mode;
};

struct read_data{
  u32 fd;//unsigned int
  u32 count;
};

//no struct for delete_module

struct create_module_data{
  u32 size;//size_t
};

struct execve_data{
  u32 nbchar;
};

struct write_data{
  u32 fd;//unsigned int
  u32 count;
};

struct getdents_data{
  u32 fd;//unsigned int
  u32 count;
};

struct getdents64_data{
  u32 fd;//unsigned int
  u32 count;
};

struct query_module_data{
  u32 which;
};

//no struct for chdir

struct ioctl_data{
  u32 fd;
  u32 cmd;
  unsigned long arg;
};

struct kill_data{
  u32 pid;
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




void print_header(struct uber_h* header){
  printf("Header\n");
  printf("sec:%u,usec:%u,pid:%u,uid:%u\n,cap_effective:%u,cap_inheritable:%u,cap_permitted:%u,res:%d\n",
	 (unsigned int)header->time_sec,(unsigned int)header->time_usec,
	 (unsigned int)header->pid,(unsigned int)header->uid,
	 (unsigned int)header->cap_effective,(unsigned int)header->cap_inheritable,
	 (unsigned int)header->cap_permitted,
	 (int)header->res);
}


/**This function guarantess that size octet from the fd will be put
  *int the buf, unless a problem occured
  *Returns:
  * 1 if ok
  * -1 if a problem occured*/

int read_from(int fd,size_t size,void* buf){
  size_t  left_to_read = size;
  ssize_t read_number;
  //We read the under header
  while(left_to_read!=0){
    if ((read_number = read(fd,buf+size-left_to_read,
			    left_to_read))<0){
      perror("read:could not read the header from the pipe");
      return -1;
    }
    else{
      left_to_read -= (size_t)read_number;
    }
  }
  return 1;
}

#define GET_VERSION(v,header) (v = (int)(header.ver_and_num_appel & (0x3 << 6)))
#define GET_SYS_CALL(id,header) (id = (int)(header.ver_and_num_appel & (0x3F)))
#define SET_FDS(fdset,fd) \
 FD_ZERO(&fdset);\
 FD_SET(fd,&fdset);

int main(int argc, char* argv[]){
  
  struct uber_h current_header;
  size_t left_to_read;
  int pipe_fd,version,pkt_header_size = sizeof(struct uber_h);
  syscall_type sys_call;
  char* data;
  //struct timeval tv;
  int select_retval;
  fd_set rfds;
  
  
 
  
  //Test arguments
  if(argc !=2){
    printf("usage:%s pipe_path\n",argv[0]);
    return -1;
  }
  
  //TODO test with O_DIRECT
  //O_DIRECT vire la bufferisation, pour vide le pipe plus
  // vite c peut etre mieux, a teste
  if ((pipe_fd=open(argv[1],O_RDONLY | O_NDELAY))<0){
    perror("open: could not open the pipe");
    return -1;
  }
  
  
  while(1){
    //We recuperate the header
    //We set the rfds to the pipe fd
    SET_FDS(rfds,pipe_fd);
    
    select_retval = select(pipe_fd +1,&rfds,NULL,NULL,NULL);
    if (select_retval == -1)
      perror("select()");
    else
      {
	//We have data
	
	if (read_from(pipe_fd,(size_t)pkt_header_size,&current_header)==-1){
	  return -1;
	}
    
	//We create the necessary data field
	left_to_read = (size_t)current_header.length;
	//if(left_to_read !=0){
	if ((data = (char*)malloc((int)left_to_read))==NULL){
	  perror("malloc:could not allocate memory for the data");
	  printf("paket loosed");
	  return -1;
	}
	else{
	  //We recuperate the data field of the current paquet
	  if (read_from(pipe_fd,(size_t)current_header.length,data)==-1){
	    return -1;
	  }
	
	  GET_VERSION(version,current_header);
	  GET_SYS_CALL(sys_call,current_header);
	
	  switch(sys_call){
	  case chmod_id:
	    {
	      /*We have a chmod*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct chmod_data);
	      struct chmod_data *chmod_d = (struct chmod_data*)data;
	      char* file_string = (char*)data + size;
	    
	      printf("CHMOD\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("mode:%u,filename:%s\n",(unsigned int)chmod_d->mode,file_string);
	    }
	    break;
	
	  case chown_id:
	    {
	      /*We have a chown*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct chown_data);
	      struct chown_data *chown_d = (struct chown_data*)data;
	      char* file_string = (char*)data + size;
	    
	      printf("CHOWN\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("filename:%s,uid:%d,gid:%d\n",file_string,
		     (int)chown_d->uid,(int)chown_d->gid);
	    }
	    break;
	
	  case chroot_id:
	    {
	      /*We have a chroot*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct chroot_data);
	      char* file_string = (char*)data + size;
	    
	      printf("CHROOT\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("filename:%s\n",file_string);
	    }
	    break;
	
	  case setuid_id:
	    {
	      /*We have a capget*/
	      /*We interpret the correspondig data field*/
	      struct setuid_data *setuid_d = (struct setuid_data*)data;
	      printf("SETUID\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("target_pid:%d\n",(unsigned int)setuid_d->uid);
	    }
	    break;
	    
	  case capget_id:
	    {
	      /*We have a capget*/
	      /*We interpret the correspondig data field*/
	      struct capget_data *capget_d = (struct capget_data*)data;
	      printf("CAPGET\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("target_pid:%d\n",(unsigned int)capget_d->target_pid);
	    }
	    break;
	  	  
	  case capset_id:
	    {
	      /*We have a capget*/
	      /*We interpret the correspondig data field*/
	      struct capset_data *capset_d = (struct capset_data*)data;
	      printf("CAPSET\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("target_pid:%d,effective_cap:%u,permitted:%u,inheritable:%u\n",
		     (int)capset_d->target_pid,(unsigned int)capset_d->effective_cap,
		     (unsigned int)capset_d->permitted_cap,(unsigned int)capset_d->inheritable_cap);
	    }
	    break;
	  
	  case open_id:
	    {
	      /*We have a open*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct open_data);
	      struct open_data *open_d = (struct open_data*)data;
	      char* file_string = (char*)data + size;
	      int mode=open_d->mode;
	      int flags=open_d->flags;
	    
	      printf("OPEN\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("flags:%i,mode:%i,filename:%s\n",flags,mode,file_string);
	    }
	    break;
	  case read_id:
	    {
	      /*We have a read*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct read_data);
	      struct read_data *read_d = (struct read_data*)data;
	      char* file_string = (char*)data + size;
	      int fd=read_d->fd;
	      int count=read_d->count;
	    
	      printf("READ\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("fd:%i,count:%i,filename:%s\n",fd,count,file_string);
	    }
	    break;
	  case delete_module_id:
	    {
	      /*We have a delete_module*/
	      /*We interpret the correspondig data field*/
	      char* file_string = (char*)data;
	    
	      printf("DELETE_MODULE\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("filename:%s\n",file_string);
	    }
	    break;
	  case create_module_id:
	    {
	      /*We have a create_module*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct create_module_data);
	      struct create_module_data *create_module_d = (struct create_module_data*)data;
	      char* file_string = (char*)data + size;
	      int size_d=create_module_d->size;
	    
	      printf("CREATE_MODULE\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("size:%i,filename:%s\n",size_d,file_string);
	    }
	    break;
	  case execve_id:
	    {
	      /*We have a execve*/
	      /*We interpret the correspondig data field*/
	      printf("EXECVE\n");
	      print_header(&current_header);

	      printf("Sous_header\n");

	      struct execve_data* buffer= (struct execve_data*)data;
	      struct execve_data* buf=buffer+1;
	      //printf("Add:Data=%d\n",buffer);
	      //printf("Add:buf=%d\n",buf);
	      char * current_string=(char*)buf;//(char*) (data+sizeof(struct execve_data));
	      char pos=0;
	    
	      printf("NBChar=%d\n",(unsigned int)buffer->nbchar);
	    
	      int i=0;
	      printf("Argc=%d\n",(unsigned int)buffer->nbchar);
	      for(i=0;i<(unsigned int)buffer->nbchar;i++)
		{
		  current_string+=pos;
		  //printf("On lit sur:%d\n",current_string);
		  printf("Argv[%i]=String:%s\n",i,current_string);
		  pos=strlen(current_string)+1;
		}

	    }
	    break; 
	  case init_module_id:
	    {
	      /*We have a init_module*/
	      /*We interpret the correspondig data field*/
	      char* file_string = (char*)data;
	      int len = strlen(file_string);
	      char* name_string= (data+len+1);
	      printf("INIT_MODULE\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("filename:%s,name_module:%s\n",file_string,name_string);
	    }
	    break;
	  case fork_id:
	    {
	      /*We have a fork*/
	      /*We interpret the correspondig data field*/
	      printf("FORK\n");
	      print_header(&current_header);
	    }
	    break; 
	  case clone_id:
	    {
	      /*We have a clone*/
	      /*We interpret the correspondig data field*/
	      printf("CLONE\n");
	      print_header(&current_header);
	    }
	    break; 
	  case write_id:
	    {
	      /*We have a read*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct write_data);
	      struct write_data *write_d = (struct write_data*)data;
	      char* file_string = (char*)data + size;
	      int fd=write_d->fd;
	      int count=write_d->count;
	    
	      printf("WRITE\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("fd:%i,count:%i,buffer:%s\n",fd,count,file_string);
	    }
	    break;
	  case getdents_id:
	    {
	      /*We have a getdents*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct getdents_data);
	      struct getdents_data *getdents_d = (struct getdents_data*)data;
	      struct dirent *file_string = (struct dirent*)(data + size);
	      int fd=getdents_d->fd;
	      int count=getdents_d->count;
	      
	      printf("GETDENTS\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("fd:%i,count:%i,d_reclen:%d\n",fd,count,file_string->d_reclen);
	    }
	    break;
	  case getdents64_id:
	    {
	      /*We have a getdents64*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct getdents64_data);
	      struct getdents64_data *getdents_d = (struct getdents64_data*)data;
	      struct dirent *file_string = (struct dirent*)malloc(getdents_d->count);
	      int fd=getdents_d->fd;
	      int count=getdents_d->count;
	      
	      memcpy(file_string,(struct dirent*)(data + size),count);
	      
	      printf("GETDENTS64\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("fd:%i,count:%i,d_reclen:%d\n",fd,count,file_string->d_reclen);
	    }
	    break;
	  case query_module_id:
	    {
	      /*We have a query_module*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct query_module_data);
	      struct query_module_data *query_module_d = (struct query_module_data*)data;
	      char* file_string = (char*)data + size;
	      int which=query_module_d->which;
	      
	      printf("QUERY_MODULE\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("which:%i,buf:%s\n",which,file_string);
	    }
	    break;
	  case chdir_id:
	    {
	      /*We have a chdir*/
	      /*We interpret the correspondig data field*/
	      int size = 0;
	      char* file_string = (char*)data + size;
	      
	      printf("CHDIR\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("filename:%s\n",file_string);
	    }
	    break;
	  case ioctl_id:
	    {
	      /*We have a ioctl*/
	      /*We interpret the correspondig data field*/
	      struct ioctl_data *ioctl_d = (struct ioctl_data*)data;
	      int fd=ioctl_d->fd;
	      int cmd=ioctl_d->cmd;
	      int arg=ioctl_d->arg;
	      
	      printf("IOCTL\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("fd:%i,cmd:%i,arg:%i\n",fd,cmd,arg);
	    }
	    break;
	  case kill_id:
	    {
	      /*We have a kill*/
	      /*We interpret the correspondig data field*/
	      struct kill_data *kill_d = (struct kill_data*)data;
	      int pid=kill_d->pid;
	      int sig=kill_d->sig;
	      
	      printf("KILL\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("pid:%i,sig:%i\n",pid,sig);
	    }
	    break;
	  case socket_id:
	    {
	      /*We have a socket*/
	      /*We interpret the correspondig data field*/
	      struct socket_data *socket_d = (struct socket_data*)data;
	      int domain=socket_d->domain;
	      int type=socket_d->type;
	      int protocol=socket_d->protocol;
	      
	      printf("SOCKET\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("domain:%i,type:%i,protocol:%i\n",domain,type,protocol);
	    }
	    break;
	  case listen_id:
	    {
	      /*We have a listen*/
	      /*We interpret the correspondig data field*/
	      struct listen_data *listen_d = (struct listen_data*)data;
	      int socket=listen_d->socket;
	      int blacklog=listen_d->blacklog;
	      
	      printf("LISTEN\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("socket:%i,blacklog:%i\n",socket,blacklog);
	    }
	    break;
	  case setsockopt_id:
	    {
	      /*We have a setsockopt_module*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct setsockopt_data);
	      struct setsockopt_data *setsockopt_d = (struct setsockopt_data*)data;
	      char* file_string = (char*)data + size;
	      int socket=setsockopt_d->socket;
	      int level=setsockopt_d->level;
	      int optname=setsockopt_d->optname;
	      int optlen=setsockopt_d->optlen;
	      
	      printf("SETSOCKOPT\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("socket:%i,level:%i,optname:%i,optlen:%i,optval:%s\n",socket,level,optname,optlen,file_string);
	    }
	    break;
	  case getsockopt_id:
	    {
	      /*We have a getsockopt*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct getsockopt_data);
	      struct getsockopt_data *getsockopt_d = (struct getsockopt_data*)data;
	      char* file_string = (char*)data + size;
	      int socket=getsockopt_d->socket;
	      int level=getsockopt_d->level;
	      int optname=getsockopt_d->optname;
	      
	      printf("GETSOCKOPT\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("socket:%i,level:%i,optname:%i,optval:%s\n",socket,level,optname,file_string);
	    }
	    break;
	  case bind_id:
	    {
	      /*We have a bind*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct bind_data);
	      struct bind_data *bind_d = (struct bind_data*)data;
	      char* file_string = (char*)data + size;
	      int socket=bind_d->socket;
	      int sa_family=bind_d->sa_family;
	      int addlen=bind_d->addlen;
	      
	      printf("BIND\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("socket:%i,sa_family:%i,addlen:%i,sa_data:%s\n",socket,sa_family,addlen,file_string);
	    }
	    break;
	  case connect_id:
	    {
	      /*We have a connect*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct connect_data);
	      struct connect_data *connect_d = (struct connect_data*)data;
	      char* file_string = (char*)data + size;
	      int socket=connect_d->socket;
	      int sa_family=connect_d->sa_family;
	      int addlen=connect_d->addlen;
	      
	      printf("CONNECT\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("socket:%i,sa_family:%i,addlen:%i,sa_data:%s\n",socket,sa_family,addlen,file_string);
	    }
	    break;
	  case accept_id:
	    {
	      /*We have a accept*/
	      /*We interpret the correspondig data field*/
	      int size = sizeof(struct accept_data);
	      struct accept_data *accept_d = (struct accept_data*)data;
	      char* file_string = (char*)data + size;
	      int socket=accept_d->socket;
	      int sa_family=accept_d->sa_family;
	      
	      printf("ACCEPT\n");
	      print_header(&current_header);
	      printf("Sous_header\n");
	      printf("socket:%i,sa_family:%i,sa_data:%s\n",socket,sa_family,file_string);
	    }
	    break;

	  default:
	    break;
	  }  
	  //The paket was entirely recuperated
	  //We free the dynamically allocated data
	  free(data);
	}
	//}
	
	//else{
	//printf("pas de data");
	//}
      }
  }
  close(pipe_fd);
  return 1;
}
