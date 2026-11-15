/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
int main(int argc,char **argv){
    if(argc!=3||!argv[1][0]||strcmp(argv[2],"c1"))return 9;
    if(getenv("MESHAGENT_PRIVATE_TEST")||!getenv("PATH")||strcmp(getenv("PATH"),"/usr/bin:/bin"))return 10;
    for(int i=0;i<3;++i){struct stat st;if(fstat(i,&st)||!S_ISCHR(st.st_mode)||major(st.st_rdev)!=1||minor(st.st_rdev)!=3)return 11;}
    DIR *dir=opendir("/proc/self/fd");if(!dir)return 12;struct dirent *entry;
    while((entry=readdir(dir))){int fd=atoi(entry->d_name);if(fd>2&&fd!=dirfd(dir)){closedir(dir);return 13;}}
    closedir(dir);int image=open("/proc/self/exe",O_RDONLY|O_CLOEXEC);if(image<0)return 14;
    int seals=fcntl(image,F_GET_SEALS);close(image);
    if((seals&(F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL))!=(F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL))return 15;
    return 2; /* A declined installer question; never requests logout. */
}
