/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "linux_gnome_assets.h"
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int passed,failed;
static void check(int value,const char *name)
{if(value)++passed;else{++failed;fprintf(stderr,"FAIL: %s\n",name);}}
static int file_equals(int parent,const char *path,const char *text)
{char data[64];int fd=openat(parent,path,O_RDONLY|O_NOFOLLOW);if(fd<0)return 0;ssize_t n=read(fd,data,sizeof(data));close(fd);return n==(ssize_t)strlen(text)&&!memcmp(data,text,(size_t)n);}
#include "linux-gnome-owner-rollback-cases.h"
int main(void)
{
 if(geteuid()!=0)return 2;
 char path[]="/tmp/meshagent-owner-rollback.XXXXXX";if(!mkdtemp(path))return 2;
 int parent=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);if(parent<0)return 2;
 mesh_gnome_asset a[3]={{(const unsigned char*)"metadata-a",10},{(const unsigned char*)"protocol-a",10},{(const unsigned char*)"extension-a",11}};
 mesh_gnome_asset b[3]={{(const unsigned char*)"metadata-b",10},{(const unsigned char*)"protocol-b",10},{(const unsigned char*)"extension-b",11}};
 owner_rollback_cases(parent,a,b);
 close(parent);check(!rmdir(path),"private rollback fixture cleaned");
 printf("%d focused rollback checks passed, %d failed\n",passed,failed);return failed?1:0;
}
