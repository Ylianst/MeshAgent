/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ***   To edit the content of this header, modify the corresponding
 ***   source file (e.g. under external/kernel-headers/original/) then
 ***   run bionic/libc/kernel/tools/update_all.py
 ***
 ***   Any manual change here will be lost the next time this script will
 ***   be run. You've been warned!
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _LINUX_MEI_H
#define _LINUX_MEI_H
// #include <linux/types.h>
// #include <linux/string.h>
typedef struct {
          unsigned char b[16];
} uuid_le;
#define IOCTL_MEI_CONNECT_CLIENT   _IOWR('H' , 0x01, struct mei_connect_client_data)
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
struct mei_client {
 unsigned int max_msg_length;
 unsigned char protocol_version;
 unsigned char reserved[3];
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
};
struct mei_connect_client_data {
 union {
 uuid_le in_client_uuid;
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
 struct mei_client out_client_properties;
 };
};
#define IOCTL_MEI_SETUP_DMA_BUF _IOWR('H' , 0x02, struct mei_client_dma_data)
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
#define IOCTL_MEI_UNSET_DMA_BUF _IOW('H' , 0x03, struct mei_client_dma_handle)
struct mei_client_dma_data {
 union {
 unsigned long userptr;
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
 };
 unsigned int length;
 unsigned int handle;
};
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
struct mei_client_dma_handle {
 unsigned int handle;
};
#endif
/* WARNING: DO NOT EDIT, AUTO-GENERATED CODE - SEE TOP FOR INSTRUCTIONS */
