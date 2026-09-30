/*
Copyright 2010 - 2011 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef LINUX_KVM_ROTATED_H_
#define LINUX_KVM_ROTATED_H_

#include <stdint.h>

typedef enum kvm_drm_rotation
{
	KVM_DRM_ROTATION_0 = 0,
	KVM_DRM_ROTATION_90 = 1,
	KVM_DRM_ROTATION_180 = 2,
	KVM_DRM_ROTATION_270 = 3
} kvm_drm_rotation;

const char *kvm_drm_rotation_name(kvm_drm_rotation rotation);
int kvm_drm_get_forced_rotation(kvm_drm_rotation *out_rotation, int log_enabled);
void kvm_drm_rotate_rgb24(const uint8_t *src, uint32_t src_width, uint32_t src_height, kvm_drm_rotation rotation, uint8_t *dst);

#endif
