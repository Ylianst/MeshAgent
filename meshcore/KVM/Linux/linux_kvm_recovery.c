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

#include "linux_kvm_recovery.h"

#define KVM_RECOVERY_FAST_ATTEMPTS 5u
#define KVM_RECOVERY_MEDIUM_ATTEMPTS 10u
#define KVM_RECOVERY_FAST_DELAY_MS 1500u
#define KVM_RECOVERY_MEDIUM_DELAY_MS 10000u
#define KVM_RECOVERY_SLOW_DELAY_MS 30000u

uint32_t kvm_recovery_next_delay_ms(uint32_t *consecutive_failures,
	uint64_t worker_started_ms, uint64_t now_ms, uint32_t healthy_runtime_ms)
{
	uint32_t failures;

	if (consecutive_failures == 0) { return KVM_RECOVERY_SLOW_DELAY_MS; }
	if (worker_started_ms != 0 && now_ms >= worker_started_ms &&
		(now_ms - worker_started_ms) >= (uint64_t)healthy_runtime_ms)
	{
		*consecutive_failures = 0;
	}
	if (*consecutive_failures < UINT32_MAX) { ++(*consecutive_failures); }
	failures = *consecutive_failures;

	if (failures <= KVM_RECOVERY_FAST_ATTEMPTS) { return KVM_RECOVERY_FAST_DELAY_MS; }
	if (failures <= KVM_RECOVERY_MEDIUM_ATTEMPTS) { return KVM_RECOVERY_MEDIUM_DELAY_MS; }
	return KVM_RECOVERY_SLOW_DELAY_MS;
}
