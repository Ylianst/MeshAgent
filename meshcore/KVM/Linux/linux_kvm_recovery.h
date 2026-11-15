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

#ifndef LINUX_KVM_RECOVERY_H_
#define LINUX_KVM_RECOVERY_H_

#include <stdint.h>

/*
 * Records one unexpected capture-worker exit and returns the bounded delay before retrying.
 * A worker that survived healthy_runtime_ms resets the short-failure circuit breaker. The
 * counter saturates, allowing long-lived services to keep probing without integer overflow.
 */
uint32_t kvm_recovery_next_delay_ms(uint32_t *consecutive_failures,
	uint64_t worker_started_ms, uint64_t now_ms, uint32_t healthy_runtime_ms);

#endif
