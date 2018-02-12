/*
Copyright 2006 - 2018 Intel Corporation

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

#pragma once

typedef enum AgentPowerStateActions
{
	POWERSTATE_NOP = 0,
	POWERSTATE_LOGOFF = 1,
	POWERSTATE_SHUTDOWN = 2,
	POWERSTATE_REBOOT = 3,
	POWERSTATE_SLEEP = 4,
	POWERSTATE_HIBERNATE = 5,
	POWERSTATE_DISPLAYON = 6,
	POWERSTATE_KEEPAWAKE = 7,
	POWERSTATE_BEEP = 8,
	POWERSTATE_CTRLALTDEL = 9,
	POWERSTATE_VIBRATE = 13,
	POWERSTATE_FLASH = 14
} AgentPowerStateActions;

int MeshInfo_GetSystemInformation(char** data);
int MeshInfo_PowerState(AgentPowerStateActions flg, int force);
