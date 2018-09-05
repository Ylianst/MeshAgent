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

#ifndef __ILIBDUKTAPE_NETWORKMONITOR__
#define __ILIBDUKTAPE_NETWORKMONITOR__

#include "duktape.h"

#ifdef __DOXY__
/*!
\brief NetworkMonitor emits events whenever the status of one of the network interfaces changes. <b>Note:</b> To use, must <b>require('NetworkMonitor')</b>
*/
class NetworkMonitor
{
public:
	/*!
	\brief 'change' event is emitted whenever any of the interfaces changes state
	*/
	void change;
	/*!
	\brief 'add' event is emitted when a new IPAddress is assigned to one of the network interfaces
	\param addr The IPAddress that was added or assigned
	*/
	void add;
	/*!
	\brief 'remove' event is emitted when an IPAddress is removed from one of the network interfaces
	\param addr The IPAddress that was removed.
	*/
	void remove;
};
#endif

void ILibDuktape_NetworkMonitor_Init(duk_context *ctx);

#endif
