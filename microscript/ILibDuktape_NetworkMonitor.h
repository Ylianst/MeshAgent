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