/*
Copyright 2021 Intel Corporation
@author Bryan Roe

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



// Evaluates hostnames and returns true if hostnames match
function dnsDomainIs(target, host)
{
    if(!host.startsWith('.'))
    {
        host = '.' + host;
    }
    return (target.toLowerCase().endsWith(host.toLowerCase()));
}

// match hostname or URL to a specified shell expression,  returns true if matched
function shExpMatch(host, exp)
{
    exp = exp.split('.').join('\\.');
    exp = exp.split('?').join('.');
    exp = exp.split('*').join('.*');
    exp = '^' + exp + '$';
    return (host.search(exp) >= 0);
}

// evaluates the IP address of a hostname, and if within a specified subnet returns true
function isInNet(target, address, mask)
{
    try
    {
        var destAddr = resolve(target)._integers[0];
        var maskAddr = resolve(mask)._integers[0];
        return (_ipv4From(destAddr & maskAddr) == address);
    }
    catch(e)
    {
        return (false);
    }
}

// resolve host name to address
function dnsResolve(host)
{
    var result = resolve(host);
    if(result.length == 0)
    {
        return ('');
    }
    else
    {
        return (result[0]);
    }
}

// return true if the hostname contains no dots
function isPlainHostName(host)
{
    return (host.indexOf('.') < 0);
}

// evaluate hostname and return true IFF exact match
function localHostOrDomainIs(target, host)
{
    return (dnsResolve(target) == host);
}

// return true if resolve is successful
function isResolvable(host)
{
    return (resolve(host).length > 0);
}

// returns the number of DNS domain levels (number of dots) in the hostname
function dnsDomainLevels(host)
{
    return (host.split('.').length - 1);
}


function weekdayRange(start, end)
{

}
function dateRange(start, end)
{

}
function timeRange(start, end)
{

}

function alert(msg)
{

}
