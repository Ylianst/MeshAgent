/*
Copyright 2022 Intel Corporation
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


//
// This code snippet walks thru verious aspects of using service-manager.js to interace with a service.
// The service name used in these examples, are obtained from the command line. Pass it like the following:
//
// Windows =>       MeshService64 ..\snippets\service-manager-test.js "Mesh Agent"
// Linux   =>       ./meshagent_x86_64 snippets/service-manager-test.js meshagent
//
//

var serviceInstance = null;
var servicename = process.argv[1]; // In this snippet, we are going to use the service name that is passed in from the command line

console.log('Service Manager Test...');
console.log('Finding service: ' + servicename);

   
try
{
    serviceInstance = require('service-manager').manager.getService(servicename); // This returns a service object for the named service, if it is found. Otherwise an exception is thrown.
    //                                                ^^  
    //                                                This is the singleton manager instance that can be used to do most of the work
}
catch(x)
{
    // If getService() throws an exception, it's becuase the specified service could not be found on the platform service manager
    console.log('Unable to find service: ' + servicename);
    process.exit();
}


console.log('Service Location: ' + serviceInstance.appLocation());                  // This is the where the service binary is located
console.log('Service Working Path: ' + serviceInstance.appWorkingDirectory());      // This is the working path for the service
console.log('Start Type: ' + serviceInstance.startType);                            // This is the start type. Usually AUTO_START or DEMAND_START
console.log('Service Running: ' + serviceInstance.isRunning());

process.exit();
