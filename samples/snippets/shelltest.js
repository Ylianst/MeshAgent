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
// This code snippet illustrates how to capture stdout from a child process
//

var child;
if (process.platform == 'win32')
{
    //                                                                             vvv   In this sample, we are simply going to spawn a command shell
    child = require('child_process').execFile(process.env['windir'] + '\\system32\\cmd.exe', ['/C dir']);
    //                                                                                         ^^^ This simply tells cmd.exe to to a dir, and then exit
    //                                                     ^^^  This gets the environment variable for the Windows Folder location
}
else
{
    child = require('child_process').execFile('/bin/ls', ['ls', '-la']);
    //                                         ^^^ On POSIX, we are simply just going to directly spawn 'ls'
}


child.stdout.str = ''; // Initialize an empty string, so we can append stdout to it
child.stdout.on('data', function (c) { this.str += c.toString(); }); // Just append to our stdout string

child.waitExit();  // This will wait until the child exits, allowing it to execute and run any event handlers

console.log(child.stdout.str);
process.exit();

