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
// This code sample/snippet illustrates how to hookup stdin, so that input can be read.
// In this particular case, we are using stdin to read a password
//


console.log('Starting Test...');

console.echo = false;       // This disables local echo to the console when keys are pressed
console.canonical = false;  // This takes the console out of canonical mode, which means stdin will process each key press individually, instead of by line.


// On first use of process.stdin, will cause the runtime to create a stream object, and hook it up so that it can be used to read from stdin, either by piping it, or by registering for events
process.stdin.chars = '';   // This is where we will store the result
process.stdin.on('data', function (c)
{
    switch(c[0])
    {
        case 127: // Linux Backspace
        case 8:   // Windows Backspace
            process.stdout.write('\r');
            for (i = 0; i < this.chars.length; ++i)
            {
                process.stdout.write(' ');  // Whenever BS is pressed, we need to clear the entire line, so we can redraw the '*' characters
                // The order is important. We must clear the entire line first, because when we redraw the '*', the cursor will
                // remain at that location, so if another key is pressed, the next '*' will be drawn there... If we only clear the removed '*',
                // the cursor will be left in the wrong position for when the next key is pressed.
            }
            process.stdout.write('\r');
            if (this.chars.length > 0) { this.chars = this.chars.substring(0,this.chars.length-1); } // On BS press, we will remove the last character we saved
            for (i = 0; i < this.chars.length; ++i)
            {
                process.stdout.write('*'); // Output a '*' to the console for each character that we have saved
            }
            break;
        case 10: // Linux CR
        case 13: // Windows CR
            console.log('\nPWD=' + this.chars); // When CR is pressed, we are done, and will simply dump what we saved to show what we captured
            process.exit();
            break;
        default:
            this.chars += c.toString();
            process.stdout.write('*');  // For each key press, we will output a '*' to the console
            break;
    }
});

process.on('exit', function ()
{
    // On POSIX, it is very important that we reset the console back to its normal/default settings... Otherwise, 
    // if we exit the app while the console is still set with echo and canonical disabled, it will remain in that state
    // making it difficult for the user to know whats going on when trying to interact with the console.
    console.echo = true;
    console.canonical = true;
});