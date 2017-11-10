var child = require('child_process');
var childProcess = null;

if (process.platform == 'win32')
{
    childProcess = child.execFile(process.env['windir'] + '\\system32\\cmd.exe', ['/c', 'dir'], OnChild);
}
else if (process.platform == 'linux')
{
    childProcess = child.execFile('/bin/sh', ['sh', '-c', 'ls'], OnChild);
}

if (childProcess != null)
{
    console.log('PID = ' + childProcess.pid);
    childProcess.stdout.on('data', function (chunk) { console.log(chunk.toString()); });
    childProcess.on('exit', function (code, sig) { console.log("Process Exited with code: " + code.toString()); });
}
//for (var envkey in process.env)
//{
//    console.log("Environment Variable: [" + envkey + "] = " + process.env[envkey]);
//}

function OnChild(err, stdErr, stdOut)
{

}