
var fs = require('fs');
var exe;
var js;
var sz = new Buffer(8);
var exeLen = 0;

if (process.argv0.endsWith('.js'))
{
    console.log("Non-integrated executable");
    if (process.argv.length < 4)
    {
        console.log("Too few parameters!");
        process.exit();
    }
    console.log("Executable Path: " + process.argv[1]);
    console.log("JavaScript Path: " + process.argv[3]);
    exe = fs.readFileSync(process.argv[1]);
    w = fs.createWriteStream(process.argv[2], { flags: "wb" });
    js = fs.readFileSync(process.argv[3]);
}
else
{
    console.log("Integrated executable");
    if (process.argv.length < 3)
    {
        console.log("Too few parameters!");
        process.exit();
    }
    console.log("Executable Path: " + process.argv[0]);
    console.log("JavaScript Path: " + process.argv[2]);
    exe = fs.readFileSync(process.argv[0]);
    w = fs.createWriteStream(process.argv[1], { flags: "wb" });
    js = fs.readFileSync(process.argv[2]);
}

if (exe.readInt32BE(exe.length - 4) == exe.length)
{
    console.log("Integrated JavaScript detected");
    exeLen = exe.length - exe.readInt32BE(exe.length - 8) - 8;
    console.log("Original Binary Size (Removed Integrated JavaScript): " + exeLen);
}
else
{
    console.log("No integrated JavaScript detected");
    exeLen = exe.length;
    console.log("Original Binary Size: " + exeLen);
}

console.log("JavaScript Length: " + js.length);
w.write(exe.slice(0, exeLen), OnWroteExe);

function OnWroteExe()
{
    this.write(js, function () {
        sz.writeInt32BE(js.length, 0);
        sz.writeInt32BE(exeLen + js.length + 8, 4);

        this.write(sz, function () {
            this.end();
            console.log("Finished!");
            process.exit();
        });
    });
}





