
var fs = require('fs');
var exe;
var js;
var sz = new Buffer(8);
var exeLen = 0;

var i;
var dependency = [];
var addOn = null;
for (i = 1; i < process.argv.length; ++i)
{
    if(process.argv[i].startsWith('-i'))
    {
        try
        {
            dependency.push({ name:process.argv[i].slice(2,process.argv[i].indexOf('.js')), base64: fs.readFileSync(process.argv[i].slice(2)).toString('base64') });
            process._argv.splice(i, 1);
            i = 0;
        }
        catch(e)
        {
            console.log(e);
            process.exit();
        }
    }
}

if (dependency.length > 0)
{
    console.log("\nIntegrating Dependencies:")
    addOn = "";
    for(i=0;i<dependency.length;++i)
    {
        addOn += ("addModule('" + dependency[i].name + "', Buffer.from('" + dependency[i].base64 + "', 'base64'));\n");
        console.log("   " + dependency[i].name);
    }
    console.log("");
}

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

if (addOn != null) { js = Buffer.concat([Buffer.from(addOn), js]); }
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





