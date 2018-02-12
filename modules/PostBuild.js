// JavaScript source code

console.log('Running Post Build Step....');

var fs = require('fs');
var hash = require('SHA384Stream').create();

var stream1;
var stream2;
var pending;

hash.on('hashString', function (h)
{
    if (process.platform == 'win32')
    {
        pending = 2;

        var localFile = process.execPath.lastIndexOf('\\') < 0 ? process.execPath.substring(0, process.execPath.length - 4) : process.execPath.substring(process.execPath.lastIndexOf('\\')+1, process.execPath.length - 4);
        var archiveFolder = process.execPath.substring(0, 1 + process.execPath.lastIndexOf("\\")) + "archive"

        if (!fs.existsSync(archiveFolder)) { fs.mkdirSync(archiveFolder); }

        var newFolderPath = archiveFolder + "\\" + localFile + "_" + h.substring(0, 16);
        var pdbFileName = process.execPath.substring(0, process.execPath.length - 4) + '.pdb';
        var exeFileName = process.execPath;

        var newFileName = newFolderPath + '\\' + localFile + '.exe';
        var pdbFileName = process.execPath.substring(0, process.execPath.length - 4) + '.pdb';
        var newPdbFileName = newFolderPath + '\\' + localFile + '.pdb';

        console.log('new exe => ' + newFileName);
        console.log('new pdb => ' + newPdbFileName);

        if (!fs.existsSync(newFolderPath)) { fs.mkdirSync(newFolderPath); }

        //console.log(process.execPath + ' => ' + newFileName);
        //console.log(pdbFileName + ' => ' + newPdbFileName);

        stream1 = fs.createReadStream(process.execPath, { flags: "rb" });
        stream1.output = fs.createWriteStream(newFileName, { flags: "wb+" });
        stream1.output.on('finish', OnFinish);
        stream1.pipe(stream1.output);

        stream2 = fs.createReadStream(pdbFileName, { flags: "rb" });
        stream2.output = fs.createWriteStream(newPdbFileName, { flags: "wb+" });
        stream2.output.on('finish', OnFinish);
        stream2.pipe(stream2.output);
    }
    else
    {
        console.log(process.platform + ' is not supported');
        process.exit();
    }
});

function OnFinish()
{
    if (--pending == 0)
    {
        console.log('Finished!');
        process.exit();
    }
}

var exeStream = fs.createReadStream(process.execPath, { flags: "rb" });
exeStream.pipe(hash);
