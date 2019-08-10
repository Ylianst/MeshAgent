

function gnome_getProxySettings(uid)
{
    var child = require('child_process').execFile('/bin/sh', ['sh'], { env: { HOME: require('user-sessions').getHomeFolder(uid) }});
    child.stderr.str = ''; child.stderr.on('data', function (c) { });
    child.stdout.str = ''; child.stdout.on('data', function (c) { this.str += c.toString(); });

    child.stdin.write('gsettings list-recursively org.gnome.system.proxy | tr "\\n" "\\|" | tr "\\\'" "\\`" | awk \'{ count=split($0, res, "|");')
    child.stdin.write('for(a=0;a<count;++a)');
    child.stdin.write('{');
    child.stdin.write('split(res[a], modecheck, " ");');
    child.stdin.write('if(modecheck[2] == "mode")');
    child.stdin.write('{');
    child.stdin.write('split(modecheck[3], prx, "`"); mode = prx[2];');
    child.stdin.write('}');
    child.stdin.write('if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="host") { split(modecheck[3], hst, "`"); host = hst[2]; }');
    child.stdin.write('if(modecheck[1]=="org.gnome.system.proxy.http" && modecheck[2]=="port") { port = modecheck[3]; }');
    child.stdin.write('}');
    child.stdin.write('printf "{\\"mode\\": \\"%s\\", \\"host\\": \\"%s\\", \\"port\\": %s}", mode, host, port; }\'\nexit\n');
    child.waitExit();
    
    try
    {
        return (JSON.parse(child.stdout.str.trim()));
    }
    catch(e)
    {
        return ({});
    }
}

switch(process.platform)
{
    case 'linux':
        module.exports = { getProxySettings: gnome_getProxySettings }
        break;
}