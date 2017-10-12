//var mesh = require('MeshAgent');
//var tmpBuffer = new Buffer(26);

//mesh.AddCommandHandler_Binary(OnBinaryCommand);
//htons(tmpBuffer, 0, 0x01);
//WriteContextGuid(tmpBuffer, 2, "THISISTHECONTEXT");
//htonl(tmpBuffer, 18, 0x40000000);
//htonl(tmpBuffer, 22, 0x00);
//mesh.InjectCommand(tmpBuffer);

//tmpBuffer = new Buffer(25);
//htons(tmpBuffer, 0, 0x10);
//WriteContextGuid(tmpBuffer, 2, "THISISTHECONTEXT");
//WriteString(tmpBuffer, 18, "bar();")
//mesh.InjectCommand(tmpBuffer);

//function WriteString(buffer, offset, val)
//{
//    var i;
//    for (i = 0; i < val.length; ++i)
//    {
//        buffer[offset + i] = val.charCodeAt(i);
//    }
//    buffer[offset + i] = 0;
//}
//function WriteContextGuid(buffer, offset, contextguid)
//{
//	var i;
//	for(i=0;i<16;++i)
//	{
//		if (i >= contextguid.length) {
//			buffer[offset + i] = 0;
//		}
//		else
//		{
//			buffer[offset + i] = contextguid.charCodeAt(i);
//		}
//	}
//}

//function OnBinaryCommand(cmd)
//{
//    var code = ntohs(cmd, 0);

//    if (code == 0x01)
//    {
//        var context = cmd.slice(2, 16).toString('utf-8');
//        var flags = ntohl(cmd, 18);
//        var etime = ntohl(cmd, 22);

//        if (code != 0xFF)
//        {
//            Microstack_print("Cmd: " + code.toString() + " Context: " + context + " Flags: " + flags.toString() + " ExecTimeout: " + etime.toString() + "\n");
//        }
//    }
//	return(0);
//}

var mesh = require('MeshAgent');
var container = mesh.CreateScriptContainer(0, ContainerPermissions.DEFAULT);


function OnExit(statusCode)
{
    Microstack_print("OnExit: " + statusCode.toString() + "\n");
}
function OnError(msg)
{
    Microstack_print("OnError: " + msg + "\n");
}


container.Exit = OnExit;
container.Error = OnError;
//container.ExecuteString("foo();");
container.ExecuteString("var agent = require('MeshAgent').db.Get(\"bryan\");", function (status, msg)
{
    Microstack_print("Completed First Execution\n");
    container.ExecuteString("foo();");
});

//container.ExecuteString("require('MeshAgent').db.Get(\"bryan\");");
//container.ExecuteString("var x = 2+2;");

