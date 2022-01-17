# MeshCentral Agent

## Table of Contents

[About](#about)  
[Social Media](#social-media)  
[MSH format](#msh-format)  
[Feedback](#feedback)  
[License](#license)
## About

The MeshCentral Agent is the software that runs on remote devices and connects to the MeshCentral server to allow for remote device management. This agent is compiled for Windows, many different Linux distributions, macOS and FreeBSD. In addition compiled for many different processors x86-32, x86-64, ARM, MIPS. For most users, install the MeshCentral server first and install the agent from your server.

To try out this software on the public server, please visit [MeshCentral.com/login](https://meshcentral.com/login). Be mindful that the public MeshCentral server comes with no guaranties, most should setup their own server.

For more information, [visit MeshCentral.com](https://www.meshcentral.com).

## Social Media
[Reddit](https://www.reddit.com/r/MeshCentral/)  
[Twitter](https://twitter.com/MeshCentral)  
[BlogSpot](https://meshcentral2.blogspot.com/)  

## MSH format
The MeshAgent gets it's security and connection instructions from a .msh text file formatted with each line being a "key=value". The .msh file is generally created by the MeshCentral server and, for example, would look like this:

```
MeshName=MyComputers
MeshType=2
MeshID=0xEDBE1BE...
ServerID=D99362D5...
MeshServer=wss://example.com:443/agent.ashx
```

Here is a list of the possible keys that are currently supported by the agent. Note that the key name must have the exact capitalization:

```
AgentCapabilities            Integer Mask, specifying supported Agent Capabilities	
agentName                    If set, this will be sent to the server instead of the hostname
compactDirtyMinimum          Minimum dirty bytes threshold for db.compact() operation
controlChannelDebug          If set, will log/display controlChannel messages (Except for JSON messages)
controlChannelIdleTimeout    Integer value specifying the idle timeout in seconds, to send Ping/Pong to server, to keep connection alive
coreDumpEnabled              If set, a dump file will be written when the agent crashes
disableUpdate                If set, will prevent the agent from self-updating
noUpdateCoreModule           If set, will prevent the agent from taking a new meshcore from the server
enableILibRemoteLogging      Integer value specifying the port number to enable Web Logging. Disabled otherwise
fakeUpdate                   If set, when the agent self-updates, it will update to the same version. Will set disableUpdate upon completion
forceUpdate                  If set, will cause the agent to perform a self-update on next start.
ignoreProxyFile              If set, will cause the agent to ignore any proxy settings
logUpdate                    If set, will cause the agent to log self-update status
jsDebugPort                  Specify a JS Debugger Port
nocertstore                  If set on Windows, will force the Agent to use OpenSSL instead of WinCrypto for cert generation/storage.
remoteMouseRender            If set, will always render the remote mouse cursor for KVM
skipmaccheck                 If set, the agent will not change NodeID on local mac address changes.
showModuleNames              If set, will display the name of modules when they are loaded for the first time
slaveKvmLog                  [Linux] If set, will enable logging inside the Child KVM Process.
WebProxy                     Manually specify proxy configuration
```

Many of these values are used by developers and are not typically used in normal use.

## Special notes for BSD systems
You'll need to mount procfs, which isn't mounted by default on FreeBSD. Add the following line to /etc/fstab
```
proc	/proc	procfs	rw	0	0
```
If you don't reboot, then you can manually mount with the command:
```
mount -t procfs proc /proc
```
In addition, it is recommended to install bash, which you can do with the following command:
```
pkg install bash
```

## Special Note about KVM Support on Linux: 
If you get an error stating that an Xauthority cannot be found, and asking if your DM is configured to use X, 
or if you get a black screen when connecting to the login screen, you may need to: 
* Open /etc/gdm/custom.conf or /etc/gdm3/custom.conf
* Uncomment: WaylandEnable=false.
* Add the following line to the [daemon] section:
```
DefaultSession=gnome-xorg.desktop
```

If you are using LightDM, and the child KVM process unexpectedly closes while connecting to the login screen,
you'll need to:
* Open /etc/lightdm/lightdm.conf
* Uncomment the following line from the [LightDM] section:
```
user-authority-in-system-dir=false
```


##	Special Note For ChromeOS:
You need to disable rootfs verification, in order to install the meshagent service.
After running the following commands, and rebooting, you should be able to install the meshagent service.
```
sudo su -
cd /usr/share/vboot/bin/
./make_dev_ssd.sh --remove_rootfs_verification
```
The above line will return a warning, but it will tell you the boot partition number, which you 
will need when specifying the above command again, this time with the --partions options. Specify the number instead of (ID)
```
./make_dev_ssd.sh --remove_rootfs_verification --partitions ID
reboot
```
When you are ready to install the agent, you'll need to copy the binary to a path that is not marked noexec, like /usr/local,
so that you can execute the installer from there.


## Feedback
If you encounter a problem or have a suggestion to improve the product, you may file an [issue report](https://github.com/Ylianst/MeshAgent/issues/)

If you are filing a problem report, you should include:
* The version of the software you are using
* The Operating System and version
* The observed output
* The expected output
* Any troubleshooting you took to resolve the issue yourself
* Any other similar reports

## License
This software is licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).