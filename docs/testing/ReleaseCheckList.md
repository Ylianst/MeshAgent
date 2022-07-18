# Release Check List

## Abstract
This document goes thru a basic check list of tasks that should be done, to test the agent prior to releasing an agent update.


## Preparation

### Compiling the Agent
The first step in being able to compile the Mesh Agent, is to pull the MeshAgent repository from GIT. The repository contains the necessary solution and project files
to compile on Windows using Visual Studio, as well as a makefile to compile on Linux, BSD, and macOS.

On Windows, simply load the MeshAgent solution file, and build the MeshService project, using either Debug or Release, for x86 or x64.
For other platforms, refer to the [Makefile](https://github.com/Ylianst/MeshAgent/blob/master/makefile) which has detailed notes on how to compile for various different platforms.
As an example, to compile for Linux x86_64, you can run the following command:
```bash
make linux ARCHID=6 WEBLOG=1
```
or for macOS Apple Silicon and Intel Silicon with the following commands:
```bash
make macos ARCHID=29 WEBLOG=1
make macos ARCHID=16 WEBLOG=1
```

### Compiling OpenSSL
The Mesh Agent uses a statically linked OpenSSL library. If you need to compile OpenSSL on your own, use the following flags when compiling OpenSSL:

```bash
no-weak-ssl-ciphers no-srp no-psk no-comp no-zlib no-zlib-dynamic no-threads no-hw no-err no-dso no-shared -no-asm no-rc5 no-idea no-md4 no-rmd160 no-ssl no-ssl3 no-seed no-camellia no-dso no-bf no-cast no-md2 no-mdc2
```

A special note for macOS... When compiling OpenSSL for macOS for Intel Silicon, it is important that you modify the makefile after running **./Configure** to add the following
to the CFLAGS: **-mmacosx-version-min=10.5**. This will insure that the static library will be compatible with older macOS releases.

### Getting ready to test
1. Prior to testing the Mesh Agent release candidate, you should pull the latest MeshCentral from GIT, as we'll be needing to use some
things from MeshCentral for testing. This folder should be separate from your actual MeshCentral server, as it will be used as a Test Server.
2. After compiling the Mesh Agent, copy the two Windows Binaries (`MeshService64.exe and MeshService.exe`) from the `MeshAgent/Release` folder
to the `MeshCentral/agents` folder. When you start the server, it will sign the two binaries and place them in the `meshcentral-data/signedagents folder`
3. Build a test meshcmd, by running the following command, from the `MeshCentral/agents` folder, swapping the actual path for the modules folder:
```bash
MeshService64 "C:\GITHub\MeshAgent\modules\exe.js" -omeshcmd.exe -dC:\GITHub\MeshCentral\agents\modules_meshcmd
```

### Self Update Testing
1. Run update-test.js in native mode, CycleCount to 20, from the `meshcentral-data/signedagents` folder for Windows, and `MeshCentral/agents` folder for other platforms.
```bash
MeshService64 "C:\GITHub\MeshAgent\test\update-test.js" --CycleCount=20
./meshagent /home/GITHub/MeshAgent/test/update-test.js --CycleCount=20
```
2. Run update-test.js in JS mode, CycleCount to 20, from the `meshcentral-data/signedagents` folder for Windows, and `MeshCentral/agents` folder for other platforms.
```bash
MeshService64 "C:\GITHub\MeshAgent\test\update-test.js" --RecoveryCore="C:\GITHub\MeshCentral\agents" --JS --CycleCount=20
./meshagent /home/GITHub/MeshAgent/test/update-test.js --RecoveryCore="/home/GITHub/MeshCentral/agents" --JS --CycleCount=20
```

### Unit Tests
1. Run self-test.js. If any failures, re-run individual tests, to verify if is an actual failure, and not a fault of the test tool.
```bash
MeshService64 "C:\GITHub\MeshAgent\test\self-test.js" --AgentsFolder="C:\GITHub\MeshCentral\agents"
./meshagent /home/GITHub/MeshAgent/test/self-test.js --AgentsFolder="C:\GITHub\MeshCentral\agents"
```

### Manual Tests
After running the automated tests, it is a good idea to manually run a few additional tests to cover additional areas of the agent that may not have been covered by the automated tests

1. Download the agent from the test server, and install as if you are installing a new agent.
2. Once the agent connects to the server, navigate to the `console tab` and run the command `fdsnapshot` to get a baseline idea of what resources are consumed when idle.
3. Connect a KVM session, and verify that the user consent and profile images (on Windows) work correctly. Once connected, on Windows try to select different displays and verify that the display changes.
4. After disconnecting KVM, run the `fdsnapshot` command again, and verify that it matches the idle state capture from earlier.
5. Connect a root, and a user terminal session. Run `fdsnapshot` after closing the terminal session to verify resource release.
6. Connect a file session, and verify you can navigate to different folders. After closing, run the `fdsnapshot` command again to verify resource release.
7. From the `console tab` run the following command, to verify that the agent can restart itself:
```bash
service restart
```


### Manual AMT Tests

Using the meshcmd that we built previously, we can manually run some AMT tests on AMT capable platforms.

1. `meshcmd AmtInfo`. This will test mei functionality, and let you know the provisioning state of AMT.
2. `meshcmd AmtEventLog`. If you run this on an already provisioned AMT, it will test the WSMAN functionality to retrieve the AMT event log.