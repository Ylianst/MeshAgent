# Release Check List

## Abstract
This document goes thru a basic check list of tasks that should be done, to test the agent prior to releasing an agent update.

## Preparation
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