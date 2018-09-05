ScanProtexProject.bat will take the user credentials, Protex server URL and project ID as input. The bat uses bdstool
to initiate the scan. After the 1st scan, rerun of this .bat file will only scan changes in code base will be scanned. 
If a forced scan is needed, then open the ScanProtexProject.bat in edit more, and update to below line
call bdstool analyze --force 

Prerequisite:
Protex client MUST be installed prior to executing the script

How to Execute:
Windows OS: 
1) Open a DOS Window
ScanProtexProject.bat <Protex server URL> <User ID> <User Password> <Project ID> <Scan Folder Path>

Linux OS
1) Open a bash windows
sh ScanProtexProject.sh <Protex server URL> <User ID> <User Password> <Project ID> <Scan Folder Path>
Input Parameters:
	        IN arg[0] - Protex server URL
	        IN arg[1] - User ID
	        IN arg[2] - Password
	        IN arg[3] - Protex project ID
	        IN arg[4] - Source files Path

Example:
ScanProtexProject.bat https://jfipscn01.intel.com abc@intel.com abc c_test_k_5271 c:\ScanSource
sh ScanProtexProject.sh https://jfipscn01.intel.com abc@intel.com abc c_test_k_5271 ~/ScanSource
================================================================================================================================
Protex Server ID				Protex Server URL
BA1						https://baipscn01.intel.com
GK1						https://gkipscn01.intel.com
IL1						https://iilipscn01.intel.com
JF1						https://jfipscn01.intel.com
JF2						https://jfipscn02.intel.com
JF03						https://jfipscn03.intel.com
JF04						https://jfipscn04.intel.com
JF05						https://jfipscn05.intel.com
JF06						https://jfipscn06.intel.com
NN01						https://nnsipscn01.intel.com
SC2						https://scipscn02.intel.com
SC3						https://scipscn03.intel.com
SH1						https://shipscn01.intel.com
MU01						https://imuipscn01.intel.com
