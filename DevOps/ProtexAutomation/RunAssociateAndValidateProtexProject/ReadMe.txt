RunAssociateAndValidateProtexProject.java will dis-associate the application from previously associated Protex project and 
re-associate the application to the project name passed as argument and execute validate. This script does the data integrity 
check between the application and Protex project

How to Execute:
java -jar RunAssociateAndValidateProtexProject.jar <Code Center server URL> <Code Center Username> <Password> <Code Center application> <Project Name> <Protex Server ID>

Input Parameters:
	        IN arg[0] - Code Center server URL
	        IN arg[1] - User ID
	        IN arg[2] - Password
	        IN arg[3] - Application (IP Plan) name
	        IN arg[4] - Protex Project name
		IN arg[5] - Protex Server ID

Example:
java -jar RunAssociateAndValidateProtexProject.jar http://sccodecenter.intel.com abc@intel.com abc "My App" "My Project" JF1

=======================================================================================================================

Protex Server ID						Protex Server URL
BA1								http://baipscn01.intel.com
GK1								http://gkipscn01.intel.com
HD1								http://hdipscn01.intel.com
IL1								http://iilipscn01.intel.com
JF1								http://jfipscn01.intel.com
JF2								http://jfipscn02.intel.com
JF03								http://jfipscn03.intel.com
NN01								http://nnsipscn01.intel.com
SC2								http://scipscn02.intel.com
SC3								http://scipscn03.intel.com
SH1								http://shipscn01.intel.com