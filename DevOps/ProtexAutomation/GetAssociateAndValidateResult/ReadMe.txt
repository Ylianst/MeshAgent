GetAssociateAndValidateResult.jar will read the Application's (passed in as argument) Validate and IP Approval status and writes the data into an 
output file in xml format. The file generated will be the same as application name with "_CM.xml" suffix.

How to Execute:
java -jar GetAssociateAndValidateResult.jar <Code Center server URL> <Code Center Username> <Password> <Code Center application> <output path>

Input Parameters:
	        IN arg[0] - Code Center server URL
	        IN arg[1] - User ID
	        IN arg[2] - Password
	        IN arg[3] - Application (IP Plan) name
	        OUT arg[4] - Output Path without filename

Example:
Windows> java -jar GetAssociateAndValidateResult.jar http://sccodecenter.intel.com abc@intel.com abc "My App" "C:\Results\CCXML"
Linux> java -jar GetAssociateAndValidateResult.jar http://sccodecenter.intel.com abc@intel.com abc "My App" "/Results/CCXML"

Output:
Windows: C:\Results\CCXML\My App_CM.xml
Linux: /Results/CCXML/My App_CM.xml