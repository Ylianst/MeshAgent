GenerateIPPlanReport.java extracts application metadata and BOM details from the Code Center application specified in input parameter 
and writes to a output file in HTML format. The output file created is with filename as "<Application Name> IP Plan.html"

How to Execute:
java -jar GenerateIPPlanReport.jar <Code Center Server URL> <User ID> <User Password> <Application Name> <Output Path>

Input Parameters:
	        IN arg[0] - Code Center server URL
	        IN arg[1] - Code Center user ID
	        IN arg[2] - Password
	        IN arg[3] - Application name
	        OUT arg[4] - Output Path (without filename)
Example:
Windows> java -jar GenerateIPPlanReport.jar http://sccodecenter.intel.com abc@intel.com abc "Android R4 AOSP Abi" "c:\IP Plans"
Linux> java -jar GenerateIPPlanReport.jar http://sccodecenter.intel.com abc@intel.com abc "Android R4 AOSP Abi" "/IP Plans"

Output:
Windows: c:\IP Plans\Android R4 AOSP Abi IP Plan.html
Linux: /IP Plans/Android R4 AOSP Abi IP Plan.html

