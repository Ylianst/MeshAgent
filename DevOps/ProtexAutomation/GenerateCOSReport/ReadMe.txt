GetCOSReport.java will generate Code Origination Scan (COS) report from the Protex project specified and writes to 
a output file in HTML and xls format

How to Execute:
java -jar GetCOSReport.jar <Protex server URL> <User ID> <User Password> <Project ID> <Output Path\Filename without extension>

Input Parameters:
	        IN arg[0] - Protex server URL
	        IN arg[1] - User ID
	        IN arg[2] - Password
	        IN arg[3] - Protex project ID
	        OUT arg[4] - Output Path\filename (without file extension)
Example:
java -jar GetCOSReport.jar http://jfipscn01.intel.com abc@intel.com abc MyTest_5271 c:\ScanResults\MyTest_COS

Output:
c:\ScanResults\MyTest_COS.html
c:\ScanResults\MyTest_COS.xls
