GetScanResult.java collects the scan analysis summary (# files scanned; # Pending identification; # Licencen conflicts; etc) 
of a protex Project passed is as argument. If the project is scanned, the analysis are written to the outfile passed in as 
argument. Else, throws an exception

How to Execute:
java -jar GetScanResult.jar <Protex server URL> <User ID> <User Password> <Project ID> <Output Path\Filename>

Input Parameters:
		IN arg[0] - Protex server URL
		IN arg[1] - the username for this server
		IN arg[2] - password
		IN arg[3] - Project ID
		OUT arg[4] - location of output xml file

Example:
java -jar GetScanResult.jar http://jfipscn01.intel.com abc@intel.com abc c_test_k_5271 c:\ScanResults\Project_Scan_result.xml

Output:
c:\ScanResults\Project_Scan_result.xml (Will contain scan result)

