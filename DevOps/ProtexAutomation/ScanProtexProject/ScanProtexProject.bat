@echo off
if "%1" == "" GOTO ENDFILE
if "%2" == "" GOTO ENDFILE 
if "%3" == "" GOTO ENDFILE 
if "%4" == "" GOTO ENDFILE  
if "%5" == "" GOTO ENDFILE 


Rem set environmental values to enable login to the Protex server


Rem Set the server URL
SET BDSSERVER=%1

Rem Set the login name
SET BDSUSER=%2

Rem Set the password
SET BDSPASSWORD=%3

pushd "%5"
call bdstool login
call bdstool new-project %4 --verbose 
call bdstool analyze
call bdstool logout
goto DONE

:ENDFILE
echo "Arugument Missing"
echo "Input Parameters:" );
echo "arg[1] - Protex server URL e.g http://scipscn03.intel.com");
echo "arg[2] - Protex user ID e.g abc@intel.com");
echo "arg[3] - Password e.g abc");
echo "arg[4] - Project ID e.g c_byt_beta_audio_6009");
echo "arg[5] - Source Code location e.g \"C:\\MySource\\ScanDir\"");

:DONE
popd