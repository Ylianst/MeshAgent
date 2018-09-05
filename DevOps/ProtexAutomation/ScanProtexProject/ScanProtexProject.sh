#!/bin/bash

if [ $# -ne 5 ]; then
  	echo "Arugument Missing"
	echo "Input Parameters:"
	echo "arg[1] - Protex server URL"
	echo "arg[2] - Protex user ID e.g abc@intel.com"
	echo "arg[3] - Password e.g abc"
	echo "arg[4] - Project ID e.g c_byt_beta_audio_6009"
	echo "arg[5] - Source Code location e.g /home/sourcefiles"
	exit
fi

# set environmental values to enable login to the Protex server

# Set the server URL
export BDSSERVER=$1

# Set the login name
export BDSUSER=$2

# Set the password
SET BDSPASSWORD=$3

pushd $5
bdstool login
bdstool new-project $4 --verbose 
bdstool analyze
bdstool logout
popd

exit
