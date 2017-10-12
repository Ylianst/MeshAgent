MicroLMS 0.0.7
--------------

This is an alternative "Local Management Service" (LMS) for Intel AMT. If provides the very basic function of relaying localhost port 16992 & 16993 to Intel AMT, but also offers a web server on port 16994 with a local version of Web Commander hosted there. To use:

  -run              Run LMS as a console application.
  -install          Install the service from this location.
  -uninstall        Remove the service from this location.
  start             Start the service.
  stop              Stop the service.

Once running, point a browser to

  http://localhost:16992    Access Intel AMT web UI, works if Intel AMT is activated.
  https://localhost:16993   Access Intel AMT web UI, works if Intel AMT is activated with TLS.
  http://localhost:16994    Access Web Commander, will display Intel AMT status even if not activated.

This is an early version of the code, it's released under Apache 2.0 open source license.

Enjoy!