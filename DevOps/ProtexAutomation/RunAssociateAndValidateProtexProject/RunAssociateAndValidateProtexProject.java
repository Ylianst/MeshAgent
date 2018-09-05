
import javax.xml.ws.soap.SOAPFaultException;

import com.blackducksoftware.sdk.codecenter.administration.data.ServerNameToken;
import com.blackducksoftware.sdk.codecenter.application.ApplicationApi;
import com.blackducksoftware.sdk.codecenter.application.data.Application;
import com.blackducksoftware.sdk.codecenter.application.data.ApplicationNameVersionToken;
import com.blackducksoftware.sdk.codecenter.application.data.ProjectNameToken;
import com.blackducksoftware.sdk.codecenter.client.util.BDSCodeCenterSample;
import com.blackducksoftware.sdk.codecenter.client.util.CodeCenterServerProxyV7_0;

//////////////////////////////////////////////////////////////////////////////////////////////////////
//This sample file dis-associates any previous association with Protex project
//and associates with the Project passed in as argument and validates with project
//RETURNS 0 FOR SUCCESS AND 1 FOR FAILURE
//////////////////////////////////////////////////////////////////////////////////////////////////////

public class RunAssociateAndValidateProtexProject extends BDSCodeCenterSample {

    private static ApplicationApi appApi = null;

    private static void usage() {
        System.out.println("Input Parameters:" );
        System.out.println("arg[0] - Code Center server URL");
        System.out.println("arg[1] - Code Center user ID");
        System.out.println("arg[2] - Password");
        System.out.println("arg[3] - Application Name");
        System.out.println("arg[4] - Protex Project Name");
        System.out.println("arg[5] - Protex Server ID (Readme file under RunAssociateAndValidateProject folder has all server ID details");
    }
    
    
    /***************************************************************************************************
     * main()    
	 * @param args
	 * @throws Exception
	 **************************************************************************************************/
    public static void main(String[] args) throws Exception {
        // check and save parameters
        if (args.length < 6) {
            System.err.println("\n\nNot enough parameters!");
            usage();
            System.exit(1);
        }

        String serverUri = args[0];
        String username = args[1];
        String password = args[2];
        // Set the attachment Id
        String applicationName = args[3];
        String projectName = args[4];
        String projectServer = args[5];
        
          
        try {
            Long connectionTimeout = 120 * 1000L;
            CodeCenterServerProxyV7_0 myCodeCenterServer = new CodeCenterServerProxyV7_0(serverUri, username, password,
                                                                                             connectionTimeout);
            // Try some longer timeouts.
            // yes this is a blanket hack
            // revisit this later to see if timeouts can be reduced to normal.
            appApi =  myCodeCenterServer.getApplicationApi();
            appApi =  myCodeCenterServer.getApplicationApi( 0L ); //workaround from bd. call this twice and use infinite timeout

        } catch (RuntimeException e) {
            System.err.println("\nConnection to server '" + serverUri + "' failed: " + e.getMessage());
            System.exit(1);
        }
        
        try {
            ServerNameToken protexServerToken = new ServerNameToken();
            ProjectNameToken protexProjectToken = new ProjectNameToken();
            try {
                protexServerToken.setName(projectServer);
                protexProjectToken.setServerId(protexServerToken);
                protexProjectToken.setName(projectName);
            } catch (Exception e) {
                System.err.println("Caught exception setting up Protex project token : " + e.getMessage());
                System.exit(1);
            }
            
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // get the application object
            //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            Application thisapp = null;
            ApplicationNameVersionToken apptoken = new ApplicationNameVersionToken();
            try {
                apptoken.setName(applicationName);
                apptoken.setVersion("Unspecified");
                thisapp = appApi.getApplication(apptoken);
            } catch (Exception e) {
            	try {
    				apptoken.setVersion("unspecified");
    				thisapp = appApi.getApplication(apptoken);
    			} catch (Exception e1) {
    				System.err.println("get APP " + applicationName + " caught exception : " + e1.getMessage());
    				System.exit(1);
    			}
            }
            if ( null == thisapp ) {
                System.err.println("FAILED: to get app for " + applicationName );
                System.exit(1);
            }

            //Disassociate current application project pair 
            try {
                appApi.disassociateProtexProject(apptoken);
            } catch (Exception e) {
                System.err.println("\ndisassociate() call in main() for application " + applicationName + " caught exception: " + e.getMessage());
            }
            //Associate application to new project  
            try {
                appApi.associateProtexProject(apptoken, protexProjectToken);
            } catch (Exception e) {
                System.err.println("\nassociate() call in main() for application " + applicationName + " caught exception: " + e.getMessage());
                System.exit(1);
            }

            //validate the Application Project pair
            String ValidationStatus = "ERROR";
            try {
                appApi.validate(apptoken, true, true);
                ValidationStatus = "PASSED";
            } catch (Exception e) {
                System.err.println("API exception: appApi.validate() for " + applicationName + " : " + e.getMessage());
                if ( -1 != e.getMessage().indexOf("not synchronized") ) {
                    ValidationStatus = "NotSynched";
                }
            }

            System.out.println(ValidationStatus);
            System.exit(0);

        } catch (SOAPFaultException e) {
            System.err.println("GetCodeCenterApplication failed in main: " + e.getMessage());
            System.exit(1);
        }
    }
}



