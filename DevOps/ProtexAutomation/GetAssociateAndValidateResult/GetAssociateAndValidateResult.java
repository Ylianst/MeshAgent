
import java.util.List;
import java.io.PrintWriter;

import javax.xml.ws.soap.SOAPFaultException;

import com.blackducksoftware.sdk.codecenter.application.ApplicationApi;
import com.blackducksoftware.sdk.codecenter.application.data.Application;
import com.blackducksoftware.sdk.codecenter.application.data.ApplicationNameVersionOrIdToken;
import com.blackducksoftware.sdk.codecenter.application.data.ApplicationNameVersionToken;
import com.blackducksoftware.sdk.codecenter.client.util.BDSCodeCenterSample;
import com.blackducksoftware.sdk.codecenter.client.util.CodeCenterServerProxyV7_0;
import com.blackducksoftware.sdk.codecenter.cola.ColaApi;
import com.blackducksoftware.sdk.codecenter.cola.data.Component;
import com.blackducksoftware.sdk.codecenter.common.data.ApprovalStatusEnum;
import com.blackducksoftware.sdk.codecenter.request.RequestApi;
import com.blackducksoftware.sdk.codecenter.request.data.Request;
import com.blackducksoftware.sdk.codecenter.request.data.RequestColumn;
import com.blackducksoftware.sdk.codecenter.request.data.RequestPageFilter;
import com.blackducksoftware.sdk.codecenter.request.data.RequestSummary;

//////////////////////////////////////////////////////////////////////////////////////////////////////
//This sample file dis-associates any previous association with Protex project
//and associates with the Project passed in as argument and validates with project
//RETURNS 0 FOR SUCCESS AND 1 FOR FAILURE
//////////////////////////////////////////////////////////////////////////////////////////////////////

public class GetAssociateAndValidateResult extends BDSCodeCenterSample {

    private static ApplicationApi appApi = null;

    private static void usage() {
        System.out.println("Input Parameters:" );
        System.out.println("arg[0] - Code Center server URL");
        System.out.println("arg[1] - Code Center user ID");
        System.out.println("arg[2] - Password");
        System.out.println("arg[3] - Application Name");
        System.out.println("arg[4] - Output Path without filename");
    }
    
    
    /***************************************************************************************************
     * main()    
	 * @param args
	 * @throws Exception
	 **************************************************************************************************/
    public static void main(String[] args) throws Exception {
        // check and save parameters
        if (args.length < 5) {
            System.err.println("\n\nNot enough parameters!");
            usage();
            System.exit(1);
        }

        String serverUri = args[0];
        String username = args[1];
        String password = args[2];
        // Set the attachment Id
        String applicationName = args[3];
        String Path = args[4];
        String outFilePath = "";
        String ValidationStatus = "ERROR";
        String ApprovalStatus = "UNAPPROVED";
        RequestApi requestApi = null;
        ColaApi colaApi = null;  
        try {
            Long connectionTimeout = 120 * 1000L;
            CodeCenterServerProxyV7_0 myCodeCenterServer = new CodeCenterServerProxyV7_0(serverUri, username, password,
                                                                                             connectionTimeout);
            // Try some longer timeouts.
            // yes this is a blanket hack
            // revisit this later to see if timeouts can be reduced to normal.
            appApi =  myCodeCenterServer.getApplicationApi();
            appApi =  myCodeCenterServer.getApplicationApi( 0L ); //workaround from bd. call this twice and use infinite timeout
            requestApi = myCodeCenterServer.getRequestApi();
            colaApi = myCodeCenterServer.getColaApi();
        } catch (RuntimeException e) {
            System.err.println("\nConnection to server '" + serverUri + "' failed: " + e.getMessage());
            System.exit(1);
        }
        
        try {
            
            
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

            
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            //Read validation status
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////            
            ValidationStatus = thisapp.getValidationStatus().toString();
            /*if ( validateException || (! ValidationStatus.equals("PASSED")) ) {
                System.err.println("Validation status is " + ValidationStatus + " for app " + applicationName );
                ValidationStatus = "Unavailable";
            }*/
            
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            //Read Application Approval Status
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			List<RequestSummary> requestsList = null;
			String ptr_str = "";
        	RequestPageFilter pageFilter = new RequestPageFilter();
	        pageFilter.setFirstRowIndex(0);
	        pageFilter.setLastRowIndex(10);
	        pageFilter.setSortAscending(false);
	        pageFilter.setSortedColumn(RequestColumn.REQUEST_APPROVAL_STATUS);
	        pageFilter.getApprovalStatuses().add(ApprovalStatusEnum.APPROVED);
            try {
            	requestsList = appApi.searchApplicationRequests((ApplicationNameVersionOrIdToken)apptoken, "", pageFilter);
                		
            } catch (Exception e) {
                System.err.println("getApplicationRequests() failed while fetching the details of the request to be updated: "
                        + e.getMessage());
                System.exit(-1);
            }

            if (requestsList == null) {
                System.err.println("getApplicationRequests() failed: returned null as result");
                System.exit(-1);
            }	
            
            for (RequestSummary request : requestsList) {
            	Request thisreq = null;
            	Component thiscomp = null;
            	String Name = " ";
            	try {
                    thisreq = requestApi.getRequest(request.getId());
                } catch (Exception e) {
                    System.err.println("getRequest failed: "
                            + e.getMessage());
                    System.exit(-1);
                }//try....catch	
            	
            	try {
                    thiscomp = colaApi.getCatalogComponent(request.getComponentId());
                } catch (Exception e) {
                    System.err.println("getCatalogComponent() failed: "
                            + e.getMessage());
                    System.exit(-1);
                }//try....catch	
                
                try {
                    Name = thiscomp.getNameVersion().getName().trim();
                } catch (Exception e) {
                    System.err.println("Missing component data : Name, caught exception: "  + e.getMessage());
                }
            	
            	
            	if (Name.equals("IP Plan Approval")) {
            		try {
	                    ApprovalStatus = thisreq.getApprovalStatus().toString();
	                } catch (Exception e) {
	                    System.err.println("Failed to create request data: ApprovalStatus, caught exception: "  + e.getMessage());
	                }
            	}
            } //for (RequestSummary request : requestsList)
            
            
            
            
            
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// Write the application status in an xml file
			//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
            String OSName = null;
    		String delimiter = null;
    		OSName = System.getProperty("os.name");
    		if (OSName.contains("Windows")) delimiter = "\\";
    		else delimiter = "/";
            outFilePath = Path + delimiter + applicationName + "_CM.xml";
            PrintWriter outFile = null;
            
            try {
            	outFile = new PrintWriter(outFilePath);
            } catch (Exception e) {
                System.err.println("\nUnable to create output file writer : " + e.getMessage());
                System.exit(-1);
            }
            outFile.println("<ApplicationData>");
			outFile.println("<Application>" + applicationName + "</Application>");
			outFile.println("<ApprovedStatus>" + ApprovalStatus + "</ApprovedStatus>");
			outFile.println("<ValidationStatus>" + ValidationStatus + "</ValidationStatus>");
			outFile.println("</ApplicationData>");
			outFile.flush();
			outFile.close();
		
            
            System.exit(0);

        } catch (SOAPFaultException e) {
            System.err.println("GetCodeCenterApplication failed in main: " + e.getMessage());
            System.exit(1);
        }
    }
}



