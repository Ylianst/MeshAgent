

import java.util.List;
import java.util.ListIterator;
import java.util.regex.Pattern;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

import com.blackducksoftware.sdk.codecenter.application.ApplicationApi;
import com.blackducksoftware.sdk.codecenter.application.data.Application;
import com.blackducksoftware.sdk.codecenter.application.data.ApplicationNameVersionOrIdToken;
import com.blackducksoftware.sdk.codecenter.application.data.ApplicationNameVersionToken;
import com.blackducksoftware.sdk.codecenter.cola.*;
import com.blackducksoftware.sdk.codecenter.cola.data.Component;
import com.blackducksoftware.sdk.codecenter.cola.data.LicenseNameOrIdToken;
import com.blackducksoftware.sdk.codecenter.cola.data.LicenseSummary;
import com.blackducksoftware.sdk.codecenter.attribute.AttributeApi;
import com.blackducksoftware.sdk.codecenter.attribute.data.AbstractAttribute;
import com.blackducksoftware.sdk.codecenter.attribute.data.AttributeNameOrIdToken;
import com.blackducksoftware.sdk.codecenter.client.util.BDSCodeCenterSample;
import com.blackducksoftware.sdk.codecenter.client.util.CodeCenterServerProxyV7_0;
import com.blackducksoftware.sdk.codecenter.common.data.ApprovalStatusEnum;
import com.blackducksoftware.sdk.codecenter.common.data.AttributeValue;
import com.blackducksoftware.sdk.codecenter.fault.SdkFault;
import com.blackducksoftware.sdk.codecenter.request.RequestApi;
import com.blackducksoftware.sdk.codecenter.request.data.*;



/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// This sample file extract application details, application metadata, BOMs, request for metadata and 
// each components metadata in BOM. It stores all the data in an HTML format into the file passed as argument
// The output file if the IP Plan of the application
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

public class GenerateIPPlanReport extends BDSCodeCenterSample {
	
	
	 private static void usage() {
	        
	        System.out.println("Input Parameters:" );
	        System.out.println("arg[0] - Code Center server URL");
	        System.out.println("arg[1] - Code Center user ID");
	        System.out.println("arg[2] - Password");
	        System.out.println("arg[3] - Application name");
	        System.out.println("arg[4] - Output Path");
	    }
	 
	 
	 /************************************************************************************
	  * GetComponentData: Get component and component request details for each component in BOM of the application
	  * @param thisapp
	  * @param applicationApi
	  * @param apptoken
	  * @param requestApi
	  * @param colaApi
	  * @param attributeApi
	  * @return String with data in html format
	  ************************************************************************************/
	public String GetComponentData(Application thisapp, ApplicationApi applicationApi, ApplicationNameVersionToken apptoken,
				RequestApi requestApi, ColaApi colaApi, AttributeApi attributeApi ) {

				
            	String ptr_str = "";
            	RequestPageFilter pageFilter = new RequestPageFilter();
   	            pageFilter.setFirstRowIndex(0);
   	            pageFilter.setLastRowIndex(2000);
   	            pageFilter.setSortAscending(false);
   	            pageFilter.setSortedColumn(RequestColumn.REQUEST_APPROVAL_STATUS);
   	            pageFilter.getApprovalStatuses().add(ApprovalStatusEnum.APPROVED);
				//get total number of Components in BOM
				List<RequestSummary> requestsList = null;
	            try {
	            	//requestsList = applicationApi.getApplicationRequests(apptoken);
	            	requestsList = applicationApi.searchApplicationRequests((ApplicationNameVersionOrIdToken)apptoken, "", pageFilter);
	                		
	            } catch (Exception e) {
	                System.err.println("getApplicationRequests() failed while fetching the details of the request to be updated: "
	                        + e.getMessage());
	                System.exit(-1);
	            }

	            if (requestsList == null) {
	                System.err.println("getApplicationRequests() failed: returned null as result");
	                System.exit(-1);
	            }	   
		        
	            System.out.println("# Requests: " + requestsList.size());
	            
	            
	            for (RequestSummary request : requestsList) {
	            	Component thiscomp = null;
	            	Request thisreq = null;
	            	String Name = " ";
					String Version = " ";
					String License = " ";
					String ReqLicense = " ";
					String ReqLicenseUsage = " ";
					String Description = " ";
					String Homepage = " ";
					String Supplier = " ";
					String SupplierCategory = " ";
					String SoftwareStackClassification = " ";
					String SoftwareTechnologyClassification = " ";
					String SpecificTechnologyClassification = " ";
					String OperatingSystem = " ";
					String OperatingSystemOther = " ";
					String ProgrammingLanguage = " ";
					String ProgrammingLanguageOther = " ";
					String DeliveryFormat = " ";
					String CopyrightOwnership = " ";
					String LicenseSource = " ";
					String LicenseLocation = " ";
					String AdditionalInformationAndComments = " ";
					String Comments = " ";
					String SourceLocation = " ";
					String SourceLocationSub = " ";
					String VersionRest = " ";
					String ApprovalStatus = " ";
					String LocationCntrl = " ";
					
					//////////////////////////////////////////////////////////////////////
					// Get the individual component request details like control string,
					// license source, etc....
					/////////////////////////////////////////////////////////////////////
	            	try {
                        thisreq = requestApi.getRequest(request.getId());
                    } catch (Exception e) {
                        System.err.println("getRequest failed: "
                                + e.getMessage());
                        System.exit(-1);
                    }//try....catch	
	            	
	            	List<AttributeValue> reqAttList = null;
	                try {
	                    ReqLicense = thisreq.getLicenseInfo().getNameToken().getName().trim().replaceAll(Pattern.quote("\r\n"), "\n").replaceAll(Pattern.quote("\r"), "\n");
	                } catch (Exception e) {
	                    //System.err.println("WARNING: empty Component Request License field");
	                }
	                try {
	                    ReqLicenseUsage = thisreq.getUsage().toString();
	                } catch (Exception e) {
	                    //System.err.println("WARNING: empty Component Request Usage field");
	                }
	                try {
	                    ApprovalStatus = thisreq.getApprovalStatus().toString();
	                } catch (Exception e) {
	                    //System.err.println("WARNING: empty Component Request Approval Status field");
	                }
	                try {
	                    reqAttList = thisreq.getAttributeValues();
	                } catch (Exception e) {
	                    //System.err.println("WARNING: empty Component Request Metadata Values field");
	                }
	                try {
	                    if ( null != reqAttList ) {
	                        if ( 0 < reqAttList.size() ) {
	                            //System.out.println("RequestAttList size is " + reqAttList.size());
	                            for (AttributeValue attValue : reqAttList) {
	                                AttributeNameOrIdToken attNameToken = attValue.getAttributeId();
	                                AbstractAttribute attribute = attributeApi.getAttribute(attNameToken);
	                                String attName = attribute.getName().trim();
	                                List<String> attStringList = attValue.getValues();

	                                if (null != attStringList) {
	                                    if ( 0 < attStringList.size() ) {
	                                        ListIterator<String> LI = attStringList.listIterator();
	                                        String attstring = LI.next().trim();
	                                        while ( LI.hasNext() ) {
	                                            attstring = attstring + "\n" + LI.next().trim();
	                                        }
	                                        attstring = attstring.replaceAll(Pattern.quote("\r\n"), "\n").replaceAll(Pattern.quote("\r"), "\n");
	                                        if ( attName.equals("CPR - Additional Information and Comments") ) {
	                                            AdditionalInformationAndComments = attstring.trim();
	                                        }
	                                        if ( attName.equals("CPR - License Location") ) {
	                                            LicenseLocation = attstring.trim();
	                                        }
	                                        if ( attName.equals("CPR - License Source") ) {
	                                            LicenseSource = attstring.trim();
	                                        }
	                                        if ( attName.equals("CPR - Location") ) {
	                                            SourceLocation = attstring.trim();
	                                            if ( SourceLocation.length() > 0 ) {
	                                                if ( SourceLocation.startsWith("/") ) {
	                                                    SourceLocation = SourceLocation.substring(1);
	                                                }
	                                                if ( SourceLocation.endsWith("/") ) {
	                                                    SourceLocation = SourceLocation.substring(0, (SourceLocation.length() - 1) );
	                                                }
	                                            }
	                                        }
	                                        if ( attName.equals("CPR - Location - Cntrl") ) {
	                                            LocationCntrl = attstring.trim();
	                                        }
	                                        if ( attName.equals("CPR - Location - Sub") ) {
	                                            SourceLocationSub = attstring.trim();
	                                            if ( SourceLocationSub.length() > 0 ) {
	                                                if ( SourceLocationSub.startsWith("/") ) {
	                                                    SourceLocationSub = SourceLocationSub.substring(1);
	                                                }
	                                                if ( SourceLocationSub.endsWith("/") ) {
	                                                    SourceLocationSub = SourceLocationSub.substring(0, (SourceLocationSub.length() - 1) );
	                                                }
	                                            }
	                                        }
	                                        if ( attName.equals("CPR - Versions") ) {
	                                            VersionRest = attstring.trim();
	                                        }
	                                    }
	                                }
	                            }
	                        }
	                    }
	                } catch (Exception e) {
	                    System.err.println("Failed to create component request data, caught exception: "  + e.getMessage());
	                }
	            	
	            	
	            	
	            	//////////////////////////////////////////////////////////////////////
	            	// Get the individual component details
	            	/////////////////////////////////////////////////////////////////////
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
                        System.err.println("WARNING: empty Component Name field");
                    }
                    try {
                        Version = thiscomp.getNameVersion().getVersion().trim();
                    } catch (Exception e) {
                        System.err.println("WARNING: empty Component Version field");
                    }
                    try {
                        Description  = thiscomp.getDescription().trim();
                    } catch (Exception e) {
                        System.err.println("WARNING: empty Component Description field");
                    }
                    try {
                        Homepage  = thiscomp.getHomepage().trim();
                    } catch (Exception e) {
                        System.err.println("WARNING: empty Component Homepage field");
                    }
                    
                    try {
                        //License = thiscomp.getLicenseInfo().getNameToken().getName().trim().replaceAll(Pattern.quote("\r\n"), "\n").replaceAll(Pattern.quote("\r"), "\n");
                        License = thiscomp.getDeclaredLicenses().get(0).getNameToken().getName().trim().replaceAll(Pattern.quote("\r\n"), "\n").replaceAll(Pattern.quote("\r"), "\n");
                    } catch (Exception e) {
                        System.err.println("WARNING: empty Component Declared License field");
                    }
                    List<AttributeValue> compAttList = null;
                    try {
                        compAttList = thiscomp.getAttributeValues();
                    } catch (Exception e) {
                        System.err.println("WARNING: empty Component Attribute Values field");
                    }
                    
                    //////////////////////////////////////////////////////////////////////
                    // Read the attributes of the component
                    //////////////////////////////////////////////////////////////////////
                    if ( null != compAttList ) {
                        if ( 0 < compAttList.size() ) {
                            for (AttributeValue attValue : compAttList) {
                            	                        	
                                AttributeNameOrIdToken attNameToken = attValue.getAttributeId();
                                AbstractAttribute attribute = null;
								try {
									attribute = attributeApi.getAttribute(attNameToken);
								} catch (SdkFault e) {
									System.err.println("WARNING: empty Component Attributes field");
								}
                                String attName = attribute.getName().trim();
 
                                List<String> attStringList = attValue.getValues();
                                if (null != attStringList) {
                                    if ( 0 < attStringList.size() ) {
                                        ListIterator<String> LI = attStringList.listIterator();
                                        String attstring = LI.next().trim();
                                        while ( LI.hasNext() ) {
                                            attstring = attstring + "\n\n\n" + LI.next().trim();
                                        }
                                        attstring = attstring.replaceAll(Pattern.quote("\r\n"), "\n").replaceAll(Pattern.quote("\r"), "\n");
                                        if ( attName.equals("APP/CPC - SW Stack Classification") ) {
                                        	SoftwareStackClassification = attstring.trim();
                                        }
                                        if ( attName.equals("APP/CPC - SW Technology Classification") ) {
                                        	SoftwareTechnologyClassification = attstring.trim();
                                        }
                                        if ( attName.equals("APP/CPC - SW Technology Classification - Other") ) {
                                        	SpecificTechnologyClassification = attstring.trim();
                                        }
                                        if ( attName.equals("CPC - Copyright Ownership") ) {
                                            CopyrightOwnership = attstring.trim();
                                        }
                                        if ( attName.equals("CPC - Distribution Type") ) {
                                            DeliveryFormat = attstring.trim();
                                        }
                                        if ( attName.equals("CPC - Operating System") ) {
                                            OperatingSystem = attstring.trim();
                                        }
                                        if ( attName.equals("CPC - Operating System - Other") ) {
                                            OperatingSystemOther = attstring.trim();
                                        }
                                        if ( attName.equals("CPC - Programming Language") ) {
                                            ProgrammingLanguage = attstring.trim();
                                        }
                                        if ( attName.equals("CPC - Programming Language - Other") ) {
                                            ProgrammingLanguageOther = attstring.trim();
                                        }
                                        if ( attName.equals("CPC -     Software Supplier Category") ) {
                                        	SupplierCategory = attstring.trim();
                                        }
                                        if ( attName.equals("CPC - Supplier Name") ) {
                                        	Supplier = attstring.trim();
                                        }
                                                                               
                                    }//if attstringlist
                                    
                            } //if attstringlist
                        } //For each compattlist
                    } //if compAttsize
                        ptr_str = ptr_str + "<tr><td style='text-align: center;'>" + Name + "</td>"
    		            		+ "<td style='text-align: center;'>" + Version + "</td>"
    		            		+ "<td style='text-align: center;'>" + License + "</td>"                			           		
    		            		+ "<td style='text-align: center;'>" + Description + "</td>" 
    		            		+ "<td style='text-align: center;'>" + Homepage + "</td>"
    		            		+ "<td style='text-align: center;'>" + Supplier + "</td>"
    		            		+ "<td style='text-align: center;'>" + SupplierCategory + "</td>"
    		            		+ "<td style='text-align: center;'>" + SoftwareStackClassification + "</td>"
    		            		+ "<td style='text-align: center;'>" + SoftwareTechnologyClassification + "</td>"
    		            		+ "<td style='text-align: center;'>" + SpecificTechnologyClassification + "</td>"
    		            		+ "<td style='text-align: center;'>" + OperatingSystem + "</td>"
    		            		+ "<td style='text-align: center;'>" + ProgrammingLanguage + "</td>"
    		            		+ "<td style='text-align: center;'>" + DeliveryFormat + "</td>"
    		            		+ "<td style='text-align: center;'>" + CopyrightOwnership + "</td>"
    		            		+ "<td style='text-align: center;'>" + ReqLicense + "</td>"
    		            		+ "<td style='text-align: center;'>" + ReqLicenseUsage + "</td>"
    		            		+ "<td style='text-align: center;'>" + SourceLocation + "</td>"
    		            		+ "<td style='text-align: center;'>" + SourceLocationSub + "</td>"
    		            		+ "<td style='text-align: center;'>" + LocationCntrl + "</td>"
    		            		+ "<td style='text-align: center;'>" + LicenseLocation + "</td>"
    		            		+ "<td style='text-align: center;'>" + LicenseSource + "</td>"
    		            		+ "<td style='text-align: center;'>" + AdditionalInformationAndComments + "</td>"
    		            		+ "<td style='text-align: center;'>" + VersionRest + "</td>"
    		            		
    		            		+ "</tr>";
                    } // compattlist = null
	            } //for RequestSummary request
		        
		         return ptr_str;   
		        
	};
		    
	
	/*********************************************************************************************
	 * GetApplicationData() Get Application's details and Metadata
	 * @param thisapp
	 * @param attributeApi
	 * @param colaApi
	 * @return String with data in html format
	 *********************************************************************************************/
	public String GetApplicationData(Application thisapp, AttributeApi attributeApi, ColaApi colaApi) {
		
		       String Name = null;
		       String Version = null;
		       String ProgramPlatform = null;
		       String  ProductName = null;
		       String Description = null;
		       String IdentificationsProductName = null;
		       String SubGroupName = null;
		       String  GroupName = null;
		       String OutboundLicense = null;
		       String OBLInstructions = null;
		       String License = null;
		       String  LicenseAcceptance = null;
		       String InformationClassification = null;
		       String ExportECCN = null;
		       String Standards = null;
		       String StandardsMember = null;
		       String StandardsList = null;
		       String Indemnification = null;
		       String IndemnificationGMApprover = null;
		       String Warranty = null;
		       String WarrantyDataSheet = null;
		       String SoftwareStackClassification = null;
		       String SoftwareTechnologyClassification = null;
		       String SoftwareTechnologyClassificationOther = null;
		       //String ThirdPartyPatents = null;
		       String IntelPatents = null;
		       String IntelPatentStatus = null;
		       String OpenSource = null;
		       String ptr_str = "";
		
		       
		        List<AttributeValue> appAttList = null;
		        try {
		            try {
		                Name = thisapp.getName();
		            } catch (Exception e) {
		                System.err.println("Missing application data: Name, caught exception: "  + e.getMessage());
		            }
		            try {
		                Version = thisapp.getVersion();
		            } catch (Exception e) {
		                System.err.println("Missing application data: Version, caught exception: "  + e.getMessage());
		            }
		            LicenseNameOrIdToken LicenseToken = null;
		            try {
		                LicenseToken = thisapp.getLicenseId();
		                } catch (Exception e) {
		                System.err.println("Missing application data: LicenseToken, caught exception: "  + e.getMessage());
		            }
		            if ( LicenseToken != null ) {
		                try {
		                    License = colaApi.getLicense(LicenseToken).getNameToken().getName();
		                } catch (Exception e) {
		                    System.err.println("Missing application data: LicenseToken, caught exception: "  + e.getMessage());
		                }
		            }

		            try {
		                Description = thisapp.getDescription().trim().replaceAll(Pattern.quote("\r\n"), "\u0001").replaceAll(Pattern.quote("\r"), "\u0001").replaceAll(Pattern.quote("\n"), "\u0001");
		            } catch (Exception e) {
		                System.err.println("Missing application data: Description, caught exception: "  + e.getMessage());
		            }
		            try {
		                appAttList = thisapp.getAttributeValues();
		            } catch (Exception e) {
		                System.err.println("Missing application data: attributeValues, caught exception: "  + e.getMessage());
		            }
		            
		            ///////////////////////////////////////////////////////////////////////////////
		            // get application metadata
		            //////////////////////////////////////////////////////////////////////////////
		            if ( null != appAttList ) {
		                if ( 0 < appAttList.size() ) {
		                    for (AttributeValue attValue : appAttList) {
		                        AttributeNameOrIdToken attNameToken = attValue.getAttributeId();
		                        AbstractAttribute attribute = attributeApi.getAttribute(attNameToken);
		                        String attName = attribute.getName().trim();
		                        List<String> attStringList = attValue.getValues();
		                        if (null != attStringList) {
		                            if ( 0 < attStringList.size() ) {
		                                ListIterator<String> LI = attStringList.listIterator();
		                                String attstring = LI.next().trim();
		                                while ( LI.hasNext() ) {
		                                    attstring = attstring + "\n\n\n" + LI.next().trim();
		                                }
		       
		                                attstring = attstring.replaceAll(Pattern.quote("\r\n"), "\n").replaceAll(Pattern.quote("\r"), "\n");
		                                if ( attName.equals("APP - Identifications - Program and Platforms")) {
		                                	ProgramPlatform = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Identifications - Product Name")) {
		                                	ProductName = attstring.trim();
		                                }
		                                //if ( attName.equals("APP - 3rd Party Patents")) {
		                                    //ThirdPartyPatents = attstring.trim();
		                                //}
		                                if ( attName.equals("APP - Export - ECCN")) {
		                                    ExportECCN = attstring.trim();
		                                }
		                                if ( attName.startsWith("APP - Super Group")) {
		                                    GroupName = attstring.trim();
		                                }
		                                if ( attName.startsWith("APP - Group - IAG")) {
		                                    SubGroupName = attstring.trim();
		                                }
		                                if ( attName.startsWith("APP - Group - SMG")) {
		                                    SubGroupName = attstring.trim();
		                                }
		                                if ( attName.startsWith("APP - Group - SSG")) {
		                                    SubGroupName = attstring.trim();
		                                }
		                                if ( attName.startsWith("APP - Group - TMG")) {
		                                    SubGroupName = attstring.trim();
		                                }
		                                if ( attName.startsWith("APP - Group - Intel Labs")) {
		                                    SubGroupName = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Identifications - Product Name")) {
		                                    IdentificationsProductName = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Indemnification")) {
		                                    Indemnification = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Indemnification - GM Approval")) {
		                                	IndemnificationGMApprover = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Information Classification")) {
		                                    InformationClassification = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Intel Patents")) {
		                                    IntelPatents = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Intel Patents - Status")) {
		                                	IntelPatentStatus = attstring.trim();
		                                }
		                                if ( attName.equals("APP - OBL")) {
		                                	OutboundLicense = attstring.trim();
		                                }
		                                if ( attName.equals("APP - OBL - Instructions")) {
		                                    OBLInstructions = attstring.trim();
		                                }
		                                if ( attName.equals("APP - OBL - Acceptance")) {
		                                	LicenseAcceptance = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Open Source")) {
		                                    OpenSource = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Standards")) {
		                                    Standards = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Standards - List")) {
		                                    StandardsList = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Standards - Member")) {
		                                    StandardsMember = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Super Group")) {
		                                	GroupName = attstring.trim();
		                                }
		                                if ( attName.equals("APP/CPC - SW Stack Classification")) {
		                                	SoftwareStackClassification = attstring.trim();
		                                }
		                                if ( attName.equals("APP/CPC - SW Technology Classification")) {
		                                    SoftwareTechnologyClassification = attstring.trim();
		                                }
		                                if ( attName.equals("APP/CPC - SW Technology Classification - Other")) {
		                                    SoftwareTechnologyClassificationOther = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Warranty")) {
		                                    Warranty = attstring.trim();
		                                }
		                                if ( attName.equals("APP - Warranty - Data Sheet")) {
		                                	WarrantyDataSheet = attstring.trim();
		                                }
		                            }
		                        }
		                    }
		                }
		            }
		            ptr_str = "<tr><td style='text-align: center;'>" + Name + "</td>"
		            		+ "<td style='text-align: center;'>" + Version + "</td>"
		            		+ "<td style='text-align: center;'>" + ProgramPlatform + "</td>"
		            		+ "<td style='text-align: center;'>" + ProductName + "</td>"
		            		+ "<td style='text-align: center;'>" + GroupName + "/" + SubGroupName + "</td>"
		            		+ "<td style='text-align: center;'>" + OutboundLicense + "</td>"
		            		+ "<td style='text-align: center;'>" + OBLInstructions + "</td>"           		
		            		+ "<td style='text-align: center;'>" + LicenseAcceptance + "</td>"
		            		+ "<td style='text-align: center;'>" + InformationClassification  + "</td>"
		            		+ "<td style='text-align: center;'>" + OpenSource + "</td>"
		            		+ "<td style='text-align: center;'>" + ExportECCN + "</td>"
		            		+ "<td style='text-align: center;'>" + Standards + "</td>"
		            		+ "<td style='text-align: center;'>" + StandardsMember + "</td>"
		            		+ "<td style='text-align: center;'>" + StandardsList + "</td>"
		            		+ "<td style='text-align: center;'>" + Indemnification + "</td>"
		            		+ "<td style='text-align: center;'>" + IndemnificationGMApprover + "</td>"
		            		+ "<td style='text-align: center;'>" + Warranty + "</td>"
		            		+ "<td style='text-align: center;'>" + WarrantyDataSheet + "</td>"
		            		+ "<td style='text-align: center;'>" + SoftwareStackClassification + "</td>"
			           		+ "<td style='text-align: center;'>" + SoftwareTechnologyClassification + "</td>"     
			           		+ "<td style='text-align: center;'>" + SoftwareTechnologyClassificationOther + "</td>" 
			           		//+ "<td style='text-align: center;'>" + ThirdPartyPatents + "</td>" 
			           		+ "<td style='text-align: center;'>" + IntelPatents + "</td>" 
			           		+ "<td style='text-align: center;'>" + IntelPatentStatus + "</td>" 
			           		
		            		
		            		+ "</tr>";
		        } catch (Exception e) {
		            System.err.println("Failed to create application data, caught exception: "  + e.getMessage());
		        }
		        return ptr_str;
		    };
		    
	/**********************************************************************************
	 * 	main()    
	 * @param args
	 * @throws Exception
	 **********************************************************************************/
    public static void main(String[] args) throws Exception {
        // check and save parameters
        if (args.length < 5) {
            System.err.println("\n\nNot enough parameters!");
            usage();
            System.exit(-1);
        }

        String serverUri = args[0];
        String username = args[1];
        String password = args[2];
        String applicationName = args[3];
        String Path = args[4];
        String outFile = "";
        
        ApplicationApi applicationApi = null;
        RequestApi requestApi = null;
        AttributeApi attributeApi = null;
        ColaApi colaApi = null;
        
        try {
            Long connectionTimeout = 600 * 1000L;
            CodeCenterServerProxyV7_0 myCodeCenterServer = new CodeCenterServerProxyV7_0(serverUri, username, password,
                    connectionTimeout);
            applicationApi = myCodeCenterServer.getApplicationApi();
            attributeApi = myCodeCenterServer.getAttributeApi();
            colaApi = myCodeCenterServer.getColaApi();
            requestApi = myCodeCenterServer.getRequestApi();
        } catch (RuntimeException e) {
            System.err.println("\nConnection to server '" + serverUri + "' failed: " + e.getMessage());
            System.exit(1);
        }

		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// get the application object
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		Application thisapp = null;
		ApplicationNameVersionToken apptoken = new ApplicationNameVersionToken();
		String OSName = null;
		String delimiter = null;
		OSName = System.getProperty("os.name");
		if (OSName.contains("Windows")) delimiter = "\\";
		else delimiter = "/";
		outFile = Path + delimiter + applicationName + " IP Plan.html"; 
		try {
			apptoken.setName(applicationName);
			apptoken.setVersion("Unspecified");
			thisapp = applicationApi.getApplication(apptoken);
		} catch (Exception e) {
			try {
				apptoken.setVersion("unspecified");
				thisapp = applicationApi.getApplication(apptoken);
			} catch (Exception e1) {
				System.err.println("get APP " + applicationName + " caught exception : " + e1.getMessage());
				System.exit(1);
			}
		}
		if ( null == thisapp ) {
			System.err.println("FAILED: to get app for " + applicationName );
			System.exit(1);
		}
     
        String html_content = "";
        
        GenerateIPPlanReport ipplan = new GenerateIPPlanReport();
        html_content = ipplan.GetApplicationData(thisapp, attributeApi, colaApi);
        
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Write the application and components in an HTML file with HTML tags
		//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        File f = new File(outFile);
        try {
                BufferedWriter bw = new BufferedWriter(new FileWriter(f));
                // Write application details and metadata
                bw.write( "<html><body>" 
                	  + "<header><h1> <span style='text-align:center;font-weight:bold'>"  + applicationName + " IP Plan"
                	  + "</span></h1></header>"
                	  + "<table border='2px'>"
                      + "<tr style='background-color: rgb(240, 240, 240);'>"
                      + "<th> Application Name </th>"
                      + "<th> Application version </th>"
                      + "<th> Program/Platform </th>"
                      + "<th> Product Name </th>"
                      + "<th> Group Name </th>"
                      + "<th> OBL </th>"
                      + "<th> OBL Instruction </th>"
                      + "<th> License Acceptance </th>"
                      + "<th> Information Classification </th>"
                      + "<th> Open Source Distribution </th>"
                      + "<th> Export Community Control Number </th>"
                      + "<th> Standards </th>"
                      + "<th> Standard Member </th>"
                      + "<th> Standard List </th>"
                      + "<th> Indemnification </th>"
                      + "<th> Indemnification GM Approver </th>"
                      + "<th> Warranty </th>"
                      + "<th> Warranty - Product/Software Data Sheet </th>"
                      + "<th> Software Stack Classification </th>"
                      + "<th> Software Technology Classification </th>"
                      + "<th> Specific Technology Classification </th>"
                      //+ "<th> 3rd Party Patents </th>"
                      + "<th> Intel Patents </th>"
                      + "<th> Intel Patent Status </th>"		
                      + "</tr>"
                      + html_content
                	  + "</table>" ) ;
                bw.write(" ");
                
                html_content = ipplan.GetComponentData(thisapp, applicationApi, apptoken, requestApi, colaApi, attributeApi);
                
                // Write each component and its request component details and its metadata
                bw.write( "<header><h1> <span style='text-align:center;font-weight:bold'>"  + " Bill Of Materials"
                  	  	+ "</span></h1></header>"
                		+"<table border='2px'>"
                        + "<tr style='background-color: rgb(240, 240, 240);'>"
                        + "<th> Component Name </th>"
                        + "<th> Component version </th>"
                        + "<th> License </th>"
                        + "<th> Description </th>"
                        + "<th> Homepage </th>"
                        + "<th> Supplier </th>"
                        + "<th> Supplier Category </th>"
                        + "<th> Software Stack Classification </th>"
                        + "<th> Software Technology Classification </th>"
                        + "<th> Software Technology Classification Other </th>"
                        + "<th> Operating System </th>"
                        + "<th> Programming Language </th>"
                        + "<th> Distribution Type </th>"
                        + "<th> Copyright Ownership </th>"
                        + "<th> Requested License </th>"
                        + "<th> Requested Usage </th>"
                        + "<th> Software Location </th>"
                        + "<th> Software Sub Location </th>"
                        + "<th> Control Strings </th>"
                        + "<th> License Location </th>"
                        + "<th> License Source </th>"
                        + "<th> Version Restrictions </th>"
                        + "<th> Information and Comments </th>"
                        + "</tr>"
                        + html_content
                  	  + "</table></body></html>" ) ;
                System.out.println("Done");

                bw.close();
        } catch (Exception e) {
          System.out.println(e);
        }
        
    } //main()

} //class GenerateIPPlan
