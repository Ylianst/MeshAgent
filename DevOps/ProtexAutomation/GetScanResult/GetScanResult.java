

import java.util.List;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.io.PrintWriter;

//import org.apache.cxf.common.util.SortedArraySet;



import com.blackducksoftware.sdk.fault.SdkFault;
import com.blackducksoftware.sdk.protex.client.util.BDProtexSample;
import com.blackducksoftware.sdk.protex.client.util.ProtexServerProxy;
import com.blackducksoftware.sdk.protex.project.Project;
import com.blackducksoftware.sdk.protex.project.ProjectApi;
import com.blackducksoftware.sdk.protex.project.bom.BomApi;
import com.blackducksoftware.sdk.protex.project.bom.BomLicenseInfo;
import com.blackducksoftware.sdk.protex.project.codetree.CodeTreeApi;
import com.blackducksoftware.sdk.protex.project.codetree.CodeTreeNode;
import com.blackducksoftware.sdk.protex.project.codetree.CodeTreeNodeRequest;
import com.blackducksoftware.sdk.protex.project.codetree.CodeTreeNodeType;
import com.blackducksoftware.sdk.protex.project.codetree.NodeCount;
import com.blackducksoftware.sdk.protex.project.codetree.NodeCountType;
import com.blackducksoftware.sdk.protex.project.codetree.discovery.CodeMatchDiscovery;
import com.blackducksoftware.sdk.protex.project.codetree.discovery.CodeMatchType;
import com.blackducksoftware.sdk.protex.project.codetree.discovery.DiscoveryApi;
import com.blackducksoftware.sdk.protex.project.codetree.discovery.IdentificationStatus;
import com.blackducksoftware.sdk.protex.project.codetree.identification.IdentificationApi;

/**
 * This sample program retrieves scan results and store the results in XML format in the output
 * file which is passed as input argument 4
 *
 * Retrieves below info:
 * - Total files analyzed
 * - Total file skipped
 * - Total files with pending identifications
 * - Total original code files
 * - List of inbound licenses
 * - OBL
 */
public class GetScanResult extends BDProtexSample {

	private static String translateXmlEntities(String line) {

        if ( null == line ) {
            return "";
        }

        //this MUST go first
        return line.replaceAll("&", "&amp;")
                .replaceAll("<", "&lt;")
                .replaceAll(">", "&gt;")
                .replaceAll("'", "&apos;")
                .replaceAll("\"", "&quot;");
    }
	
    private static void usage() {
    	System.out.println("Input Parameters:" );
        System.out.println("arg[0] - Protex server URL");
        System.out.println("arg[1] - Protex user ID");
        System.out.println("arg[2] - Password");
        System.out.println("arg[3] - Project ID");
        System.out.println("arg[4] - Location of output xml file");
    }
    
    
    /**************************************************************************************
     * 
     * @param args
     * @throws Exception
     */

    public static void main(String[] args) throws Exception {
        // check and save parameters
        if (args.length < 5) {
            System.err.println("Not enough parameters!");
            usage();
            System.exit(-1);
        }
        
        String serverUri = args[0];
        String username = args[1];
        String password = args[2];
        String projectId = args[3];
        String outPath = args[4];

        ProjectApi projectApi = null;
        CodeTreeApi codetreeApi = null;
        DiscoveryApi discoveryApi = null;
        BomApi bomApi = null;

        // get service and service port
        try {
            Long connectionTimeout = 120 * 1000L;
            ProtexServerProxy myProtexServer = new ProtexServerProxy(serverUri, username, password,
                    connectionTimeout);

            projectApi = myProtexServer.getProjectApi(5 * connectionTimeout);
            codetreeApi = myProtexServer.getCodeTreeApi(15 * connectionTimeout);
            discoveryApi = myProtexServer.getDiscoveryApi(15 * connectionTimeout);
            bomApi = myProtexServer.getBomApi(30 * connectionTimeout);

        } catch (RuntimeException e) {
            System.err.println("Connection to server '" + serverUri + "' failed: " + e.getMessage());
            System.exit(-1);
        }

        //get the license list
        List<BomLicenseInfo> licenses = null;
        try {
            licenses = bomApi.getBomLicenseInfo(projectId);
        } catch (SdkFault e) {
            System.err.println("\ngetLicenseInfo failed: " + e.getMessage());
            System.exit(-1);
        }
        // Check for valid return
        if (licenses == null) {
            System.err.println("\ngetLicenseInfo: unexpected return object");
            System.exit(-1);
        }
		///////////////////////////////////////////////////////////////////////////////////////////////////////////
		// code tree nodes
		///////////////////////////////////////////////////////////////////////////////////////////////////////////
		int DEPTH = 1; //pulling just the parent results in all 0 counts!??
		CodeTreeNodeRequest nodeRequest = new CodeTreeNodeRequest();
		nodeRequest.setDepth(DEPTH);
		nodeRequest.getCounts().add(NodeCountType.PENDING_ID_CODE_MATCH);
		nodeRequest.getCounts().add(NodeCountType.PENDING_REVIEW);
		nodeRequest.getCounts().add(NodeCountType.VIOLATIONS);
		nodeRequest.getCounts().add(NodeCountType.NO_DISCOVERIES);
		nodeRequest.getCounts().add(NodeCountType.FILES);
		nodeRequest.getCounts().add(NodeCountType.DISCOVERED_COMPONENTS);
		nodeRequest.getIncludedNodeTypes().add(CodeTreeNodeType.EXPANDED_ARCHIVE);
		nodeRequest.getIncludedNodeTypes().add(CodeTreeNodeType.FILE);
		nodeRequest.getIncludedNodeTypes().add(CodeTreeNodeType.FOLDER);
		nodeRequest.setIncludeParentNode(true);
		
        // get CodeTree
        String root = "/";
        int TOP_ONLY = 0;
        Long analyzedFiles = null;
        Long skippedFiles = null;
        Long discoveriesPending = null;
        Long noDiscoveries = null;
        Long discoveredComponents = null;
        Integer bomComponents = null;
        Integer bomLicenses = null;
        Long pendingReview = null;
        Long licenseViolations = null;
        
        //PartialCodeTree partialCodeTree = null;
        List<CodeTreeNode> partialCodeTree = null;
        try {
        	partialCodeTree = codetreeApi.getCodeTreeNodes(projectId, root, nodeRequest);
            for ( CodeTreeNode node : partialCodeTree) {
                if ( ! node.getName().equals("") ) continue;

                List<NodeCount> countList = node.getNodeCounts(); 
                for (NodeCount count: countList) {
                    Long value = count.getCount();
                    NodeCountType type = count.getCountType();
                    if ( NodeCountType.PENDING_ID_CODE_MATCH == type ) {
                    	discoveriesPending =  value;
                    } else if ( NodeCountType.PENDING_REVIEW == type ) {
                    	pendingReview = value;
                    } else if ( NodeCountType.VIOLATIONS == type ) {
                    	licenseViolations = value;
                    } else if ( NodeCountType.NO_DISCOVERIES == type ) {
                    	noDiscoveries = value;
                    } else if ( NodeCountType.FILES == type ) {
                    	analyzedFiles = value;
                    } else if ( NodeCountType.DISCOVERED_COMPONENTS == type ) {
                    	discoveredComponents = value;
                    } 
                    
                }//for (NodeCount
            }//for ( CodeTreeNode node
        	
            skippedFiles = codetreeApi.getSkippedFileCount(projectId);
        	
        } catch (SdkFault e) {
            System.err.println("getCodeTree(TOP_ONLY) failed: " + e.getMessage());
            System.exit(-1);
        }

        Project project = null;
        String analyzedDate = null;
        String projectName = null;
        project = projectApi.getProjectById(projectId);
        if (project != null) {
            DateFormat formatter = new SimpleDateFormat("dd MMM, yyyy hh:mm:ss a");
            analyzedDate = formatter.format(project.getLastAnalyzedDate().getTime());
            projectName = project.getName();
        }
     

        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // BOM (file) counts
        /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        try {
            bomComponents = bomApi.getBomComponentCount(projectId);
        } catch (SdkFault e) {
            System.err.println("getBomComponentCount() failed: " + e.getMessage());
            System.exit(-1);
        }
        try {
            bomLicenses = bomApi.getBomLicenseCount(projectId);
        } catch (SdkFault e) {
            System.err.println("getBomLicenseCount() failed: " + e.getMessage());
            System.exit(-1);
        }
        

        
         {

            PrintWriter outFile = null;
            try {
                outFile = new PrintWriter(outPath);
            } catch (Exception e) {
                System.err.println("\nUnable to create output file writer : " + e.getMessage());
                System.exit(-1);
            }

            
            outFile.println("<Project name=\"" + projectName + "\" id=\"" + projectId + "\" >");
            outFile.println("<ServerUrl>" + serverUri +"</ServerUrl>");
            outFile.println("<LastAnalyzed>" + analyzedDate +"</LastAnalyzed>");
            outFile.println("<ScanFileInfo>");
            outFile.println("\t<Analyzed>" + analyzedFiles + "</Analyzed>");
            outFile.println("\t<Skipped>" + skippedFiles + "</Skipped>");
            outFile.println("\t<PendingID>" + discoveriesPending + "</PendingID>");
            outFile.println("\t<NoDiscoveries>" + noDiscoveries + "</NoDiscoveries>" );
            outFile.println("</ScanFileInfo>");
            outFile.println("<Components>");
            outFile.println("\t<DiscoveredComponents>" + discoveredComponents + "</DiscoveredComponents>");
            outFile.println("</Components>");

            outFile.println("<BOM>");
            outFile.println("\t<TotalComponents>" + bomComponents + "</TotalComponents>");
            outFile.println("\t<TotalLicenses>" + bomLicenses + "</TotalLicenses>");
            outFile.println("\t<LicenseList>");
            if (licenses.size() == 0) {
                outFile.println("\t\t<None/>");
            } else {
                for (BomLicenseInfo license : licenses) {
                	String licensename = translateXmlEntities(license.getName());
                    if ( ! licensename.equals("Unspecified") ) {
                    	outFile.println("\t\t<License>" + licensename  + "</License>");
                    }
                }
            }

            outFile.println("\t</LicenseList>");
            outFile.println("\t<PendingReview>" + pendingReview + "</PendingReview>");
            outFile.println("\t<LicenseViolations>" + licenseViolations + "</LicenseViolations>");
            outFile.println("</BOM>");
            outFile.println("</Project>\n");

            outFile.flush();
            outFile.close();
        }
    }
}
