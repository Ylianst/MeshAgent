

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.xml.ws.soap.SOAPFaultException;

import com.blackducksoftware.sdk.fault.SdkFault;
import com.blackducksoftware.sdk.protex.client.util.BDProtexSample;
import com.blackducksoftware.sdk.protex.client.util.ProtexServerProxy;
import com.blackducksoftware.sdk.protex.project.Project;
import com.blackducksoftware.sdk.protex.project.ProjectApi;
import com.blackducksoftware.sdk.protex.report.Report;
import com.blackducksoftware.sdk.protex.report.ReportApi;
import com.blackducksoftware.sdk.protex.report.ReportFormat;
import com.blackducksoftware.sdk.protex.report.ReportSection;
import com.blackducksoftware.sdk.protex.report.ReportSectionType;
import com.blackducksoftware.sdk.protex.report.ReportTemplateRequest;


/**
 * This sample generates COS report and writes it to a file in HTML and xls
 *
 * It demonstrates:
 * - How to generate a report from a client side supplied template
 * - How to receive this report and write it to a file (using MTOM - Attachments)
 */
public class GetCOSReport extends BDProtexSample {


    private static void usage() {
    	System.out.println("Input Parameters:" );
        System.out.println("arg[0] - Protex server URL");
        System.out.println("arg[1] - Protex user ID");
        System.out.println("arg[2] - Password");
        System.out.println("arg[3] - Project ID");
        System.out.println("arg[4] - Output path\\Filename (without extension)");
        System.out.println("arg[5] - SCS Report Header text");
    }

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
        String reportFileName = args[4];
        //String headerText = args[5];
        String tableOfContents = "true";

        ReportApi reportApi = null;
        ProjectApi projectApi = null;
        try {
            Long connectionTimeout = 120 * 1000L;
            ProtexServerProxy myProtexServer = new ProtexServerProxy(serverUri, username, password,
                    connectionTimeout);

            reportApi = myProtexServer.getReportApi(15 * connectionTimeout);
            projectApi = myProtexServer.getProjectApi(15 * connectionTimeout);

       } catch (RuntimeException e) {
            System.err.println("Connection to server '" + serverUri + "' failed: " + e.getMessage());
            System.exit(-1);
        }
        Boolean showTOC = Boolean.valueOf("true".equals(tableOfContents));

        //now get the rest of the report data
        ReportTemplateRequest templateRequest = new ReportTemplateRequest();
        templateRequest.setName(projectId);
        Project project = projectApi.getProjectById(projectId);
        String projectName = project.getName();
        templateRequest.setTitle("Protex COS Report for " + projectName);
        //templateRequest.setHeader(headerText);
        templateRequest.setForced(Boolean.TRUE);
        //templateRequest.setTableofcontents("TOC");
       

     
        ReportSection section = new ReportSection();
        section.setLabel("Summary");
        section.setSectionType(ReportSectionType.SUMMARY);
        templateRequest.getSections().add(section);

        section = new ReportSection();
        section.setLabel("Analysis Summary");
        section.setSectionType(ReportSectionType.ANALYSIS_SUMMARY);
        templateRequest.getSections().add(section);

        section = new ReportSection();
        section.setLabel("BOM");
        section.setSectionType(ReportSectionType.BILL_OF_MATERIALS);
        templateRequest.getSections().add(section);
        
        section = new ReportSection();
        section.setLabel("Licenses in Effect");
        section.setSectionType(ReportSectionType.LICENSES_IN_EFFECT);
        templateRequest.getSections().add(section);

        section = new ReportSection();
        section.setLabel("License Conflicts");
        section.setSectionType(ReportSectionType.LICENSE_CONFLICTS);
        templateRequest.getSections().add(section);
        
        section = new ReportSection();
        section.setLabel("File Inventory");
        section.setSectionType(ReportSectionType.FILE_INVENTORY);
        templateRequest.getSections().add(section);
        
        section = new ReportSection();
        section.setLabel("IP Architecture");
        section.setSectionType(ReportSectionType.IP_ARCHITECTURE);
        templateRequest.getSections().add(section);
        
        section = new ReportSection();
        section.setLabel("Obligations");
        section.setSectionType(ReportSectionType.OBLIGATIONS);
        templateRequest.getSections().add(section);
        
        section = new ReportSection();
        section.setLabel("Identified Files");
        section.setSectionType(ReportSectionType.IDENTIFIED_FILES);
        templateRequest.getSections().add(section);

        section = new ReportSection();
        section.setLabel("Excluded Components");
        section.setSectionType(ReportSectionType.EXCLUDED_COMPONENTS);
        templateRequest.getSections().add(section);

        section = new ReportSection();
        section.setLabel("Work History - Bill of Material");
        section.setSectionType(ReportSectionType.WORK_HISTORY_BILL_OF_MATERIALS);
        templateRequest.getSections().add(section);
        
        section = new ReportSection();
        section.setLabel("Work History - File Inventory");
        section.setSectionType(ReportSectionType.WORK_HISTORY_FILE_INVENTORY);
        templateRequest.getSections().add(section);
        
        section = new ReportSection();
        section.setLabel("Potential Bill Of Materials");
        section.setSectionType(ReportSectionType.POTENTIAL_BILL_OF_MATERIALS);
        templateRequest.getSections().add(section);
        
        section = new ReportSection();
        section.setLabel("Searches");
        section.setSectionType(ReportSectionType.STRING_SEARCHES);
        templateRequest.getSections().add(section);

        

        


        // Call the Api
        Report reportHTML = null;
        Report reportXLS = null;
        try {
            try {
                reportHTML = reportApi.generateAdHocProjectReport(projectId, templateRequest, ReportFormat.HTML, showTOC);
                reportXLS = reportApi.generateAdHocProjectReport(projectId, templateRequest, ReportFormat.XLS, showTOC);
            } catch (SdkFault e) {
                System.err.println("generateProjectReport failed: " + e.getMessage());
                System.exit(-1);
            }

            // Check for valid return
            if (reportHTML == null || reportXLS == null) {
                System.err.println("unexpected return object");
                System.exit(-1);
            }

            if (reportHTML.getFileName() == null || reportXLS.getFileName() == null) {
                System.err.println("unexpected return object: File name can't be null or empty");
                System.exit(-1);
            }

            if (reportHTML.getFileContent() == null || reportXLS.getFileContent() == null) {
                System.err.println("unexpected return object: File content can't be null or empty");
                System.exit(-1);
            }

            File transferredFileHTML = new File(reportFileName + ".html");
            File transferredFileXLS = new File(reportFileName + ".xls");
            FileOutputStream outStream = null;
            try {

                outStream = new FileOutputStream(transferredFileHTML);
                reportHTML.getFileContent().writeTo(outStream);
            } catch (IOException e) {
                System.err.println("report.getFileContent().writeTo() failed: " + e.getMessage());
                System.exit(-1);
            } finally {
                if (outStream != null) {
                    outStream.close();
                }
            }
            System.out.println("\nHTML Report written to: " + transferredFileHTML.getAbsolutePath());

            try {

                outStream = new FileOutputStream(transferredFileXLS);
                reportXLS.getFileContent().writeTo(outStream);
            } catch (IOException e) {
                System.err.println("report.getFileContent().writeTo() failed: " + e.getMessage());
                System.exit(-1);
            } finally {
                if (outStream != null) {
                    outStream.close();
                }
            }
            System.out.println("\nXLS Report written to: " + transferredFileXLS.getAbsolutePath());
        } catch (SOAPFaultException e) {
            System.err.println("SampleGenerateReportFromTemplate failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(-1);
        }
    }

}
