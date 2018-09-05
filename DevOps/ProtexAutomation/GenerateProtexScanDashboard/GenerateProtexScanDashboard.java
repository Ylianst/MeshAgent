import java.io.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class GenerateProtexScanDashboard {

	private static void usage() {
        System.out.println("Input Parameters:" );
        System.out.println("Folder path\\name - Location and folder name where all scan results xml files are stored\n" + 
                "File path\\name - location and filename to store the dashboard summary html report ");
        System.out.println("");
       
    }
	
    public String getAllScanResult(File  file) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            int number;
            //File file = new File(fileName);

            //System.out.println("Exists: " + file.getName() + " " + file.exists());
            if (file.exists()) {
                Document doc = db.parse(file);

                
                //System.out.println("File: " + fileName);
                //System.out.println("Root element :" + doc.getDocumentElement().getNodeName());
                //System.out.println("Root element attrib :" + doc.getDocumentElement().getAttribute("name"));

                NodeList serverList = doc.getElementsByTagName("ServerUrl");
                Node serverUrlNode = serverList.item(0);
                Element serverUrlElement = (Element) serverUrlNode;
                //System.out.println("Server url: " + serverUrlElement.getTextContent());

                NodeList analyzedTimeList = doc.getElementsByTagName("LastAnalyzed");
                Node anaTimeNode = analyzedTimeList.item(0);
                Element anaTimeElement = (Element) anaTimeNode;
                //System.out.println("ANAly Time: " + anaTimeElement.getTextContent());

                NodeList analyzedList = doc.getElementsByTagName("Analyzed");
                Node anaNode = analyzedList.item(0);
                Element anaElement = (Element) anaNode;
                //System.out.println("ANAly : " + anaElement.getTextContent());

                NodeList pendingList = doc.getElementsByTagName("PendingID");
                Node penNode = pendingList.item(0);
                Element penElement = (Element) penNode;
                //System.out.println("Pending : " + penElement.getTextContent());

                NodeList totCompList = doc.getElementsByTagName("TotalComponents");
                Node tCompNode = totCompList.item(0);
                Element tCompElement = (Element) tCompNode;
                //System.out.println("total Comp : " + tCompElement.getTextContent());

                NodeList totLicList = doc.getElementsByTagName("TotalLicenses");
                Node tLicNode = totLicList.item(0);
                Element tLicElement = (Element) tLicNode;
                //System.out.println("Tot Lic : " + tLicElement.getTextContent());

                NodeList pendingRevList = doc.getElementsByTagName("PendingReview");
                Node penRevNode = pendingRevList.item(0);
                Element penRevElement = (Element) penRevNode;
                //System.out.println("Pending Rev: " + penRevElement.getTextContent());

                NodeList licVioList = doc.getElementsByTagName("LicenseViolations");
                Node licVioNode = licVioList.item(0);
                Element licVioElement = (Element) licVioNode;
                //System.out.println("Lice Violati : " + licVioElement.getTextContent());

                String prj_str = "<tr><td><a href='" + serverUrlElement.getTextContent() + "' target='_blank'>"
                          + doc.getDocumentElement().getAttribute("name") + "</a></td>"
                          + "<td style='text-align: center;'>" + anaTimeElement.getTextContent() + "</td>"
                          + "<td style='text-align: center;'>" + anaElement.getTextContent() + "</td>";
                
                number =  Integer.parseInt(penElement.getTextContent());
                if (number > 0) 
                	prj_str = prj_str + "<td style='text-align: center;': bgcolor=gold> <b> <font color=red>" + penElement.getTextContent()  + "</font></b></td>";
                else 
                	prj_str = prj_str + "<td style='text-align: center;'>" + penElement.getTextContent()  + "</td>";
                                          
                prj_str = prj_str      + "<td style='text-align: center;'>" + tCompElement.getTextContent() + "</td>"
                          + "<td style='text-align: center;'>" + tLicElement.getTextContent() + "</td>";
                          
                number =  Integer.parseInt(penRevElement.getTextContent());
                if (number > 0) 
                	prj_str = prj_str + "<td style='text-align: center;': bgcolor=gold> <b> <font color=red>" + penRevElement.getTextContent()  + "</font></b></td>";
                else 
                	prj_str = prj_str + "<td style='text-align: center;'>" + penRevElement.getTextContent() + "</td>";
                
                number =  Integer.parseInt(licVioElement.getTextContent());
                if (number > 0) 
                	prj_str = prj_str + "<td style='text-align: center;': bgcolor=gold> <b> <font color=red>" + licVioElement.getTextContent()  + "</font></b></td>";
                else 
                	prj_str = prj_str + "<td style='text-align: center;'>" + licVioElement.getTextContent() + "</td>";
                
               // prj_str = prj_str        + "<td style='text-align: center;'><a href='COS_report.html' target='_blank'>COS Report</a></td></tr>";

                return prj_str;
            }
        } catch (Exception e) {
            System.out.println(e);
        }
        return "Error!! Parsing XML reports";
    }

    public static void main(String[] args)
    {

    	if (args.length < 2) {
            System.err.println("Not enough parameters!");
            usage();
            System.exit(-1);
        }
    	
        GenerateProtexScanDashboard parser = new GenerateProtexScanDashboard();
        String filename;
        File folder = new File( args[0] );
        File[] listOfFiles = folder.listFiles();
        String html_content = "";
        String OSName = null;
		String delimiter = null;
		OSName = System.getProperty("os.name");
		if (OSName.contains("Windows")) delimiter = "\\";
		else delimiter = "/";
		
        for (int i = 0; i < listOfFiles.length; i++)
        {
           if (listOfFiles[i].isFile())
           {
              filename = folder.getPath() + delimiter + listOfFiles[i].getName();
              //System.out.println("File: " + filename);
              if (filename.endsWith(".xml") || filename.endsWith(".XML"))
              {
            	  File filehandle = new File(filename);
                  String prj_str = parser.getAllScanResult( filehandle );
                  html_content = html_content + prj_str;
              }
           }
        }

        File f = new File(args[1]);
        try {
                BufferedWriter bw = new BufferedWriter(new FileWriter(f));
                bw.write( "<html><body>" 
                	  + "<h1> <span style='text-align:center;font-weight:bold'>  Protex Scan Summary </span></h1>"
                	  + "<table border='2px'>"
                      + "<tr style='background-color: rgb(240, 240, 240);'>"
                      + "<th rowspan='2'> Protex Project </th>"
                      + "<th rowspan='2'> Last Scan Timestamp </th>"
                      + "<th colspan='2' style='border-bottom: 1px solid;'> Files </th>"
                      + "<th colspan='4' style='border-bottom: 1px solid;'> BOM </th>"
                     // + "<th rowspan='2'> Detailed Summary </th>"
                      + "</tr><tr style='background-color: rgb(240, 240, 240);'>"
                      + "<th style='border-left: 1px solid;'> Analyzed </th>"
                      + "<th style='border-left: 1px solid;'> Pending </th>"
                      + "<th style='border-left: 1px solid;'> Components </th>"
                      + "<th style='border-left: 1px solid;'> NumLicense </th>"
                      + "<th style='border-left: 1px solid;'> PendingReview </th>"
                      + "<th style='border-left: 1px solid;'> LicenseViolations </th></tr>"
                      + html_content + "</table></body></html>" ) ;

                bw.close();
        } catch (Exception e) {
          System.out.println(e);
        }
    }
}
