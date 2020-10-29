package burp;

import java.net.URL;

/**
 * This class defines CustomIssue, which is created by RegexScan
 *
 */

public class CustomIssue implements IScanIssue {

    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;
    private String remediation;

    public CustomIssue(
            IHttpRequestResponse baseRequestResponse,
            URL url,
            String name,
            String detail){
        httpService = baseRequestResponse.getHttpService();
        this.url = url;
        this.httpMessages = new IHttpRequestResponse[]{baseRequestResponse};
        this.name = name;
        this.detail = detail;
        this.severity = "Information"; // "High", "Medium", "Low", "Information" or "False positive"
        this.confidence = "Certain"; //"Certain", "Firm" or "Tentative"
        this.remediation = null;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return name;
    }

    @Override
    public int getIssueType() {
        return 0x08000000; //See http://portswigger.net/burp/help/scanner_issuetypes.html
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return "This is an <b>informational</b> finding only. You need to investigate it.<br>";
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return detail;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    public String getHost() {
        return null;
    }

    public int getPort() {
        return 0;
    }

    public String getProtocol() {
        return null;
    }

}
