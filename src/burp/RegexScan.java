package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

/**
 * This class creates a passive scan which checks patterns.
 *
 * Functions: addRegexRule, removeRegexRule, clearRegexRules
 * were adapted from https://github.com/augustd/burp-suite-utils
 * Original author:
 * @author August Detlefsen
 */

public class RegexScan implements IScannerCheck {

    protected static List<RegexRule> rules = new ArrayList<>();
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    RegexScan(final IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse){
        ArrayList<IScanIssue> issues = new ArrayList<>();
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        String urlPrefix = url.getProtocol() + "://" + url.getHost() + url.getPath();
        this.callbacks.printOutput("Do passive scan:" + urlPrefix );

        byte[] responseBytes = baseRequestResponse.getResponse();
        String response = helpers.bytesToString(responseBytes);

        //iterate through rules and check for matches
        for (RegexRule rule : rules) {
            Matcher matcher = rule.getPattern().matcher(response);
            if(matcher.find()){
                callbacks.printOutput("Pattern found: " + rule.getPattern().toString());
                issues.add(new CustomIssue(
                        baseRequestResponse,
                        url,
                        rule.getName(),
                        "<b>" + rule.getDescription() + "</b> found <b>" + matcher.group() + "</b> using pattern <b>" + rule.getPattern().toString() + "</b><br>"));
            }
        }


        return issues;
                //.stream()
                //.filter(Objects::nonNull)
                //.collect(Collectors.toList());
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return new ArrayList<>();
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()) && existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
            return -1;
        else return 0;
    }

    /**
     * Add a new match rule to the scan
     *
     * @param newRule match rule to add
     */
    public void addRegexRule(RegexRule newRule) {
        rules.add(newRule);
    }

    /**
     * Remove match rule from the scan
     *
     * @param index Index of the match rule to remove
     */
    public void removeRegexRule(int index) {
        rules.remove(index);
    }

    /**
     * Clear all match rules from the scan
     */
    public void clearRegexRules() {
        rules.clear();
    }

    /**
     * Get an existing match rule of the scan.
     *
     * If no match rule exists at the specified index, this method returns null.
     *
     * @param index Index of the match rule to return
     * @return The match rule at the specified index, or null if none exists
     */
    public RegexRule getRegexRule(int index) {
        if (index < rules.size()) {
            return rules.get(index);
        }
        return null;
    }
}
