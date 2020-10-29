package burp;

/**
 * Burp Extender definition
 */

public class BurpExtender implements IBurpExtender {

    private static final String name = "RegexFinder";
    private static final String version = "0.1";
    private static final String tabName = "RegexFinder";

    protected RegexRulesTable rulesTable;
    protected RegexTab burpTab;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        callbacks.setExtensionName(name);

        RegexScan scan = new RegexScan(callbacks);
        callbacks.registerScannerCheck(scan);

        rulesTable = new RegexRulesTable(callbacks,scan);
        burpTab = new RegexTab(tabName, callbacks);
        burpTab.addComponent(rulesTable);
    }

}

