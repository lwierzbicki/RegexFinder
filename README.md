# RegexFinder

RegexFinder is a BurpSuitePro extension to passively scan responses for occurrence of regular expression patterns. 
Vulnerabilities or additional information about application can be found based on patterns. 
Regular expressions can be used to detect patterns of:

- error messages
- software version
- reflected values
- Javascript functions (like postMessage or document.write)
- API keys
- information disclosures

The tester adds and controls list of patterns, which are used by the extension. 
Each pattern has category and description. 
If extension found pattern in HTTP response, it adds an issue.
Issue name is category assigned by the tester. 
Issue description contains details about the pattern and description assigned by the tester.
List of patterns can be uploaded as tab-delimited file (.tsv, .tab) file. 
It can also be filled manually by adding / removing values.
Example tab-delimited file included [here](https://github.com/lwierzbicki/RegexFinder/blob/main/burp.regex.tsv). 

I would summarize it as simplified, extended and adapted to the current version of Burp Suite extension originally created by [August Detlefsen](https://github.com/augustd). 


## Installation

1. Download the RegexFinder.jar file.
2. In Burp Suite open Extender tab. 
3. In Extensions tab, click Add button.
4. Choose downloaded jar file -> Next.
5. Check installation for no error messages.

## Example usage

1. On RegexFinder tab load tsv file containing list of patterns. 
2. In example the following pattern `AIza[0-9A-Za-z-_]{35}`. That pattern matches Google API key.
3. When you look through the pages, extension is going to add an issue if there is a match. 
4. You can then verify found Google API key using [gmapsapiscanner](https://github.com/ozguralp/gmapsapiscanner).   

## Building Your Own Regex File

### Error messages

Good starting point is original list used for [Error Message Checks](https://github.com/augustd/burp-suite-error-message-checks) located [here](https://github.com/augustd/burp-suite-error-message-checks/blob/master/src/main/resources/burp/match-rules.tab).

### Software versions

Good starting point is original list used for [Software Version Checks](https://github.com/augustd/burp-suite-software-version-checks) located [here](https://github.com/augustd/burp-suite-software-version-checks/blob/master/src/main/resources/burp/match-rules.tab).  

### Reflected values

Extension [Reflection Tracer](https://github.com/securityewok/Reflection-Tracer) uses the following pattern `tr4c3[a-z0-9]{8}`. You can create any value which can be distinguished using regular expression and add it to the file with list of patterns.

### Javascript functions

### API keys

Good starting point are the following repos:

- [RegExAPI by odomojuli](https://github.com/odomojuli/RegExAPI)
- [RegHex by l4yton](https://github.com/l4yton/RegHex)

How these API keys can be used:

- [Keyhacks by streaak](https://github.com/streaak/keyhacks)
- [PayloadsAllTheThings by swisskyrepo](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API%20Key%20Leaks)

### Information disclosure

##  Dev Setup

### Set up project in IDEA IntelliJ (Community Edition)

1. Open new project
2. In `Project Structure`, section `Modules` -  add dependency for BurpSuitePro jar.
3. In `Project Structure`, section `Artifacts` - add a new artifact which produces jar.
4. Copy src to src folder.
5. Add new `Add Configuration Run`. Setup it as `Application` and `Main class` to burp.StartBurp.
6. Play button will start BurpSuitePro.

### Build

Run `Build` > `Build Artifacts...`

## Design decisions

1. The passive scan of HTTP responses based on user-defined list of rules.
2. Rule contains: name, description and pattern.
3. Extension creates an issue based on rule information. 
4. Use of BurpSuite built-in mechanism - function `doPassiveScan`.
5. Configuration of extensions through built-in BurpSuite mechanism (i.e. passive scan of HTTP responses from Repeater is possible through configuration of live task).
6. Minimalistic.

## Acknowledgements

Special thanks for the following projects and their creators for inspiration:

- [Error Message Checks](https://github.com/augustd/burp-suite-error-message-checks)
- [Reflection Tracer](https://github.com/securityewok/Reflection-Tracer)   
- [Reflected Parameters](https://github.com/portswigger/reflected-parameters)

Extension borrows a good piece of code from [Error Message Checks](https://github.com/augustd/burp-suite-error-message-checks) and [Burp Suite Utils](https://github.com/augustd/burp-suite-utils).
