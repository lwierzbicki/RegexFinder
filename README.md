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

## Installation

1. Download the RegexFinder.jar file.
2. In Burp Suite open Extender tab. 
3. In Extensions tab, click Add button.
4. Choose downloaded jar file -> Next.
5. Check installation for no error messages.

## Example usage


  

##  Setup environment

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
