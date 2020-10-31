package burp;

import java.util.regex.Pattern;

/**
 * This class defines RegexRule
 *
 *
 */

public class RegexRule {
    private String name;
    private String description;
    private Pattern pattern;

    public RegexRule(String name, String description, Pattern pattern){
        this.name = name;
        this.description = description;
        this.pattern = pattern;
    }

    public String getName() { return name;}

    public void setName(String name) {this.name = name;}

    public String getDescription() { return description;}

    public void setDescription(String description) { this.description = description;}

    public Pattern getPattern() {
        return pattern;
    }

    public void setPattern(Pattern pattern) {
        this.pattern = pattern;
    }
}
