package com.vv.ldapInjectionPrevention.controller;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class LdapUtils {

    private LdapUtils() {
    }
    /**
     * A regular expression pattern used to match and capture the value in a key-value pair format,
     * where the key and value are separated by an equals sign (`=`).
     *
     * The regex specifically matches an equals sign (`=`), followed by one or more characters
     * that are not parentheses (`(` or `)`).
     *
     * Pattern: `=([^\\)\\(]+)`
     *
     * Explanation:
     * - `=`: Matches the literal equals sign.
     * - `(`: Begins a capturing group.
     * - `[^\\)\\(]+`: Matches one or more characters that are not `)` or `(`.
     * - `)`: Ends the capturing group.
     *
     * Use Case:
     * This pattern is useful for extracting the value in key-value pairs, where the value
     * should not contain parentheses. For example, in a string like "key=value", the regex
     * will capture "value".
     *
     * Example Matches:
     * - Input: "key=value"
     *   - Match: `=value`
     *   - Captured group: `value`
     * - Input: "param=abc123"
     *   - Match: `=abc123`
     *   - Captured group: `abc123`
     * - Input: "example=(value)"
     *   - No match (value contains `(` or `)`).
     */

    private static final Pattern FILTER_VALUE_PATTERN = Pattern.compile( "=([^\\)\\(]+)" );

    /**
     * Escapes special characters in an LDAP DN (Distinguished Name).
     * Special characters include: \, ,, +, ", <, >, ;, and spaces
     * at the beginning and end of the string.
     *
     * @param name The DN name to escape.
     * @return The DN name with special characters escaped.
     */
    public static String escapeDN(String name) {
        final Map<Character, String> DN_ESCAPE_MAP = Map.of(
                '\\', "\\\\",
                ',', "\\,",
                '+', "\\+",
                '"', "\\\"",
                '<', "\\<",
                '>', "\\>",
                ';', "\\;");

        StringBuilder sb = new StringBuilder();
        if ((name.length() > 0) && ((name.charAt(0) == ' ') || (name.charAt(0) == '#'))) {
            sb.append('\\'); // add the leading backslash if needed
        }
        sb.append(escapeCharacters(name, DN_ESCAPE_MAP));
        if ((name.length() > 1) && (name.charAt(name.length() - 1) == ' ')) {
            sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if needed
        }
        return sb.toString();
    }

    /**
     * Escapes values in an LDAP filter to ensure they are correctly interpreted.
     *
     * This method takes an LDAP filter string as input, identifies the values within the filter,
     * and applies the necessary escape sequences to special characters found in those values.
     *
     * @param filter The LDAP filter string to process.
     * @return The LDAP filter string with escaped values.
     */
    public static String escapeLDAPFilter(String filter) {
        Matcher matcher = FILTER_VALUE_PATTERN.matcher( filter );
        StringBuffer escapedFilter = new StringBuffer();
        while (matcher.find()) {
            String value = matcher.group(1);
            String escapedValue = escapeLDAPSearchFilterValue(value);
            matcher.appendReplacement(escapedFilter, "=" + escapedValue);
        }
        matcher.appendTail(escapedFilter);
        return escapedFilter.toString();
    }

    /**
     * Escapes special characters in an LDAP search filter.
     * Special characters include: \, *, (, ), and the null character (\u0000).
     *
     * @param filter The LDAP search filter to escape.
     * @return The LDAP search filter with special characters escaped.
     */
    public static final String escapeLDAPSearchFilterValue(String filter) {
        final Map<Character, String> FILTER_ESCAPE_MAP = Map.of(
                '\\', "\\5c",
                '*', "\\2a",
                '(', "\\28",
                ')', "\\29",
                '\u0000', "\\00" );

        return escapeCharacters(filter, FILTER_ESCAPE_MAP);
    }

    /**
     * Escapes special characters in an input string based on the provided mapping.
     *
     * @param input The input string to escape.
     * @param escapeMap A map containing the characters to escape as keys and their replacements as values.
     * @return The input string with special characters escaped.
     */
    public static String escapeCharacters(String input, Map<Character, String> escapeMap ) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char curChar = input.charAt(i);
            if (escapeMap.containsKey(curChar)) {
                        sb.append(escapeMap.get(curChar));
            } else {
                sb.append(curChar);
            }
        }
        return sb.toString();
    }
}
