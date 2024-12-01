package com.vv.ldapInjectionPrevention.domain;

public class LdapRequest {
    private String distinguishedName;
    private String filter;

    // Getters and Setters
    public String getDistinguishedName() {
        return distinguishedName;
    }
    public void setDistinguishedName(String distinguishedName) {
        this.distinguishedName = distinguishedName;
    }
    public String getFilter() {
        return filter;
    }
    public void setFilter(String filter) {
        this.filter = filter;
    }
}

