package com.vv.ldapInjectionPrevention.controller;

import com.vv.ldapInjectionPrevention.domain.LdapRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.List;

@Controller
public class LdapController {

    @Autowired
    private LdapTemplate ldapTemplate;

    @GetMapping("/")
    public String form( Model model ) {
        model.addAttribute("ldapRequest", new LdapRequest() );
        return "form";
    }

    @PostMapping("/submit")
    public String submitForm(@ModelAttribute LdapRequest ldapRequest, Model model) {
        try {
            // Debug logging for distinguishedName and filter
            String distinguishedName = ldapRequest.getDistinguishedName();
            System.out.println( "Distinguished Name: " + distinguishedName );
            String filter = ldapRequest.getFilter();
            System.out.println( "Filter: " + filter );

            distinguishedName = LdapUtils.escapeDN( distinguishedName );
            System.out.println( "Sanitized Distinguished Name: " + distinguishedName );
            filter = LdapUtils.escapeLDAPFilter( filter );
            System.out.println( "Sanitized Filter: " + filter );

            // Execute LDAP query
            List<String> results = ldapTemplate.search(
                    distinguishedName,
                    filter,
                    (AttributesMapper<String>) attrs -> attrs.get("cn").get().toString()
                                                      );
            model.addAttribute("results", results);
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
        }
        return "result";
    }

}
