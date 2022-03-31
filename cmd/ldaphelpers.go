package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func getSPNs(username string, password string, domain string, dcip string) [][]string {
	var ldapUrl string

	if dcip == "" {
		ldapUrl = fmt.Sprintf("ldap://%s:389", getDCFromDomain(domain))
	} else {
		ldapUrl = fmt.Sprintf("ldap://%s:389", dcip)
	}

	l, err := ldap.DialURL(ldapUrl)
	if err != nil {
		log.Fatal(err.Error())
	}

	defer l.Close()

	cn := fmt.Sprintf("%s@%s", username, domain)
	var dnparts []string
	parts := strings.Split(domain, ".")
	for _, p := range parts {
		dnparts = append(dnparts, fmt.Sprintf("dc=%s", p))
	}
	dn := strings.Join(dnparts, ",")

	err = l.Bind(cn, password)
	if err != nil {
		log.Fatal(err.Error())
	}

	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))",
		[]string{"sAMAccountName", "servicePrincipalName"},
		nil,
	)

	res, err := l.Search(req)
	if err != nil {
		log.Fatal(err.Error())
	}

	var out [][]string
	for _, entry := range res.Entries {
		out = append(out, []string{entry.GetAttributeValue("sAMAccountName"), entry.GetAttributeValue("servicePrincipalName")})
	}

	return out
}

func getPreAuthNotReq(username string, password string, domain string, dcip string) []string {
	var ldapUrl string

	if dcip == "" {
		ldapUrl = fmt.Sprintf("ldap://%s:389", getDCFromDomain(domain))
	} else {
		ldapUrl = fmt.Sprintf("ldap://%s:389", dcip)
	}

	l, err := ldap.DialURL(ldapUrl)
	if err != nil {
		log.Fatal(err.Error())
	}

	defer l.Close()

	cn := fmt.Sprintf("%s@%s", username, domain)

	var dnparts []string
	parts := strings.Split(domain, ".")
	for _, p := range parts {
		dnparts = append(dnparts, fmt.Sprintf("dc=%s", p))
	}
	dn := strings.Join(dnparts, ",")
	err = l.Bind(cn, password)
	if err != nil {
		log.Fatal(err.Error())
	}

	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
		[]string{"sAMAccountName"},
		nil,
	)

	res, err := l.Search(req)
	if err != nil {
		log.Fatal(err.Error())
	}

	var out []string
	for _, entry := range res.Entries {
		out = append(out, entry.GetAttributeValue("sAMAccountName"))
	}

	return out
}
