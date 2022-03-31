package cmd

import (
	"fmt"
	"log"
	"net"
)

func getDCFromDomain(domain string) string {
	_, srvs, err := net.LookupSRV("ldap", "tcp", fmt.Sprintf("dc._msdcs.%s", domain))
	if err != nil {
		log.Fatal(err.Error())
	}
	return srvs[0].Target
}
