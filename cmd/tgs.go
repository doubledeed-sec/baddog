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

	"github.com/spf13/cobra"
)

// tgsCmd represents the tgs command
var tgsCmd = &cobra.Command{
	Use:   "tgs",
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

		tgs(cmd, tgt, username, password, domain, dcip, spn, enc)
	},
}

func init() {
	rootCmd.AddCommand(tgsCmd)

	//also add option to read TGT from file? keytabs, ccache, kirbi... etc
	tgsCmd.Flags().StringP(
		"tgt", "t", "", "Base64 encoded TGT to be used to obtain TGS",
	)
	tgsCmd.Flags().StringP(
		"username", "u", "", "Username to be used for kerberos authentication",
	)
	tgsCmd.Flags().StringP(
		"password", "p", "", "Password to be used for kerberos authentication",
	)
	tgsCmd.Flags().StringP(
		"domain", "d", "", "Domain to be used for kerberos authentication",
	)
	tgsCmd.Flags().StringP(
		"dc-ip", "", "", "IP Address of domain controller",
	)
	tgsCmd.Flags().StringP(
		"enc", "", "rc4,aes128,aes256,desCRC,desMD5", "Encryption types, comma delimited",
	)
	tgsCmd.Flags().StringP(
		"spn", "s", "", "SPN for which TGS will be requested",
	)

}

func tgs(tgsCmd *cobra.Command, tgt string, username string, password string, domain string, dcip string, spnstring string, enc string) {
	if tgsCmd.Flags().Changed("tgt") {
		fmt.Println("[+] TGT Provided, using it to obtain TGS")
	} else if tgsCmd.Flags().Changed("username") && tgsCmd.Flags().Changed("password") && tgsCmd.Flags().Changed("domain") {
		fmt.Println("[+] Credentials provided, attempting to obtain fresh TGT")
		cl := NewCl(username, password, domain, dcip, enc)
		tgt := GetTGT(cl)
		GetTGS(cl, tgt, spnstring, domain)
	} else {
		fmt.Println("Please provide either a tgt or credentials")
	}
}
