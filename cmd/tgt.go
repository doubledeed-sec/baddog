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
	"github.com/spf13/cobra"
)

// tgtCmd represents the tgt command
var tgtCmd = &cobra.Command{
	Use:   "tgt",
	Short: "Requests a TGT",
	Long:  `Requests a TGT`,
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		dcip, _ := cmd.Flags().GetString("dc-ip")
		enc, _ := cmd.Flags().GetString("enc")
		tgt(username, password, domain, dcip, enc)
	},
}

func init() {
	rootCmd.AddCommand(tgtCmd)

	tgtCmd.Flags().StringP(
		"username", "u", "", "Username to be used for kerberos authentication",
	)
	tgtCmd.Flags().StringP(
		"password", "p", "", "Password to be used for kerberos authentication",
	)
	tgtCmd.Flags().StringP(
		"domain", "d", "", "Domain to be used for kerberos authentication",
	)
	tgtCmd.Flags().StringP(
		"dc-ip", "", "", "IP Address of domain controller",
	)
	tgtCmd.Flags().StringP(
		"enc", "", "rc4,aes128,aes256,desCRC,desMD5", "Encryption types, comma delimited",
	)
}

func tgt(username string, password string, domain string, dcip string, enc string) {
	cl := NewCl(username, password, domain, dcip, enc)
	GetTGT(cl)
}
