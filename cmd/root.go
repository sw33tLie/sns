package cmd

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/sw33tLie/sns/pkg/scanner"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"github.com/sw33tLie/sns/internal/utils"
)

var cfgFile string
var headers []string

var rootCmd = &cobra.Command{
	Use:   "sns",
	Short: "A IIS shortname scanner written in Go",
	Long:  `A IIS shortname scanner written in Go`,
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")
		check, _ := cmd.Flags().GetBool("check")
		proxy, _ := cmd.Flags().GetString("proxy")
		scanURL, _ := cmd.Flags().GetString("url")
		silent, _ := cmd.Flags().GetBool("silent")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")
		nocolor, _ := cmd.Flags().GetBool("nocolor")

		if scanURL == "" && file == "" {
			log.Fatal("No URL(s) to scan provided")
		}

		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		}

		http.DefaultClient.Timeout = time.Duration(timeout) * time.Second

		if proxy != "" {
			proxyURL, err := url.Parse(proxy)
			if err != nil {
				log.Fatal("Invalid Proxy String")
			}
			http.DefaultTransport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
		}

		if scanURL != "" {
			if check {
				scanner.CheckIfVulnerable(scanURL, headers, timeout, threads, true, false)
				return
			}

			scanner.Run(scanURL, headers, threads, silent, timeout, nocolor, proxy)
			return
		}

		if file != "" {
			if check {
				scanner.BulkCheck(file, headers, threads, timeout, nocolor)
				return
			}

			scanner.BulkScan(file, headers, threads, silent, timeout, nocolor, proxy)
			return
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sns.yaml)")
	rootCmd.Flags().StringP("file", "f", "", "File containing URLs to scan")
	rootCmd.Flags().StringP("proxy", "", "", "HTTP Proxy (Useful for debugging. Example: http://127.0.0.1:8080)")
	rootCmd.Flags().StringP("url", "u", "", "URL to scan")
	rootCmd.Flags().IntP("threads", "t", 50, "Threads")
	rootCmd.Flags().IntP("timeout", "", 30, "HTTP requests timeout")
	rootCmd.Flags().BoolP("nocolor", "", false, "Don't use colored output")
	rootCmd.Flags().BoolP("silent", "s", false, "Silent output")
	rootCmd.Flags().BoolP("check", "", false, "Only check if vulnerable")
	rootCmd.Flags().StringSliceVarP(&headers, "header", "H", []string{}, "Custom header. Example: -H \"X-Forwarded-For: 127.0.0.1\"")
	rootCmd.PersistentFlags().StringP("loglevel", "l", "info", "Set log level. Available: debug, info, warn, error, fatal")

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".sns" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".sns")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	levelString, _ := rootCmd.PersistentFlags().GetString("loglevel")
	utils.SetLogLevel(levelString)
}
