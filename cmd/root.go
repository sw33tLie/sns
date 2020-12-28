package cmd

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/sw33tLie/sns/pkg/scanner"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sns",
	Short: "A IIS shortname scanner written in Go",
	Long:  `A IIS shortname scanner written in Go`,
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")
		proxy, _ := cmd.Flags().GetString("proxy")
		scanURL, _ := cmd.Flags().GetString("url")
		silent, _ := cmd.Flags().GetBool("silent")
		threads, _ := cmd.Flags().GetInt("threads")
		timeout, _ := cmd.Flags().GetInt("timeout")

		if scanURL == "" && file == "" {
			log.Fatal("No URL(s) to scan provided")
		}

		if proxy != "" {
			proxyURL, err := url.Parse(proxy)
			if err != nil {
				log.Fatal("Invalid Proxy String")
			}
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			http.DefaultTransport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
		}

		if scanURL != "" {
			scanner.Run(scanURL, threads, silent, timeout)
			return
		}

		if file != "" {
			scanner.BulkScan(file, threads, silent, timeout)
			return
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sns.yaml)")
	rootCmd.Flags().StringP("file", "f", "", "File containing URLs to scan")
	rootCmd.Flags().StringP("proxy", "", "", "HTTP Proxy (Useful for debugging. Example: http://127.0.0.1:8080)")
	rootCmd.Flags().StringP("url", "u", "", "URL to scan")
	rootCmd.Flags().IntP("threads", "t", 50, "Threads")
	rootCmd.Flags().IntP("timeout", "", 10, "HTTP requests timeout")
	rootCmd.Flags().BoolP("color", "c", false, "Use colored output")
	rootCmd.Flags().BoolP("silent", "s", false, "Silent output")
	rootCmd.Flags().BoolP("banner", "b", false, "Silent output")

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
}
