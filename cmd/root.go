package cmd

import (
	"fmt"
	"log"
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
		url, _ := cmd.Flags().GetString("url")
		file, _ := cmd.Flags().GetString("file")
		threads, _ := cmd.Flags().GetInt("threads")

		if url == "" && file == "" {
			log.Fatal("No URL(s) to scan provided")
		}

		if url != "" {
			scanner.Scan(url, threads)
			return
		}

		if file != "" {
			scanner.BulkScan(file)
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
	rootCmd.Flags().StringP("url", "u", "", "URL to scan")
	rootCmd.Flags().StringP("file", "f", "", "File containing URLs to scan")
	rootCmd.Flags().IntP("threads", "t", 50, "Threads")
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
