package scanner

import (
	"bufio"
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/enriquebris/goconcurrentqueue"
	"github.com/olekukonko/tablewriter"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/sw33tLie/sns/internal/utils"
)

var magicFinalParts = [12]string{"\\a.aspx", "\\a.asp", "/a.aspx", "/a.asp", "/a.shtml", "/a.asmx", "/a.ashx", "/a.config", "/a.php", "/a.jpg", "/webresource.axd", "/a.xxx"}
var requestMethods = [7]string{"OPTIONS", "GET", "POST", "HEAD", "TRACE", "TRACK", "DEBUG"}
var alphanum = "abcdefghijklmnopqrstuvwxyz0123456789_-"

const (
	bannerLogo = `  ___ _ __  ___ 
 / __| '_ \/ __|
 \__ \ | | \__ \
 |___/_| |_|___/ v1.0`
	bar = "________________________________________________"
)

type queueElem struct {
	url     string
	path    string
	ext     string
	shorter bool
}

type mapElem struct {
	count int
	found bool
}

func printBanner() {
	fmt.Println(bannerLogo + "\n\n IIS shortname scanner by sw33tLie\n" + bar + "\n")
}

var requestsCounter int
var requestsCounterMutex sync.Mutex

func incrementRequestsCounter(by int) {
	requestsCounterMutex.Lock()
	defer requestsCounterMutex.Unlock()
	requestsCounter += by
}

// CheckIfVulnerable checks if a target is vulnerable
func CheckIfVulnerable(url string, timeout int) (result bool, method string) {
	asteriskSymbol := "*"

	for _, requestMethod := range requestMethods {
		for _, magicFinalPart := range magicFinalParts {
			// First Request
			validStatus, validBody := utils.HTTPRequest(requestMethod, url+asteriskSymbol+"~1"+asteriskSymbol+magicFinalPart, "")
			invalidStatus, invalidBody := utils.HTTPRequest(requestMethod, url+"/1234567890"+asteriskSymbol+"~1"+asteriskSymbol+magicFinalPart, "")
			incrementRequestsCounter(2)

			acceptedDiffLength := 10

			if validStatus != invalidStatus && !(acceptedDiffLength >= 0 && utils.Abs(len(invalidBody)-len(validBody)) <= acceptedDiffLength) {
				return true, requestMethod
			}
			//fmt.Println(string(body2))
		}
	}
	return false, ""
}

func Scan(url string, requestMethod string, threads int, silent bool) (files []string, dirs []string) {
	queue := goconcurrentqueue.NewFIFO()
	cmap.New()
	m := cmap.New()

	for _, char := range alphanum {
		queue.Enqueue(queueElem{url, string(char), ".*", false})
	}

	processGroup := new(sync.WaitGroup)
	processGroup.Add(threads)

	for i := 0; i < threads; i++ {
		go func() {
			for queue.GetLen() > 0 {
				q, err := queue.Dequeue()
				if err != nil {
					log.Fatal("QUEUE WAS NIL")
				}
				qElem := q.(queueElem)

				if !silent {
					fmt.Printf("\r /" + qElem.path)
				}
				sc, _ := utils.HTTPRequest(requestMethod, qElem.url+qElem.path+"*~1"+qElem.ext+"/1.aspx", "")
				incrementRequestsCounter(1)
				found := false

				if sc == 404 {
					found = true

					if len(qElem.path) < 6 && !qElem.shorter {
						for _, char := range alphanum {
							queue.Enqueue(queueElem{qElem.url, qElem.path + string(char), qElem.ext, qElem.shorter})
						}
					} else {
						if qElem.ext == ".*" {
							queue.Enqueue(queueElem{qElem.url, qElem.path, "", qElem.shorter})
						}

						if qElem.ext == "" {
							if !silent {
								fmt.Println("\r - " + qElem.path + "~1 (Directory)")
							}
							dirs = append(dirs, qElem.path+"~1")
						} else if len(qElem.ext) == 5 || !(strings.HasSuffix(qElem.ext, "*")) {
							if !silent {
								fmt.Println("\r - " + qElem.path + "~1" + qElem.ext + " (File)")
							}
							files = append(files, qElem.path+"~1"+qElem.ext)
						} else {
							for _, char := range alphanum {
								queue.Enqueue(queueElem{qElem.url, qElem.path, utils.TrimLastChar(qElem.ext) + string(char) + "*", qElem.shorter})
								if len(qElem.ext) < 4 {
									queue.Enqueue(queueElem{qElem.url, qElem.path, utils.TrimLastChar(qElem.ext) + string(char), qElem.shorter})
								}
							}
						}
					}
				}

				prevPath := utils.TrimLastChar(qElem.path)
				if tmp, ok := m.Get(prevPath); ok {
					if found {
						m.Set(prevPath, mapElem{tmp.(mapElem).count - 1, true})
					} else {
						m.Set(prevPath, mapElem{tmp.(mapElem).count - 1, tmp.(mapElem).found})
					}
					if tmp.(mapElem).count == 0 && tmp.(mapElem).found == false {
						// we found a file with a len(shortname) < 6
						queue.Enqueue(queueElem{qElem.url, prevPath, ".*", true})
					}

				} else {
					if found {
						m.Set(prevPath, mapElem{len(alphanum) - 2, true})
					} else {
						m.Set(prevPath, mapElem{len(alphanum) - 2, false})
					}
				}
			}
			processGroup.Done()
		}()
	}
	processGroup.Wait()

	sort.Strings(files)
	sort.Strings(files)

	return files, dirs
}

// Run prints the output of a scan
func Run(scanURL string, threads int, silent bool, timeout int, proxy string) {
	startTime := time.Now()

	parsedURL, err := url.Parse(scanURL)
	if err != nil {
		if !silent {
			fmt.Println("Malformed URL, skipping...")
		}
		return
	}

	// The URL must end with /, and we ignore anything after ?
	scanURL = parsedURL.Scheme + "://" + parsedURL.Host + strings.TrimSuffix(parsedURL.Path, "/") + "/"

	if !silent {
		printBanner()
		if proxy == "" {
			fmt.Println(" Proxy:  ", "None")
		} else {
			fmt.Println(" Proxy:  ", proxy)
		}
		fmt.Println(" Target: ", scanURL)
		fmt.Println(" Threads:", threads)
		fmt.Println(" Timeout:", timeout)

		fmt.Println(bar + "\n")
	}

	vulnerable, requestMethod := CheckIfVulnerable(scanURL, timeout)

	if !vulnerable {
		if !silent {
			fmt.Println("Target is not vulnerable")
		}
		return
	}

	files, dirs := Scan(scanURL, requestMethod, threads, silent)

	fmt.Println("\n" + bar + "\n\n")
	// Let's print the results in a nice table
	var tableData [][]string
	for _, row := range dirs {
		tableData = append(tableData, []string{row, "Not found", "Directory"})
	}

	for _, row := range files {
		tableData = append(tableData, []string{row, "Not found", "File"})
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"SHORTNAME", "FULL NAME", "TYPE"})
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("\t") // pad with tabs
	table.SetNoWhiteSpace(true)

	for _, v := range tableData {
		table.Append(v)
	}
	table.Render()

	endTime := time.Now()
	if !silent {
		fmt.Println("Done! Requests:", requestsCounter, " Time:", endTime.Sub(startTime))
	}
}

// BulkScan prints the output of a bulk scan
func BulkScan(filePath string, threads int, silent bool, timeout int, proxy string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		Run(scanner.Text(), threads, silent, timeout, proxy)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
