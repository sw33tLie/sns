package scanner

import (
	"bufio"
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/enriquebris/goconcurrentqueue"
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
	url  string
	path string
	ext  string
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
			validStatus, validBody := utils.HTTPRequest(requestMethod, url+asteriskSymbol+"~1"+asteriskSymbol+magicFinalPart, "", timeout)
			invalidStatus, invalidBody := utils.HTTPRequest(requestMethod, url+"/1234567890"+asteriskSymbol+"~1"+asteriskSymbol+magicFinalPart, "", timeout)
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

func Scan(url string, requestMethod string, threads int, silent bool, timeout int) (files []string, dirs []string) {
	queue := goconcurrentqueue.NewFIFO()

	for _, char := range alphanum {
		queue.Enqueue(queueElem{url, string(char), ".*"})
	}

	processGroup := new(sync.WaitGroup)
	processGroup.Add(threads)

	for i := 0; i < threads; i++ {
		go func() {
			for queue.GetLen() > 0 {
				q, _ := queue.Dequeue()

				qElem := q.(queueElem)

				sc, _ := utils.HTTPRequest(requestMethod, qElem.url+qElem.path+"*~1"+qElem.ext+"/1.aspx", "", timeout)
				incrementRequestsCounter(1)

				if sc == 404 {
					if len(qElem.path) < 6 {
						for _, char := range alphanum {
							queue.Enqueue(queueElem{qElem.url, qElem.path + string(char), qElem.ext})
						}
					} else {
						if qElem.ext == ".*" {
							queue.Enqueue(queueElem{qElem.url, qElem.path, ""})
						}
						if qElem.ext == "" {
							if !silent {
								fmt.Println("[Dir] " + qElem.path + "~1")
							}
							dirs = append(dirs, qElem.path+"~1")
						} else if len(qElem.ext) == 5 || !(strings.HasSuffix(qElem.ext, "*")) {
							if !silent {
								fmt.Println("[File] " + qElem.path + "~1" + qElem.ext)
							}
							files = append(files, qElem.path+"~1"+qElem.ext)
						} else {
							for _, char := range alphanum {
								queue.Enqueue(queueElem{qElem.url, qElem.path, utils.TrimLastChar(qElem.ext) + string(char) + "*"})
								if len(qElem.ext) < 4 {
									queue.Enqueue(queueElem{qElem.url, qElem.path, utils.TrimLastChar(qElem.ext) + string(char)})
								}
							}
						}
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
func Run(scanURL string, threads int, silent bool, timeout int) {
	startTime := time.Now()

	if !silent {
		printBanner()
		fmt.Println(" Target: ", scanURL)
		fmt.Println(" Timeout:", timeout)

		fmt.Println(bar + "\n")
	}

	parsedURL, err := url.Parse(scanURL)
	if err != nil {
		if !silent {
			fmt.Println("Malformed URL, skipping...")
		}
		return
	}

	// The URL must end with /, and we ignore anything after ?
	scanURL = parsedURL.Scheme + "://" + parsedURL.Host + strings.TrimSuffix(parsedURL.Path, "/") + "/"
	vulnerable, requestMethod := CheckIfVulnerable(scanURL, timeout)

	if !vulnerable {
		if !silent {
			fmt.Println("Target is not vulnerable")
		}
		return
	}

	dirs, files := Scan(scanURL, requestMethod, threads, silent, timeout)

	fmt.Println("\n" + bar + "\n\nDirectories (" + strconv.Itoa(len(dirs)) + "):\n =======\n" + strings.Join(files, "\n ") + "\n\nFiles (" + strconv.Itoa(len(files)) + "):\n =======\n" + strings.Join(dirs, "\n "))

	endTime := time.Now()
	if !silent {
		fmt.Println("Done! Requests:", requestsCounter, " Time:", endTime.Sub(startTime))
	}
}

// BulkScan prints the output of a bulk scan
func BulkScan(filePath string, threads int, silent bool, timeout int) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		Run(scanner.Text(), threads, silent, timeout)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
