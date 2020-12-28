package scanner

import (
	"fmt"
	"strings"
	"sync"

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
			// Logic
			fmt.Println(validStatus)
			fmt.Println(invalidStatus)

			if validStatus != invalidStatus && !(acceptedDiffLength >= 0 && utils.Abs(len(invalidBody)-len(validBody)) <= acceptedDiffLength) {
				return false, requestMethod
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

// Scan scans a single URL
func Scan(url string, threads int) {
	PrintBanner()
	fmt.Println("Scanning: " + url)
	vulnerable, vulnerableMethod := CheckIfVulnerable(url)
	fmt.Println(vulnerable)

	// Add to queue
	queue := goconcurrentqueue.NewFIFO()

	for _, char := range alphanum {
		queue.Enqueue(queueElem{url, string(char), ".*"})
	}

	processGroup := new(sync.WaitGroup)
	processGroup.Add(threads)

	fmt.Println(threads)
	var dirs []string
	var files []string

	for i := 0; i < threads; i++ {
		go func() {

			for {
				q, _ := queue.Dequeue()

				// If queue is empty
				if q == nil {
					break
				}

				qElem := q.(queueElem)

				sc, _ := utils.HTTPRequest(vulnerableMethod, qElem.url+qElem.path+"*~1"+qElem.ext+"/1.aspx", "")
				//fmt.Println(q)

				//status = self._get_status(url + '*~1' + ext + '/1.aspx')
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
							fmt.Println("FOUND DIRECTORY")
							dirs = append(dirs, qElem.path+"~1")
						} else if len(qElem.ext) == 5 || !(strings.HasSuffix(qElem.ext, "*")) {
							fmt.Println("FOUND FILE")
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

	fmt.Println(dirs)
	fmt.Println(files)
}

// BulkScan scans multiple targets
func BulkScan(filePath string) {
	fmt.Println("Bulk Scanning: " + filePath)
}
