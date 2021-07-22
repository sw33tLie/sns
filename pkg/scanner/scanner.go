package scanner

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/enriquebris/goconcurrentqueue"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/sw33tLie/sns/internal/utils"
)

var magicFinalParts = [12]string{"\\a.aspx", "\\a.asp", "/a.aspx", "/a.asp", "/a.shtml", "/a.asmx", "/a.ashx", "/a.config", "/a.php", "/a.jpg", "/webresource.axd", "/a.xxx"}
var requestMethods = [7]string{"OPTIONS", "GET", "POST", "HEAD", "TRACE", "TRACK", "DEBUG"}
var alphanum = "abcdefghijklmnopqrstuvwxyz0123456789_-"

const (
	logoBase64 = "ICBfX18gXyBfXyAgX19fCiAvIF9ffCAnXyBcLyBfX3wgICAgICAgICAgIElJUyBTaG9ydG5hbWUgU2Nhbm5lcgogXF9fIFwgfCB8IFxfXyBcICAgICAgICAgICAgICAgICAgICAgYnkgc3czM3RMaWUKIHxfX18vX3wgfF98X19fLyB2MS4x"
	bar        = "________________________________________________"
)

// Colors
const (
	COLOR_RESET  = "\033[0m"
	COLOR_RED    = "\033[31m"
	COLOR_GREEN  = "\033[32m"
	COLOR_YELLOW = "\033[33m"
	COLOR_BLUE   = "\033[34m"
	COLOR_PURPLE = "\033[35m"
	COLOR_CYAN   = "\033[36m"
	COLOR_GRAY   = "\033[37m"
	COLOR_WHITE  = "\033[97m"
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

type checker struct {
	method string
	url1   string
	url2   string
}

var requestsCounter int
var requestsCounterMutex sync.Mutex

func incrementRequestsCounter(by int) {
	requestsCounterMutex.Lock()
	defer requestsCounterMutex.Unlock()
	requestsCounter += by
}

func printBanner() {
	logo, _ := base64.StdEncoding.DecodeString(logoBase64)
	fmt.Println(string(logo) + "\n" + bar + "\n")
}

func CheckIfVulnerable(scanURL string, timeout int, threads int, checkOnly bool) (result bool, method string) {

	parsedURL, err := url.Parse(scanURL)
	if err != nil {
		println("Malformed URL, skipping...")
		return
	}

	// The URL must end with /, and we ignore anything after ?
	scanURL = parsedURL.Scheme + "://" + parsedURL.Host + strings.TrimSuffix(parsedURL.Path, "/") + "/"

	checks := make(chan *checker, threads)
	processGroup := new(sync.WaitGroup)
	processGroup.Add(threads)

	asteriskSymbol := "*"
	acceptedDiffLength := 10

	vuln := false
	vulnMethod := ""
	for i := 0; i < threads; i++ {
		go func() {
			for {
				check := <-checks
				if check == nil {
					break
				}

				validStatus, validBody := utils.HTTPRequest(check.method, check.url1, "")
				invalidStatus, invalidBody := utils.HTTPRequest(check.method, check.url2, "")
				incrementRequestsCounter(2)

				if validStatus != invalidStatus && !(acceptedDiffLength >= 0 && utils.Abs(len(invalidBody)-len(validBody)) <= acceptedDiffLength) {
					vuln = true
					vulnMethod = check.method

					if checkOnly {
						fmt.Println("[VULNERABLE-" + vulnMethod + "] " + scanURL)
						os.Exit(0)
					}
				}
			}
			processGroup.Done()
		}()
	}

	for _, requestMethod := range requestMethods {
		for _, magicFinalPart := range magicFinalParts {
			checks <- &checker{
				method: requestMethod,
				url1:   scanURL + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart,
				url2:   scanURL + "/1234567890" + asteriskSymbol + "~1" + asteriskSymbol + magicFinalPart,
			}
		}
	}

	close(checks)
	processGroup.Wait()

	if checkOnly {
		println("Target is not vulnerable")
	}
	return vuln, vulnMethod
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
							fileName := qElem.path + "~1" + qElem.ext

							if !silent {
								color := ""
								if fileName == "web~1.con*" {
									fileName = "web.config"
									color = COLOR_GREEN
								}
								fmt.Println("\r " + color + "- " + fileName + " (File)" + COLOR_RESET)
							}
							files = append(files, fileName)
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

	vulnerable, requestMethod := CheckIfVulnerable(scanURL, timeout, threads, false)

	if !vulnerable {
		if !silent {
			fmt.Println("Target is not vulnerable")
		}
		return
	}

	Scan(scanURL, requestMethod, threads, silent)

	endTime := time.Now()
	if !silent {
		fmt.Println(bar+"\nDone! Requests:", requestsCounter, " Time:", endTime.Sub(startTime))
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

func BulkCheck(filePath string, threads int, timeout int) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fmt.Println("CHEKC")
		CheckIfVulnerable(scanner.Text(), timeout, threads, true)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
