package scanner

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/enriquebris/goconcurrentqueue"
	"github.com/icza/gox/timex"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/sw33tLie/sns/pkg/whttp"
)

var magicFinalParts = [12]string{"\\a.aspx", "\\a.asp", "/a.aspx", "/a.asp", "/a.shtml", "/a.asmx", "/a.ashx", "/a.config", "/a.php", "/a.jpg", "/webresource.axd", "/a.xxx"}
var requestMethods = [7]string{"OPTIONS", "GET", "POST", "HEAD", "TRACE", "TRACK", "DEBUG"}
// english frequency order
var alphanum = "etaoinsrhdlucmfywgpbvkxqjz0123456789_-"

const (
	logoBase64 = "ICBfX18gXyBfXyAgX19fCiAvIF9ffCAnXyBcLyBfX3wgICAgICAgICAgIElJUyBTaG9ydG5hbWUgU2Nhbm5lcgogXF9fIFwgfCB8IFxfXyBcICAgICAgICAgICAgICAgICAgICAgYnkgc3czM3RMaWUKIHxfX18vX3wgfF98X19fLyB2MS4yLjE="
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
	num     int
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

var requestsCounter, errorsCounter int
var requestsCounterMutex, errorsCounterMutex sync.Mutex

func incrementRequestsCounter(by int) {
	requestsCounterMutex.Lock()
	defer requestsCounterMutex.Unlock()
	requestsCounter += by
}

func incrementErrorsCounter(by int) {
	errorsCounterMutex.Lock()
	defer errorsCounterMutex.Unlock()
	errorsCounter += by
}

func printBanner() {
	logo, _ := base64.StdEncoding.DecodeString(logoBase64)
	fmt.Println(string(logo) + "\n" + bar + "\n")
}

func Abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func TrimLastChar(s string) string {
	r, size := utf8.DecodeLastRuneInString(s)
	if r == utf8.RuneError && (size == 0 || size == 1) {
		size = 0
	}
	return s[:len(s)-size]
}

func CheckIfVulnerable(scanURL string, headers []string, timeout int, threads int, checkOnly bool, bulkCheck bool) (result bool, method string) {
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

				wHeaders, customHost := whttp.MakeCustomHeaders(headers)
				validRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
					URL:        check.url1,
					Method:     check.method,
					Headers:    wHeaders,
					CustomHost: customHost,
				}, http.DefaultClient)

				if err != nil {
					incrementErrorsCounter(1)
					continue
				}

				invalidRes, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
					URL:        check.url2,
					Method:     check.method,
					Headers:    wHeaders,
					CustomHost: customHost,
				}, http.DefaultClient)

				if err != nil {
					incrementErrorsCounter(1)
					continue
				}

				incrementRequestsCounter(2)

				if validRes.StatusCode != invalidRes.StatusCode && !(acceptedDiffLength >= 0 && Abs(len(invalidRes.BodyString)-len(validRes.BodyString)) <= acceptedDiffLength) {
					vuln = true
					vulnMethod = check.method

					if checkOnly {
						fmt.Println("[VULNERABLE-" + vulnMethod + "] " + scanURL)
						if !bulkCheck {
							os.Exit(0)
						}
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

func Scan(url string, headers []string, requestMethod string, threads int, silent bool, nocolor bool) (files []string, dirs []string) {
	queue := goconcurrentqueue.NewFIFO()
	cmap.New()
	m := cmap.New()

	for _, char := range alphanum {
		queue.Enqueue(queueElem{url, string(char), ".*", 1, false})
	}

	wHeaders, customHost := whttp.MakeCustomHeaders(headers)

	processGroup := new(sync.WaitGroup)
	processGroup.Add(threads)

	for i := 0; i < threads; i++ {
		go func() {
			for queue.GetLen() > 0 {
				q, err := queue.Dequeue()
				if err != nil {
					continue
				}
				qElem := q.(queueElem)

				if !silent {
					fmt.Printf("\r /" + qElem.path)
				}

				res, err := whttp.SendHTTPRequest(&whttp.WHTTPReq{
					URL:        qElem.url + qElem.path + "*~" + strconv.Itoa(qElem.num) + qElem.ext + "/1.aspx",
					Method:     requestMethod,
					Headers:    wHeaders,
					CustomHost: customHost,
				}, http.DefaultClient)

				if err != nil {
					incrementErrorsCounter(1)
					continue
				}

				incrementRequestsCounter(1)
				found := res.StatusCode == 404

				if found {
					if len(qElem.path) < 6 && !qElem.shorter {
						for _, char := range alphanum {
							queue.Enqueue(queueElem{qElem.url, qElem.path + string(char), qElem.ext, qElem.num, qElem.shorter})
						}
					} else {
						if qElem.ext == ".*" {
							queue.Enqueue(queueElem{qElem.url, qElem.path, "", qElem.num, qElem.shorter})
						}
						if qElem.ext == "" {
							fileName := findKnownFile(qElem.path + "~" + strconv.Itoa(qElem.num))
							if !silent {
								color := ""
								if !nocolor {
									color = COLOR_GREEN
								}
								fmt.Println("\r " + color + "- " + fileName + " (Directory)" + COLOR_RESET)
							} else {
								fmt.Println("  " + fileName + " (Directory)")
							}
							// checking if more than one dir exists with prefix
							if qElem.num < 9 && len(qElem.path) == 6 {
								queue.Enqueue(queueElem{qElem.url, qElem.path, qElem.ext, qElem.num+1, qElem.shorter})
							}
							dirs = append(dirs, fileName)
						} else if len(qElem.ext) == 5 || !(strings.HasSuffix(qElem.ext, "*")) {
							fileName := findKnownFile(qElem.path + "~" + strconv.Itoa(qElem.num) + qElem.ext)
							if !silent {
								color := ""
								if !nocolor {
									color = COLOR_GREEN
								}
								fmt.Println("\r " + color + "- " + fileName + " (File)" + COLOR_RESET)
							} else {
								fmt.Println("  " + fileName + " (File)")
							}
							// checking if more than one file exists with prefix
							if qElem.num < 9 && len(qElem.path) == 6 {
								queue.Enqueue(queueElem{qElem.url, qElem.path, qElem.ext, qElem.num+1, qElem.shorter})
							}
							files = append(files, fileName)
						} else {
							for _, char := range alphanum {
								queue.Enqueue(queueElem{qElem.url, qElem.path, TrimLastChar(qElem.ext) + string(char) + "*", qElem.num, qElem.shorter})
								if len(qElem.ext) < 4 {
									queue.Enqueue(queueElem{qElem.url, qElem.path, TrimLastChar(qElem.ext) + string(char), qElem.num, qElem.shorter})
								}
							}
						}
					}
				}

				// logic for identifying files with len < 6
				prevPath := TrimLastChar(qElem.path)
				if tmp, ok := m.Get(prevPath); ok {
					if found {
						m.Set(prevPath, mapElem{tmp.(mapElem).count - 1, true})
					} else {
						m.Set(prevPath, mapElem{tmp.(mapElem).count - 1, tmp.(mapElem).found})
					}
					if tmp.(mapElem).count == 0 && tmp.(mapElem).found == false {
						// we found a file with a len(shortname) < 6
						queue.Enqueue(queueElem{qElem.url, prevPath, ".*", qElem.num, true})
					}
				} else {
					m.Set(prevPath, mapElem{len(alphanum) - 2, found})
				}
			}
			processGroup.Done()
		}()
	}
	processGroup.Wait()

	sort.Strings(files)

	return files, dirs
}

// Run prints the output of a scan
func Run(scanURL string, headers []string, threads int, silent bool, timeout int, nocolor bool, proxy string) {
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

		if len(headers) > 0 {
			fmt.Print(" Header(s): ")
			for _, h := range headers {
				fmt.Print(strings.Split(h, ":")[0] + ", ")
			}
			fmt.Println()

		}

		fmt.Println(bar + "\n")
	}

	vulnerable, requestMethod := CheckIfVulnerable(scanURL, headers, timeout, threads, false, false)

	if !vulnerable {
		if !silent {
			fmt.Println("Target is not vulnerable. Requests sent: "+strconv.Itoa(requestsCounter)+", Errors:", errorsCounter)
		}
		return
	}

	if silent {
		fmt.Println(scanURL)
	}

	Scan(scanURL, headers, requestMethod, threads, silent, nocolor)

	endTime := time.Now()
	if !silent {
		fmt.Println("\r"+bar+"\nDone! Requests: "+strconv.Itoa(requestsCounter)+", Errors: "+strconv.Itoa(errorsCounter), ", Time:", timex.Round(endTime.Sub(startTime), 2))
	}
}

// BulkScan prints the output of a bulk scan
func BulkScan(filePath string, headers []string, threads int, silent bool, timeout int, nocolor bool, proxy string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		Run(scanner.Text(), headers, threads, silent, timeout, nocolor, proxy)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func BulkCheck(filePath string, headers []string, threads int, timeout int, nocolor bool) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		CheckIfVulnerable(scanner.Text(), headers, timeout, threads, true, true)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

var knownFiles = map[string]string{
	"web~1.con*": "web.config",
	"aspnet~1":   "aspnet_client",
	"iissta~1.htm": "iisstart.html",
}

func findKnownFile(shortName string) (fullName string) {
	if val, ok := knownFiles[shortName]; ok {
		return val
	}
	return shortName
}
