// Log Filter

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

var (
	version     = "0.1"  // Code version
	splitchar   = ";"    // Character used to split the log fields
	orderby     = "time" // Sort output by
	ipfilter192 *net.IPNet
	ipfilter172 *net.IPNet
	ipfilter10  *net.IPNet
)

type logLine struct {
	time    string
	srcip   net.IP
	srcport int
	dstip   net.IP
	dstport int
}

func (l logLine) String() string {
	ret := "Time: " + l.time + "\n"
	ret += "Source IP: " + l.srcip.String() + "\n"
	ret += "Source Port: " + strconv.Itoa(l.srcport) + "\n"
	ret += "Destination IP: " + l.dstip.String() + "\n"
	ret += "Destination Port: " + strconv.Itoa(l.dstport) + "\n"
	return ret
}

// printUsage: Print the help and exit
func printUsageandExit(err error) {
	if err != nil {
		fmt.Println(err, "\n")
	}
	fmt.Println("logfilter " + version + " - Filter logs from a log file")
	fmt.Println()
	fmt.Println("Usage:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Experimental exercise with Check Point logs coming from fw1-loggrabber - expected format:")
	fmt.Println(`
File Format: Firewall Blade
0: time
1: action
2: fw gateway
3: inzone
4: outzone
5: rule number
6: rule name
7: service_id
8: src ip
9: src port
10: dst ip
11: dst port
12: protocol
13: src machine name
14: snid
15: dst machine name
`)
	os.Exit(0)
}

// File Format: Firewall Blade
// 0: time
// 1: action
// 2: fw gateway
// 3: inzone
// 4: outzone
// 5: rule number
// 6: rule name
// 7: service_id
// 8: src ip
// 9: src port
// 10: dst ip
// 11: dst port
// 12: protocol
// 13: src machine name
// 14: snid
// 15: dst machine name
func filter(line string) (logLine, bool) {
	var ret logLine
	var err bool

	linesl := strings.Split(line, splitchar)
	// Loop over the parameters in the line
	for arg := range linesl {
		param := linesl[arg]
		switch arg {
		case 0: // time
			ret.time = param

		case 8: // src ip
			ret.srcip = net.ParseIP(param)
			if ret.srcip == nil {
				err = true
				break
			}

		case 9: // src port
			ret.srcport, _ = strconv.Atoi(param)

		case 10: // dst ip
			ip := net.ParseIP(param)
			// Test if IP is invalid and if it's within RFC1918
			if ip == nil || ipfilter192.Contains(ip) || ipfilter172.Contains(ip) || ipfilter10.Contains(ip) {
				err = true
				break
			}
			ret.dstip = ip

		case 11: // dst port
			ret.dstport, _ = strconv.Atoi(param)
		}
	}
	return ret, err
}

// Sorting - thanks to https://golang.org/pkg/sort/
type By func(l1, l2 *logLine) bool

func (by By) Sort(logline []logLine) {
	logsorter := &logSorter{
		logs: logline,
		by:   by,
	}
	sort.Sort(logsorter)
}

type logSorter struct {
	logs []logLine
	by   func(l1, l2 *logLine) bool
}

// Implementing Len, Swap and Less interfaces for logSorter to make sorting work
func (l *logSorter) Len() int {
	return len(l.logs)
}
func (l *logSorter) Swap(i, j int) {
	l.logs[i], l.logs[j] = l.logs[j], l.logs[i]
}
func (l *logSorter) Less(i, j int) bool {
	return l.by(&l.logs[i], &l.logs[j])
}

// Sorters
func sortBySrcPort(l1, l2 *logLine) bool {
	return l1.srcport < l2.srcport
}
func sortByDstPort(l1, l2 *logLine) bool {
	return l1.dstport < l2.dstport
}
func sortByTime(l1, l2 *logLine) bool {
	return l1.time < l2.time
}
func sortBySrcIP(l1, l2 *logLine) bool {
	return l1.srcip.String() < l2.srcip.String()
}
func sortByDstIP(l1, l2 *logLine) bool {
	return l1.dstip.String() < l2.dstip.String()
}

func main() {
	var file *os.File // File descriptor of the log file

	var filename = flag.String("f", "", "Log file to use. If none is used, read from stdin")
	flag.StringVar(&splitchar, "s", ";", "Character to split")
	flag.StringVar(&orderby, "o", "time", "Order by: time, srcip, srcport, dstip, dstport")
	help := flag.Bool("h", false, "Print help and exit")
	flag.Parse()

	if *help == true {
		printUsageandExit(nil)
	}

	if *filename == "" {
		file = os.Stdin
		fmt.Println("Reading from stdin...")
	} else {
		var err error
		file, err = os.Open(*filename)
		if err != nil {
			log.Fatalln(err)
		}
		defer file.Close()
	}

	// IP Filters:
	_, ipfilter192, _ = net.ParseCIDR("192.168.0.0/16")
	_, ipfilter172, _ = net.ParseCIDR("172.16.0.0/12")
	_, ipfilter10, _ = net.ParseCIDR("10.0.0.0/8")

	// Read every line
	var logline []logLine
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// For every line, run the filter
		ret, err := filter(scanner.Text())
		if err != true {
			logline = append(logline, ret)
		} else {
			fmt.Println("Error parsing")
		}
	}

	// Apply sorting
	switch orderby {
	case "time":
		By(sortByTime).Sort(logline)
	case "srcip":
		By(sortBySrcIP).Sort(logline)
	case "srcport":
		By(sortBySrcPort).Sort(logline)
	case "dstip":
		By(sortByDstIP).Sort(logline)
	case "dstport":
		By(sortByDstPort).Sort(logline)
	}
	fmt.Println(logline)
}
