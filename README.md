# logfilter
Filter logs from a log file.

It reads a file or stdin line by line and expects to have data in a CSV style. For now, the log fields are specified below in the usage section. This is a follow up on the work I did with [fw1-loggrabber here](http://gammenion.github.io/post/fw1-loggrabber/)

The filtering in this version only removes non-RFC1918 destination IP addresses from processing. Everything else is processed and returned.

This program is written in Go. You can run it directly like below or compile it with `go build logfilter.go`

### go run logfilter.go -h

```
Usage:
  -f string
    	Log file to use. If none is used, read from stdin
  -h	Print help and exit
  -o string
    	Order by: time, srcip, srcport, dstip, dstport (default "time")
  -s string
    	Character to split (default ";")

Experimental exercise with Check Point logs coming from fw1-loggrabber - expected format:

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
```

## To Do
Many things can be done to improve this, such as:

* Add more filters to processing and choose them with command line params
* Generalize the file format to allow anything to be processed (what if src ip is in position 7 instead of 8 - imagine multiple log files from different log source technologies)
* Create more sorters
* Create multiple ways of output. The current version prints the whole data structure line by line
* Expand the data structure to accommodate random number of values as defined by command line arguments
* Ensure IP address name resolution for each processed IP address, cache it for a certain timeout
* Remove useless lines, such as empty or beginning with a comment

## Example
Log file:  
```bash
2016-04-06 16:20:39|action=accept|orig=11.22.33.44|inzone=Internal|outzone=Internal|rule=31|rule_name=random rule name|service_id=RPC|10.55.66.220|51223|11.20.30.40|139|proto=tcp|src_machine_name=mymachine@gama.int|snid=xxxxxx|dst_machine_name=hismachine@gama.int
2016-04-06 18:20:39|action=accept|orig=11.22.33.44|inzone=Internal|outzone=Internal|rule=31|rule_name=random rule name|service_id=MS_135|10.33.44.110|54472|12.13.14.15|135|proto=tcp|src_machine_name=mymachine@gama.int|snid=xxxxx|dst_machine_name=hismachine@gama.int
```

Then running:  
```
> go run logfilter.go -f test.log -s \| -o srcip
[Time: 2016-04-06 16:20:39
Source IP: 10.109.120.225
Source Port: 51223
Destination IP: 11.20.30.40
Destination Port: 139
 Time: 2016-04-06 18:20:39
Source IP: 10.109.4.115
Source Port: 54472
Destination IP: 12.13.14.15
Destination Port: 135
```