package fdexplorer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

var (
	pid  int
	ppid int

	states = map[string]string{
		"01": "TCP_ESTABLISHED",
		"02": "TCP_SYN_SENT",
		"03": "TCP_SYN_RECV",
		"04": "TCP_FIN_WAIT1",
		"05": "TCP_FIN_WAIT2",
		"06": "TCP_TIME_WAIT",
		"07": "TCP_CLOSE",
		"08": "TCP_CLOSE_WAIT",
		"09": "TCP_LAST_ACK",
		"0A": "TCP_LISTEN",
		"0B": "TCP_CLOSING",
		"0C": "TCP_MAX_STATES",
	}
)

func getFdsForPid(pid int) {
	folder := fmt.Sprintf("/proc/%d/fdinfo", pid)
	content, err := ioutil.ReadDir(folder)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, file := range content {
		if !file.IsDir() {
			fn := fmt.Sprintf("%s/%s", folder, file.Name())
			fmt.Printf("Reading %s\n", fn)
			bytes, err := ioutil.ReadFile(fn)
			if err == nil {
				fileContent := string(bytes)
				fmt.Println(fileContent)
			} else {
				fmt.Println(err)
			}
		} else {
			fmt.Printf("%s is a dir\n", file.Name())
		}
	}
	fmt.Printf("\n--> %d descriptors open\n", len(content))
}

// NodePort Combination of address, port and state
type NodePort struct {
	IPAddr string
	Port   int64
	State  string
}

// NodePortCounter collection of all discovered node ports with counter
type NodePortCounter struct {
	NodePort NodePort
	Count    int
}

var ErrInvalidNodePortFormat = errors.New("invalid node port format")

func toNodePort(entry string) (NodePort, error) {
	parts := strings.Split(entry, ":")
	if len(parts) != 2 {
		return NodePort{}, ErrInvalidNodePortFormat
	}
	port, err := strconv.ParseInt("0x"+parts[1], 0, 64)
	if err != nil {
		return NodePort{}, err
	}
	ipAddr := parts[0]
	digits, err := hex.DecodeString(ipAddr)
	if err != nil {
		return NodePort{}, err
	}
	if len(digits) != 16 {
		return NodePort{}, ErrInvalidNodePortFormat
	}
	ipAddr = fmt.Sprintf("%d.%d.%d.%d", digits[15], digits[14], digits[13], digits[12])
	return NodePort{ipAddr, port, ""}, nil
}

func toNodePortV4(entry string) (NodePort, error) {
	parts := strings.Split(entry, ":")
	if len(parts) != 2 {
		return NodePort{}, ErrInvalidNodePortFormat
	}
	port, err := strconv.ParseInt("0x"+parts[1], 0, 64)
	if err != nil {
		return NodePort{}, err
	}
	ipAddr := parts[0]
	digits, err := hex.DecodeString(ipAddr)
	if err != nil {
		return NodePort{}, err
	}
	if len(digits) != 4 {
		return NodePort{}, ErrInvalidNodePortFormat
	}
	ipAddr = fmt.Sprintf("%d.%d.%d.%d", digits[3], digits[2], digits[1], digits[0])
	return NodePort{ipAddr, port, ""}, nil
}

func getTCP(pid int) map[string]NodePortCounter {
	results := make(map[string]NodePortCounter)
	fileName := fmt.Sprintf("/proc/%d/net/tcp", pid)
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return results
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		columns := strings.Split(line, " ")
		for i, column := range columns {
			if i > 0 {
				if len(column) == 13 && len(columns[i-1]) == 13 {
					remoteAddress := column
					//localAddress := columns[i-1]
					state := "UNK"
					if v, ok := states[columns[i+1]]; ok {
						state = v
					}
					remote, err := toNodePortV4(remoteAddress)
					if err != nil {
						fmt.Printf("Error converting remote %s: %s\n", remoteAddress, err)
						continue
					}
					//local, err := toNodePortV4(localAddress)
					//if err != nil {
					//	fmt.Printf("Error converting local %s: %s\n", localAddress, err)
					//	continue
					//}
					key := fmt.Sprintf("%s_%d_%s", remote.IPAddr, remote.Port, state)
					results[key] = NodePortCounter{
						NodePort: NodePort{
							IPAddr: remote.IPAddr,
							Port:   remote.Port,
							State:  state,
						},
						Count: results[key].Count + 1,
					}
				}
			}
		}
	}
	fmt.Printf("\n--> %d descriptors open\n", len(lines))
	return results
}

func getTCP6(pid int) map[string]NodePortCounter {
	results := make(map[string]NodePortCounter)
	fileName := fmt.Sprintf("/proc/%d/net/tcp6", pid)
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println("Failed to fetch tcp6 file")
		return results
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		columns := strings.Split(line, " ")
		for i, column := range columns {
			if i > 0 {
				if len(column) == 37 && len(columns[i-1]) == 37 {
					remoteAddress := column
					localAddress := columns[i-1]
					remote, err := toNodePort(remoteAddress)
					if err != nil {
						fmt.Printf("Error converting remote %s: %s\n", remoteAddress, err)
						continue
					}
					local, err := toNodePort(localAddress)
					if err != nil {
						fmt.Printf("Error converting local %s: %s\n", localAddress, err)
						continue
					}
					key := fmt.Sprintf("%s_%d", remote.IPAddr, remote.Port)
					results[key] = NodePortCounter{
						NodePort: NodePort{
							IPAddr: remote.IPAddr,
							Port:   remote.Port,
						},
						Count: results[key].Count + 1,
					}
					fmt.Printf("%v\t%v\n", remote, local)
				}
			}
		}
	}
	fmt.Printf("\n--> %d descriptors open\n", len(lines))
	return results
}

// GetSummary retrieves the list of all remote connections
func GetSummary() map[string]NodePortCounter {
	if pid == 0 {
		pid = os.Getpid()
	}
	//getFdsForPid(pid)
	return getTCP(pid)
	/*for _, entry := range counters {
		fmt.Printf("[%17s] %20s:%d\t%d\n", entry.NodePort.State, entry.NodePort.IPAddr, entry.NodePort.Port, entry.Count)
	}*/
}
