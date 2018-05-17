//
// resolver : A simple dns resolving tool
// Written By : @ice3man (Nizamul Rana)
//
// Distributed Under MIT License
// Copyrights (C) 2018 Ice3man
//

package main

import (
    "bufio"
    "crypto/rand"
    "flag"
    "fmt"
    "io"
    "os"
    "reflect"
    "strings"
    "sync"

    "github.com/bogdanovich/dns_resolver"
)

var wg, wg2 sync.WaitGroup
var ResolversLoaded []string
var WildcardIP []string
var IsWildcard bool
var resolver *dns_resolver.DnsResolver
var WildcardMap map[string]bool
var ValidSubs []string

// Struct containing jobs
type Job struct {
    Work   string
    Result string
}

var (
    Threads       int    // Number of threads to use
    Domain        string // Name of domains
    list          string // List of subdomains found
    output        string // Output file to write to
    comResolvers  string // Comma separated resolvers
    listResolvers string // List of resolvers to use
)

// Resolve a host using dns_resolver lib
func ResolveHost(host string) (ips []string, err error) {
    // In case of i/o timeout
    resolver.RetryTimes = 5

    //fmt.Printf("\n[RESOLVE] Host %s", host)
    ip, err := resolver.LookupHost(host)
    if err != nil {
        return []string{}, err
    }

    var retIPs []string
    for _, host := range ip {
        retIPs = append(retIPs, host.String())
    }

    return retIPs, nil
}

// NewUUID generates a random UUID according to RFC 4122
// Taken from : https://play.golang.org/p/4FkNSiUDMg
//
// Used for bruteforcing and detection of Wildcard Subdomains :-)
func NewUUID() (string, error) {
    uuid := make([]byte, 16)
    n, err := io.ReadFull(rand.Reader, uuid)
    if n != len(uuid) || err != nil {
        return "", err
    }
    // variant bits; see section 4.1.1
    uuid[8] = uuid[8]&^0xc0 | 0x80
    // version 4 (pseudo-random); see section 4.1.3
    uuid[6] = uuid[6]&^0xf0 | 0x40
    return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func SliceExists(slice interface{}, item interface{}) bool {
    s := reflect.ValueOf(slice)

    if s.Kind() != reflect.Slice {
        panic("SliceExists() given a non-slice type")
    }

    for i := 0; i < s.Len(); i++ {
        if s.Index(i).Interface() == item {
            return true
        }
    }

    return false
}

// Check if a ip result contains wildcards
func CheckWildcard(ips []string) (result bool) {
    for _, ip := range ips {
        for _, wildcardIp := range WildcardIP {
            if ip == wildcardIp {
                return true
            }
        }
    }

    // Not wildcard
    return false
}

// Checks if a host returns wildcard ips and returns status with ips returned
func InitWildcard(domain string) (result bool, ips []string) {
    UUIDs := make([]string, 4)

    // Generate 4 random UUIDs
    for i := 0; i < 4; i++ {
        uuid, err := NewUUID()
        if err != nil {
            fmt.Printf("\nerror: %v\n", err)
            os.Exit(1)
        }
        UUIDs[i] = uuid
    }

    for _, uid := range UUIDs {
        attempt := fmt.Sprintf("%s.%s", uid, domain)

        // Currently we check only A records. GoBuster also does that
        // I don't think checking both A and CNAME checking is necessary
        ips, err := ResolveHost(attempt)
        if err != nil {
            continue
        }

        if len(ips) > 0 {
            return true, ips
        }
    }

    return false, ips
}

func analyze(results <-chan *Job) {
    defer wg2.Done()
    for job := range results {
        if job.Result != "" {
            fmt.Printf("\n[+] %s : %s", job.Work, job.Result)
	    ValidSubs = append(ValidSubs, job.Work)
        }
    }
}

func consume(jobs <-chan *Job, results chan<- *Job) {
    defer wg.Done()
    for job := range jobs {
        ips, err := ResolveHost(job.Work)
        if err != nil {
            continue
        }

        if len(ips) <= 0 {
            // We didn't found any ips
            job.Result = ""
            results <- job
        } else {
            if IsWildcard == true {
                result := CheckWildcard(ips)
                if result == true {
                    // We have a wildcard ip
                    job.Result = ""
                    results <- job
                } else {
                    // Not a wildcard subdomains ip
                    job.Result = ips[0]
                    results <- job
                }
            } else {
                job.Result = ips[0]
                results <- job
            }
        }
    }
}

func produce(jobs chan<- *Job) {
    // Read the subdomains from input list and produce
    // jobs for them
    file, err := os.Open(list)
    if err != nil {
        fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
        os.Exit(1)
    }

    defer file.Close()

    scanner := bufio.NewScanner(file)

    for scanner.Scan() {
        // Send the job to the channel
        jobs <- &Job{Work: fmt.Sprintf("%s", scanner.Text()), Result: ""}
    }

    close(jobs)
}

func main() {
    flag.IntVar(&Threads, "t", 10, "Number of threads to use")
    flag.StringVar(&Domain, "d", "", "Domain to resolve subdomains of")
    flag.StringVar(&output, "o", "", "File to output subdomains to")
    flag.StringVar(&list, "l", "", "File to resolve subdomains from")
    flag.StringVar(&comResolvers, "r", "", "Comma-separated list of resolvers to use")
    flag.StringVar(&listResolvers, "rL", "", "File containing list of resolvers to use")

    flag.Parse()

    if list == "" {
        fmt.Printf("\n[!] No Input file specified !\n")
        os.Exit(1)
    }

    if output == "" {
        fmt.Printf("\n[!] No Output file specified !\n")
        os.Exit(1)
    }

    fmt.Printf("[#] Resolve : Subdomains Cleaning tool")
    fmt.Printf("\n[#] Written By : @ice3man")
    fmt.Printf("\n[#] Github : github.com/ice3man543")

    if comResolvers != "" {
        // Load the Resolvers from list
        setResolvers := strings.Split(comResolvers, ",")

        for _, resolver := range setResolvers {
            ResolversLoaded = append(ResolversLoaded, resolver)
        }
    }

    if listResolvers != "" {
        // Load the resolvers from file
        file, err := os.Open(listResolvers)
        if err != nil {
            fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
            os.Exit(1)
        }

        defer file.Close()

        scanner := bufio.NewScanner(file)

        for scanner.Scan() {
            // Send the job to the channel
            ResolversLoaded = append(ResolversLoaded, scanner.Text())
        }
    }

    // Use the default resolvers
    if comResolvers == "" && listResolvers == "" {
        ResolversLoaded = append(ResolversLoaded, "1.1.1.1")
        ResolversLoaded = append(ResolversLoaded, "8.8.8.8")
        ResolversLoaded = append(ResolversLoaded, "8.8.4.4")
    }

    resolver = dns_resolver.New(ResolversLoaded)

    // Initialize Wildcard Subdomains
    IsWildcard, WildcardIP = InitWildcard(Domain)
    if IsWildcard == true {
        WildcardMap := make(map[string]bool)
        for i := 0; i < len(WildcardIP); i++ {
            WildcardMap[WildcardIP[i]] = true
        }
        fmt.Printf("\n[~] Wildcard IPs found at %s. IP(s) %s", Domain, WildcardIP)
    }

    jobs := make(chan *Job, 100)    // Buffered channel
    results := make(chan *Job, 100) // Buffered channel

    // Start consumers:
    for i := 0; i < Threads; i++ {
        wg.Add(1)
        go consume(jobs, results)
    }

    // Start producing
    go produce(jobs)

    // Start analyzing
    wg2.Add(1)
    go analyze(results)

    wg.Wait()
    close(results)

    wg2.Wait()

    file, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
     if err != nil {
          return 
     }

     defer file.Close()

     for _, subdomain := range ValidSubs {
          _, err := io.WriteString(file, subdomain+"\n")
          if err != nil {
               return
          }
     }

     return
}
