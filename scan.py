import nmap
def scan_target(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                print(f"Port: {port} \t State: {nm[host][proto][port]['state']}")
def main():
    ip = input("Digite o IP do host: ")
    scan_target(ip)

if __name__ == "__main__":
    main()
