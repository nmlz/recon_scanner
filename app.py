#Comments
# 1. We should add our API keys from services we have to subfinder/provider-config.yaml, in order to get better output. https://projectdiscovery.io/blog/do-you-really-know-subfinder-an-in-depth-guide-to-all-features-of-subfinder-beginner-to-advanced#specifying-a-dns-resolver
# 2. naabu ips output won't be used here, we should cross it with our current inventory, merge, and then scan with masscan -> if ports > 10 -> shodan
#                                                                                                                          -> else -> nmap
# 3. httpx flags are conservative, in case we find a need for extra info we can add, i.e screenshots, hash, etc.
# 4. we should add a seen() function that works with a hash() function. If the hash of domains.txt changed, then we scan the new domains that weren't seen by seen(). If not, we don't, that's just an idea to not rely on manual work only.
# 5. We'll only scan ipv4 IPs, we should see what do we do with IPv6.

import subprocess
import json
import os

domain_list = "domains.txt"

def subdomain_enumeration():
    subfinder_output = "subfinder_output.json"
    subfinder_command = ["subfinder", "-dL", domain_list, "-oJ", "-o", subfinder_output, "-silent"]
    subprocess.run(subfinder_command, check=True)
    return subfinder_output

def subfinder_output_to_subdomain_only(subfinder_output):
    subdomain_list = "subdomains.txt"
    hosts = set()
    with open(subfinder_output, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            host = entry.get("host")
            if host:
                hosts.add(host)
    with open(subdomain_list, "w", encoding="utf-8") as out:
        for h in sorted(hosts):
            out.write(h + "\n")
    print(f"Wrote {len(hosts)} subdomains to {subdomain_list}")
    return(subdomain_list)

# I believe we should run this once every x months, first for all subdomains, then only for the new ones. 
def resolver(subdomain_list):
    dnsx_output = "dnsx_output.txt"
    dnsx_command = ["dnsx", "-l", subdomain_list, "-a", "-aaaa", "-cname", "-resp-only", "-silent", "-o", dnsx_output]
    subprocess.run(dnsx_command, check=True)
    return dnsx_output

#This is just to split dnsx output between ipv4 and ipv6 lists
def parse_naabu_output(dnsx_output):
    ipv4 = set()
    ipv6 = set()
    ipv4_file="ipv4.txt"
    ipv6_file="ipv6.txt"

    with open(dnsx_output, "r", encoding="utf-8") as f:
        for line in f:
            entry = json.loads(line)

            for ip in entry.get("a", []):
                ipv4.add(ip)

            for ip in entry.get("aaaa", []):
                ipv6.add(ip)

    with open(ipv4_file, "w", encoding="utf-8") as f:
        for ip in sorted(ipv4):
            f.write(ip + "\n")

    with open(ipv6_file, "w", encoding="utf-8") as f:
        for ip in sorted(ipv6):
            f.write(ip + "\n")

    print(f"[+] IPv4: {len(ipv4)} | IPv6: {len(ipv6)}")

    return ipv4_file, ipv6_file

#We'll only scan ipv4 IPs, we should see what do we do with IPv6.
def naabu(ipv4_file):
    naabu_output = "naabu_output.txt"
    naabu_command = ["naabu", "-l", ipv4_file, "-p", "8080,8443,8000,8888,9000,9443,10443", "-rate", "200", "-silent", "-o", naabu_output]
    return naabu_output


def sub_and_naabu_merge(subdomain_list, naabu_output, output_file="httpx_targets.txt"):
    targets = set()
    with open(subdomain_list, "r", encoding="utf-8") as subdomain_file:
        for line in subdomain_file:
            sub = line.strip()
            if sub:
                targets.add(sub)
    if os.path.isfile(naabu_output):
        with open(naabu_output, "r", encoding="utf-8") as naabu_file:
            for line in naabu_file:
                ip = line.strip()
                if ip:
                    targets.add(ip)

    with open(output_file, "w", encoding="utf-8") as output:
        for i in sorted(targets):
            output.write(i + "\n")

    print(f"[+] httpx targets written: {len(targets)} → {output_file}")
    return output_file

# Not sure about -follow-redirects, set up -maxr 2 just in case there is a sso that causes a lot of redirects, we don't care much about those
# Httpx has a TON of functionalities, like screenshot, saving hash, and more, this is a basic scan that should serve its purpose during the first scans without adding a lot of overhead
def httpx(httpx_input_file):
    httpx_output = "httpx_output.txt"
    httpx_command = ["httpx", "-l", httpx_input_file, "-status-code", "-tech-detect", "-title", "-t", "100", "-follow-redirects", "-location", "-timeout", "5", "-maxr", "2", "-j", "-o", httpx_output]
    subprocess.run(httpx_command, check=True)
    return(httpx_output)

def main():
    output = subdomain_enumeration()
    subdomain_list = subfinder_output_to_subdomain_only(output)
    ips = resolver(subdomain_list)
    naabu_output = naabu(ips)
    httpx_input_file = sub_and_naabu_merge(subdomain_list, naabu_output)
    httpx(httpx_input_file)
    print("End")

if __name__ == '__main__':
    main()
