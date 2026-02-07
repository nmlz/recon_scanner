You'll only need a domains.txt file in the same directory where app.py is.
domains.txt must have domains in the following format, separated by newlines:
domain.com
domain1.com
domain3.com

To run just use python3 app.py.

What the code does is the following:

1. domains.txt
2. subdomain enumeration using subfinder 
3. parse subfinder output to a new subdomains.txt file, you may add additional subdomains here but I recommend populating subfinder's provider-config.yaml
4. dnsx resolve of each line in subdomains.txt. here we also split between ipv4 and ipv6
5. naabu scan of each ipv4 ip for common web ports
6. naabu output and subdomains are merged in a new function
7. httpx against the mentioned merged list.

First lines of comments are for future ideas to enhance the scanner, but this serves as a v1. First upgrades should be running katana+uro after step 7 (httpx scan). So that then we can save katana+uro output and httpx output for working sites and scan with nuclei.
