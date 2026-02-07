You'll only need a domains.txt file in the same directory where app.py is.
domains.txt must have domains in the following format, separated by newlines:
domain.com
domain1.com
domain3.com

To run just use python3 app.py.

What the code does is the following:

domains.txt -> subdomain enumeration using subfinder -> parse subfinder output to a new subdomains.txt file, you may add additional subdomains here but I recommend populating subfinder's provider-config.yaml -> dnsx resolve of each line in subdomains.txt. here we also split between ipv4 and ipv6 -> naabu scan of each ipv4 ip for common web ports -> naabu output and subdomains are merged in a new function -> httpx against the mentioned merged list.

First lines of comments are for future ideas to enhance the scanner, but this serves as a v1.
