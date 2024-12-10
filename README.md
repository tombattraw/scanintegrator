nmap / FFUF integrator

Requires python3-xmltodict

Scans with nmap, then uses nmap results to run an extension scan, then wordlists with each extension against each revealed web port.

Intended for use by people comfortable with pentesting and Python. May need manual adjustment depending on web server, target, and how to reach it.
Don't do illegal stuff.

usage: scan.py [-h] [-s SCAN_SPEED] [-r] [-p HTTP_PORTS] [-t HTTPS_PORTS] [-w WORDLIST] [-o OUTPUT] hosts

positional arguments:
  hosts

options:
  -h, --help            show this help message and exit
  -s SCAN_SPEED, --scan-speed SCAN_SPEED
                        nmap scan speed, integer 1-5. Default is 4
  -r, --rerun-scan      Rerun scan if already scanned. Default is to use cached results.
  -p HTTP_PORTS, --http-ports HTTP_PORTS
                        List of comma-separated ports to scan as HTTP
  -t HTTPS_PORTS, --https-ports HTTPS_PORTS
                        List of comma-separated ports to scan as HTTPS
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist for ffuf
  -o OUTPUT, --output OUTPUT
                        Output file. Default is output.txt

