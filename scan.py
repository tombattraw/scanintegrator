#!/usr/bin/env python3

import argparse, xml, json, os, subprocess, time, datetime, xmltodict

class Script:
    def __init__(self, obj):
        self.id = obj['@id']
        self.output = obj['@output']
        #self.elem = ''
        #if 'elem' in obj.keys(): self.elem = ' ' + obj['elem']
    
    def __repr__(self):
        return f'{self.id:\t{self.output}\t{self.elem}}'

class Port:
    def __init__(self, obj):
        self.protocol = obj['@protocol']
        self.id = obj['@portid']
        self.service = ''
        if 'service' in obj.keys():
            self.service = obj['service']['@name']
            for i in ['@ostype', '@product', '@version', '@extrainfo']:
                if i in obj['service'].keys(): self.service += ' ' + obj['service'][i]
        self.scripts = []
        if 'script' in obj.keys():
            # nmap will just store a single script as a dict, while multiple will be stored as a list of dicts. Wrap solo scripts in a list to simplify handling
            if type(obj['script']) == dict: obj['script'] = [obj['script']]
            self.scripts = [Script(x) for x in obj['script']]

    def __repr__(self):
        return f'{self.id}/{self.protocol}\t\t{self.service}'

class Url:
    def __init__(self, obj):
        self.url = obj['url']
        self.status = obj['status']
    def __repr__(self):
        return f'{self.url}: {self.status}'

class Host:
    def __init__(self, obj):
        if type(obj['os']['osmatch']) == list:
            self.os = obj['os']['osmatch'][0]['@name']        
            self.os_probability = obj['os']['osmatch'][0]['@accuracy']
        else:
            self.os = obj['os']['osmatch']['@name'] 
            self.os_probability = obj['os']['osmatch']['@accuracy']
        self.ip = obj['address']['@addr']
        self.ports = []
        self.extensions = []
        self.base_urls = []
        self.urls = []

        for port in obj['ports']['port']:
            if port['state']['@state'] == 'open':
                self.ports.append(Port(port))
    
    def setUrls(self, http_ports, https_ports):
        for port in self.ports:
            if int(port.id) in [int(x) for x in http_ports.split(',')]:
                self.base_urls.append(f'http://{self.ip}:{port.id}')
            elif int(port.id) in [int(x) for x in https_ports.split(',')]:
                self.base_urls.append(f'https://{self.ip}:{port.id}')
            else:
                for service in ['httpd', 'nginx', 'apache', 'iis']:
                    if service in port.service:
                        self.base_urls.append(f'http://{self.ip}:{port.id}')

    def __repr__(self):
        return f'{self.ip}:\t{self.os} / {self.os_probability}%\n\t{"\n\t".join([str(x) for x in self.ports])}\n\n\t{"\n\t".join([str(x) for x in self.urls])}'


START = time.perf_counter()


def parseArgs():
    args = argparse.ArgumentParser(epilog='Combination nmap and FFUF scanner; uses nmap results to run wordlists against relevant ports')
    args.add_argument('hosts')
    args.add_argument('-s', '--scan-speed', type=int, default=4, help='nmap scan speed, integer 1-5. Default is 4')
    args.add_argument('-r', '--rerun-scan', help='Rerun scan if already scanned. Default is to use cached results.', action='store_true')
    args.add_argument('-p', '--http-ports', help='List of comma-separated ports to scan as HTTP', default="80,8080")
    args.add_argument('-t', '--https-ports', help='List of comma-separated ports to scan as HTTPS', default="443,8443")
    args.add_argument('-w', '--wordlist', default='/home/kali/dsmallest.txt', help='Wordlist for ffuf')
    args.add_argument('-o', '--output', default='output.txt', help='Output file. Default is output.txt')
    return args.parse_args()


def elapsed():
    global START
    return str(datetime.timedelta(seconds=int(time.perf_counter() - START)))


def parseNmapXml():
    with open('scan.xml', 'r') as f:
        res = xmltodict.parse(f.read())
    hostArr = []
    for host in res['nmaprun']['host']:
        if host['status']['@state'] == 'up':
            hostArr.append(Host(host))
        else: print(f'Host {host['address']['@addr']} is down')
    
    return hostArr


def main():
    args = parseArgs()

    # Step 1: nmap
    if not 'scan.xml' in os.listdir('.') or args.rerun_scan:
        scan = f'nmap -Pn -sS -T{args.scan_speed} -p- -O -A --script vuln -oN scan.nmap -oX scan.xml {args.hosts} -vv'
        print(f'Starting scan: {scan}')
        subprocess.run(scan.split())
        print(f'Scan complete. Time: {elapsed()}')

    hosts = parseNmapXml()
    print(f'Parsing complete. Time: {elapsed()}')

    for host in hosts:
        host.setUrls(args.http_ports, args.https_ports)
    
    base_urlArr = []
    [base_urlArr.extend(x.base_urls) for x in hosts]

    # Detect extensions
    os.mkdir('tmpdir')
    for index, url in enumerate(base_urlArr):
        scan = f'ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u {url}/indexFUZZ -of json -o tmpdir/{index}.json'
        print(f'Starting extension scan: {scan}')
        subprocess.run(scan.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    extension_results = []

    for i in os.listdir('tmpdir'):
        with open(f'tmpdir/{i}', 'r') as f:
            extension_results.append(json.load(f))
        os.remove(f'tmpdir/{i}')
    print(f'Extension scan complete. Time: {elapsed()}')

    # Index hosts for ease of use
    hostDct = {}
    for host in hosts: hostDct[host.ip] = host

    validStatus = list(range(200,300))
    validStatus.extend([301, 302, 307, 401, 403, 405, 500])
    for obj in extension_results:
        for result in obj['results']:
            if int(result['status']) in validStatus and result['url'].split('.')[-1] not in hostDct[result['host'].split(':')[0]].extensions:
                hostDct[result['host'].split(':')[0]].extensions.append(result['url'].split('.')[-1])

    # Word scan
    for i,host in enumerate(hostDct.values()):
        if host.extensions != []:
            for j,url in enumerate(host.base_urls):
                for k,extension in enumerate(host.extensions):
                    scan = f'ffuf -w {args.wordlist} -u {url}/FUZZ -recursion -recursion-depth 1 -e {extension} -of json -o tmpdir/{i}{j}{k}.json'
                    print(f'Fuzzing: {scan}')
                    subprocess.run(scan.split())
                    print(f'Fuzz complete. Time: {elapsed()}')
    url_results = []
    for i in os.listdir('tmpdir'):
        with open(f'tmpdir/{i}', 'r') as f:
            url_results.append(json.load(f))
        os.remove(f'tmpdir/{i}')
    os.rmdir('tmpdir')
    print(f'URL scan complete. Time: {elapsed()}')

    for obj in url_results:
        for result in obj['results']:
            if int(result['status']) in validStatus:
                hostDct[result['host'].split(':')[0]].urls.append(Url(result))
    output_txt = '\n\n\n'.join([str(x) for x in hostDct.values()])
    with open(args.output,'w') as f:
        f.write(output_txt)
    print(output_txt)

main()