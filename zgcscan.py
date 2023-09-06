import os
import argparse
import shutil
import nmap
import threading
import subprocess
from datetime import datetime

def parse_args():
    parser = argparse.ArgumentParser(description='Masscan2Httpx2Nuclei')
    parser.add_argument('-i', '--input', type=str, help='input file path')
    parser.add_argument('-p', '--port', type=str, help='port range')
    parser.add_argument('--rate', type=int, help='scan rate')
    return parser.parse_args()

# Rest of the code...

def check_args(args):
    if not os.path.exists(args.input):
        print('IP file does not exist')
        exit()
    if not args.port:
        print('Please provide the port range')
        exit()
    if not args.rate:
        print('Please provide the scan rate (e.g., --rate 2000)')
        exit()
    return args

def masscan_scan(args):
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d%H%M%S")
    os.mkdir(timestamp)
    os.system(f"masscan -iL {args.input} -p {args.port} --rate {args.rate} -oL {timestamp}/masscan.txt")
    return timestamp

def update_tools():
    print('+----------------------------------+')
    print('| 正在更新工具库                   |')
    print('+----------------------------------+')
    os.system('./nuclei -update')
    os.system('./afrog -update')
    os.system('./httpx -update')
    os.system('./observer  --update-self')
    print('+----------------------------------+')
    print('| 工具库更新完成!!               |')
    print('+----------------------------------+')

def masscan_scan(args):
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d%H%M%S")
    os.mkdir(timestamp)
    os.system(f'masscan -iL {args.input} -p{args.port} -oL {timestamp}/masscan.txt --rate {args.rate}')
    return timestamp

def convert_masscan_to_httpx(timestamp):
    print('+----------------------------------------+')
    print('| Masscan扫描结果解析并调用httpx          |')
    print('+----------------------------------------+')
    with open(f"{timestamp}/masscan.txt", "r") as masscanfile:
        for line in masscanfile:
            if line.startswith("#"):
                continue
            if line.startswith("open"):
                line = line.split(" ")
                with open(f"{timestamp}/masscanconvert.txt", "a") as f:
                    f.write(line[3] + ":" + line[2] + "\n")
    os.system(f'./httpx -l {timestamp}/masscanconvert.txt -nc -o {timestamp}/httpxresult.txt')
    print('+----------------------------------+')
    print('| Httpx is done !                  |')
    print('+----------------------------------+')

def nmap_scan(host, port, timestamp):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, ports=port, arguments=' -T4 -sV -O')
    with open(f"{timestamp}/service.txt", "a") as f:
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    f.write(host + ":" + str(port) + " " + nm[host][proto][port]['name'] + "\n")

def multi_nmap_scan(timestamp):
    with open(f"{timestamp}/masscanconvert.txt", "r") as f:
        threads = []
        for line in f.readlines():
            line = line.strip().split(':')
            host = line[0]
            port = line[1]
            t = threading.Thread(target=nmap_scan, args=(host, port, timestamp))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    print('+----------------------------------+')
    print('| nmap扫描完成，结果保存在service.txt文件中 |')
    print('+----------------------------------+')

def observer_scan(timestamp):
    os.system(f'./observer -f {timestamp}/masscanconvert.txt -c {timestamp}/observer.txt')

def finger_scan(timestamp):
    path = os.getcwd() + f"/{timestamp}"
    url_file = f"{path}/httpxresult.txt"
    os.system(f'python3 Finger/Finger.py -f {url_file}')
    files = "/Finger/output/"

    if not os.path.exists(files):
        print(f"Directory {files} does not exist")
        return

    for f in os.listdir(files):
        shutil.move(os.path.join(files, f), path)

def afrog_scan(timestamp):
    path = os.getcwd() + f"/{timestamp}"
    url_file = f"{path}/httpxresult.txt"
    if os.path.exists(url_file):
        os.system(f'./afrog -T {url_file} -S high,critical,medium -o {timestamp}/afrog.html')
        print('+----------------------------------+')
        print('| afrog扫描完成，结果保存在afrog.html文件中 |')
        print('+----------------------------------+')
    else:
        print("扫描结果未发现http协议")
        exit()

def nuclei_scan(timestamp):
    path = os.getcwd() + f"/{timestamp}"
    url_file = f"{path}/httpxresult.txt"
    url_file1 =f"{path}/masscanconvert.txt"
    if os.path.exists(url_file):
        os.system(f'./nuclei -l {url_file1} -t /root/nuclei-templates/network/ -o {timestamp}/nucleiresult-service.txt')
    if os.path.exists(f"{timestamp}/httpxresult.txt"):
        os.system(f'./nuclei -l {url_file} -s medium,high,critical -o {timestamp}/nucleiresult.txt')
    else:
        print("扫描结果未发现http协议")
    if os.path.exists(f"{timestamp}/nucleiresult.txt"):
        print('+----------------------------------+')
        print('| 扫描完成,请查看nucleiresult.txt |')
        print('+----------------------------------+')


def xray_scan(timestamp, url):
    path = os.getcwd() + f"/{timestamp}"
    url_file = f"{path}/httpxresult.txt"
    if os.path.exists(url_file):
        # Use the URL's address as the filename
        filename = url.split("//")[-1].replace("/", "-") + ".html"
        cmd = f"./xray webscan --basic-crawler {url} --html-output {timestamp}/{filename}"
        subprocess.run(cmd, shell=True)
    else:
        print("扫描结果未发现http协议")
        exit()


def xray_batch_scan(timestamp):
    path = os.getcwd() + f"/{timestamp}"
    url_file = f"{path}/httpxresult.txt"
    with open(url_file, 'r') as file:
        for line in file:
            url = line.strip()
            xray_scan(timestamp, url)  # Pass 'url' as an argument to the xray_scan() function

    print('Xray批量扫描完成')

def fscan_scan(args,timestamp):
    os.system(f'./fscan64 -hf {args.input} -pn 21 -o {timestamp}/fscan.txt') # 排除fscan偶尔扫描21端口出现卡死问题

def main():
    args = parse_args()
    args = check_args(args)

    update_tools()
    timestamp = masscan_scan(args)
    convert_masscan_to_httpx(timestamp)
    multi_nmap_scan(timestamp)
    observer_scan(timestamp)
    finger_scan(timestamp)
    fscan_scan(args,timestamp)
    afrog_scan(timestamp)
    nuclei_scan(timestamp)
    
    xray_batch_scan(timestamp)

if __name__ == '__main__':
    main()