import os, json, socket, base64, sys, time

def s_to_bytes(s):
    if sys.version_info < (3, 0):
        return bytes(s)
    else:
        return bytes(s, 'utf8')

def bytes_to_s(b):
    if sys.version_info < (3, 0):
        return b
    else:
        return b.decode()

def save_config():
    global config
    fstream = open("pivoteer_config.json", "w")
    fstream.write(json.dumps(config))
    fstream.close()

def green(text):
    return('\033[92m'+text+'\033[0m')

def yellow(text):
    return('\033[93m'+text+'\033[0m')

def red(text):
    return('\033[91m'+text+'\033[0m')

common_ports = [21, 22, 23, 80]
def port_scan_common_ports(ip):
    open_ports = []
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)

        try:
            con = s.connect((ip,port))
            print(str(port)+"/TCP is open on "+ip)
            open_ports.append(port)
            con.close()
        except:
            continue
    return open_ports

def run_ssh_command(ip, port, username, password, command):
    # this function is just a wrapper for sshpass
    # sshpass -p password ssh vyos@172.16.120.1 -o StrictHostKeyChecking=no uname -a
    result = os.popen("sshpass -p '"+password+"' ssh -p "+str(port)+" "+username+"@"+ip+" "+command+" 2> stderr.txt").read()

    # load the stderr
    fstream = open('stderr.txt', 'r')
    stderr = fstream.read()
    fstream.close()
    os.system("rm stderr.txt")

    if len(result) == 0:
        return False, None, stderr

    return True, result, stderr

def port_scan_banner_grab(ip, specified_ports):
    open_ports = 0
    port_list = []
    for port in specified_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        banner = ''

        try:
            s.connect((ip,port))
            s.close()
            if len(port_list) == 0:
                print(green(ip+" is online."))
            banner =  banner_grab(ip, port)
            print(yellow(str(port))+"/TCP is OPEN\t"+banner)
            port_list.append([port, banner])
            open_ports += 1
        except:
            continue
    if open_ports > 0:
        print()
    return port_list

def port_scan(ip, specified_ports):
    open_ports = 0
    port_list = []
    for port in specified_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        banner = ''

        try:
            s.connect((ip,port))
            s.close()
            if len(port_list) == 0:
                print(green(ip+" is online."))
            print(yellow(str(port))+"/TCP is OPEN")
            port_list.append(port)
            open_ports += 1
        except:
            continue
    if open_ports > 0:
        print()
    return port_list


def one_liner_ssh_scan(network, all_ports=False):
    fstream = open("custom_scan.sh")
    base_script = fstream.read()
    fstream.close()

    if all_ports:
        base_script = base_script.replace("PORT_RANGE", "[]")
    else:
        base_script = base_script.replace("PORT_RANGE", "[21, 22, 23, 80]")

    base_script = base_script.replace("NETWORK_CIDR", network)

    return base64.b64encode(s_to_bytes(base_script))

def verify_tool(name, msg_if_absent):
    result = os.popen("which "+name.strip()).read()
    if name not in result:
        print(yellow(msg_if_absent))
        return False
    else:
        print(green("[PASS] "+name.strip()+" is present on system."))
        return True

# track which tools are available
proxychains = True
wget = True
sshpass = True

base_scan = '''
#!/bin/bash

python << END
import socket, json

common_ports = PORT_RANGE
if len(common_ports) == 0:
    for x in range(0, 65536):
        common_ports.append(x)

def port_scan_common_ports(ip):
    open_ports = []
    for port in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        banner = ''

        try:
            s.connect((ip,port))
            s.close()
            open_ports.append(port)
        except:
            continue
    return open_ports

def expand_cidr(net):
    try:
        cidr = int(net.split("/")[-1])
    except:
        return []
    try:
        octets = [int(o) for o in net.split("/")[0].split(".")]
    except:
        return []
    # get the network bits: '0b11'
    bin_ip = ''
    for o in octets:
        bin_str = bin(o)[2:]
        while len(bin_str) < 8:
            bin_str = '0'+bin_str
        bin_ip = bin_ip + bin_str
    start = bin_ip[:cidr]
    stop = bin_ip[:cidr]
    # turn all host bits on/off
    while len(start) < 32:
        start = start + '0'
    while len(stop) < 32:
        stop = stop + '1'
    # convert back to octets
    start_octets = [int(start[:8], 2), int(start[8:16], 2), int(start[16:24], 2), int(start[24:], 2)]
    stop_octets = [int(stop[:8], 2), int(stop[8:16], 2), int(stop[16:24], 2), int(stop[24:], 2)]
    ips = []
    for a in range(start_octets[0], stop_octets[0]+1):
        for b in range(start_octets[1], stop_octets[1]+1):
            for c in range(start_octets[2], stop_octets[2]+1):
                for d in range(start_octets[3], stop_octets[3]+1):
                    if d == 0 or d== 255:
                        continue
                    ips.append(str(a)+"."+str(b)+"."+str(c)+"."+str(d))
    return ips

def scan_network(ip_range):
    results = {}
    ips = expand_cidr(ip_range)
    if len(ips) == 0:
        return
    for ip in ips:
        # scan a low port without using ping so this can run with minimal permissions
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        host_online = False
        try:
            con = s.connect((ip,10))
            con.close()
            host_online = True
        except Exception as error:
            if "Connection refused" in str(error):
                host_online = True
        if host_online:
            # check the most common ports
            port_list = port_scan_common_ports(ip)
            results[ip] = port_list
    return results

print(json.dumps(scan_network('NETWORK_CIDR')))

END
'''

def one_liner_ssh_scan(network, all_ports=False):
    if all_ports:
        base_script = base_scan.replace("PORT_RANGE", "[]")
    else:
        base_script = base_scan.replace("PORT_RANGE", "[21, 22, 23, 80]")

    base_script = base_script.replace("NETWORK_CIDR", network)

    return base64.b64encode(s_to_bytes(base_script))

def main():
    global sshpass, wget, proxychains
    # Check which tools are available on the system
    print(yellow("\n[INFO] Checking for access to local tools."))
    tools = [['proxychains', '[WARN] Proxychains is missing, you may need to set up an SSH tunnel for each port on the remote host.'], ['wget', '[WARN] wget is missing, you may need to use curl, python requets, or some other alternative.'], ['curl', '[WARN] curl is missing, you may need to use wget, python requests, or some other alternative.'], ['sshpass', '[WARN] sshpass is missing, you will need to type passwords manually when trying to ssh to a remote host.']]
    for tool in tools:
        result = verify_tool(tool[0], tool[1])
        if result == False and tool[0] == 'sshpass':
            sshpass = False
        if result == False and tool[0] == 'wget':
            wget = False
        if result == False and tool[0] == 'proxychains':
            proxychains = False

    print()

    # Prompt the user for the appropriate input
    print(yellow("[INFO] This script will quickly perform up to two hops of scanning, banner grabbing, and file retrieval."))
    print(yellow("[INFO] Follow the prompts below to begin network enumeration.\n"))

    first_hop_ip = input("Enter the IP first hop IP address that you have SSH access to >>>")
    first_hop_ssh_port = input("Enter the port number that is running SSH >>>")

    # if we have sshpass, get the creds to automatically run commands
    username = None
    password = None
    if sshpass:
        username = input("Enter the SSH username for "+first_hop_ip+" >>>")
        password = input("Enter the SSH password for "+first_hop_ip+" >>>")

    # check if there is an additional network to be scanned
    new_networks = []
    print(yellow("\n[INFO] If you leave the below section blank, this script will just scan the networks attached to the interfaces on the remote host."))
    while True:
        additional = input("Enter additional network ranges to scan from this host, e.g. 192.168.88.0/24, empty entry to continue >>>")
        if len(additional.strip()) == 0:
            break
        new_networks.append(additional.strip())

    # go to work
    ip = first_hop_ip
    port = first_hop_ssh_port
    print(yellow("\n[INFO] Step 1: Find networks associated with interfaces on the remote host"))
    command = "ip a | grep global | awk '{print $2}'"
    status, result, stderr = run_ssh_command(ip, port, username, password, command)
    if status:
        print(green("[PASS] Success, found the following network(s) from remote interfaces:"))
        for new_network in result.split("\n"):
            if len(new_network):
                print(green("  - "+new_network))
                new_networks.append(new_network)
    else:
        print(red("[FAIL] Command failed to run."))
    print(yellow("\n[INFO] Step 2: Get the hostname/OS of the machine"))
    command = "hostname"
    status, result, stderr = run_ssh_command(ip, port, username, password, command)
    if status:
        print(green("[PASS] Hostname for "+ip+" is "+result.strip()))
    else:
        print(red("[FAIL] Command failed to run."))

    command = "uname -a"
    status, result, stderr = run_ssh_command(ip, port, username, password, command)
    if status:
        print(green("[PASS] OS for "+ip+" is "+result.strip()))
    else:
        print(red("[FAIL] Command failed to run."))

    print(yellow("\n[INFO] Step 3: Play the CTF, look for hint/flag"))
    command = "'find / -iname hint*'"
    status, result, stderr = run_ssh_command(ip, port, username, password, command)
    if status:
        print(result)
        while True:
            print(yellow("[INFO] If any of the above files look interesting, paste the path in the input below to download it."))
            filename = input("Full filepath, press enter to skip >>>")
            if len(filename) < 3:
                break
            name_only = filename.split("/")[-1]
            if os.path.exists(ip) == False:
                os.mkdir(ip)
            command = "base64 "+filename+" -w 0"
            status, result, stderr = run_ssh_command(ip, port, username, password, command)
            if status:
                os.system("echo "+result.strip()+" | base64 --decode > "+os.path.join(ip, name_only))
                print(green("[PASS] A copy of "+filename.strip()+" has been saved in a directory called "+ip))
                filetype = os.popen("file "+os.path.join(ip, name_only)).read()
                if 'ASCII' in filetype:
                    print(yellow("[INFO] File contents (only ASCII files are displayed):"))
                    os.system("cat "+os.path.join(ip, name_only))
            else:
                print(red("[FAIL] Failed to retrieve file:"))
                print(stderr)
    else:
        print(red("[FAIL] Command failed to run."))
    command = "'find / -iname flag*'"
    status, result, stderr = run_ssh_command(ip, port, username, password, command)
    if status:
        print(result)
        while True:
            print(yellow("[INFO] If any of the above files look interesting, paste the path in the input below to download it."))
            filename = input("Full filepath, press enter to continue >>>")
            if len(filename) < 3:
                break
            name_only = filename.split("/")[-1]
            if os.path.exists(ip) == False:
                os.mkdir(ip)
            command = "base64 "+filename.strip()+" -w 0"
            status, result, stderr = run_ssh_command(ip, port, username, password, command)
            if status:
                os.system("echo "+result.strip()+" | base64 --decode > "+os.path.join(ip, name_only))
                print(green("[PASS] A copy of "+filename.strip()+" has been saved in a directory called "+ip))
                filetype = os.popen("file "+os.path.join(ip, name_only)).read()
                if 'ASCII' in filetype:
                    print(yellow("[INFO] File contents (only ASCII files are displayed):"))
                    os.system("cat "+os.path.join(ip, name_only))
            else:
                print(red("[FAIL] Failed to retrieve file:"))
                print(stderr)
    else:
        print(red("[FAIL] Command failed to run."))

    print(yellow("\n[INFO] Step 4: Port Scan Interface Networks"))
    scan_outputs = []
    for n in new_networks:
        print(yellow("[INFO]Performing host discovery for "+n.strip()))
        b64 = bytes_to_s(one_liner_ssh_scan(n.strip(), all_ports=False))
        command = "'echo "+b64+" | base64 --decode | sh'"
        status, result, stderr = run_ssh_command(ip, port, username, password, command)
        if status:
            try:
                jdata = json.loads(result)
                print(green("[PASS] Found "+str(len(jdata))+" new IPs, adding them to network lists."))
                print(jdata)
                scan_outputs.append(jdata)
            except:
                print(red("[FAIL] Failed to load enumeration response, maybe it wasn't valid JSON:"))
                print(result)
        else:
            print(red("[FAIL] Port scan failed for network: "+n.strip()))
            print(stderr)

    print(yellow("\n[INFO] Step 5: Get all the files"))
    if proxychains:
        dynamic_command = "ssh "+username+"@"+ip+" -p "+port+" -D 9050 -NT"
        # check for existing dynamic port forwards, give a warning if one is already running
        existing_dynamic_ports = int(os.popen("ps -elf | grep ssh | grep 9050 | wc -l").read().strip())
        if existing_dynamic_ports:
            print(red("[WARN] Saying yes will terminate any other dynamic port forwarding ssh connections you have."))
            print(yellow("[INFO] Existing dynamic port forward:"))
            os.system("ps -elf | grep ssh | grep 9050 | grep -v grep")
            print(yellow("[INFO] New dynamic ssh command: "+dynamic_command))
            choice = input("Do you want to tear down existing dynamic port forwards to set up a new one to retrieve files? (y/n) >>>")

            if 'y' not in choice:
                print(yellow("\n[INFO] Exiting, you can re-run the script with the above options to continue."))
                exit()

            print(yellow("\n[INFO] Tearing down existing dynamic port forwards..."))
            for line in os.popen("ps -elf | grep ssh | grep 9050 | grep -v grep").read().split("\n"):
                try:
                    pid = int(line.split()[3])
                    command = "kill -9 "+str(pid)
                    os.system(command)
                    print(green("[PASS] Terminated existing dynamic port forward"))
                except:
                    continue

        choice = input("Create new port forward to retrieve files? (y/n) >>>")
        if sshpass:
            os.system("nohup sshpass -p '"+password+"' "+dynamic_command+" &")
            print(yellow("[INFO] Opened new dynamic port in the background, run the command below to terminate it:"))
            print(yellow("[INFO] kill -9 $(ps -elf | grep ssh | grep 9050 | grep -v grep | awk '{print $4}' | head -n 1)"))
        else:
            print(red("\n[WARN] You do not have sshpass on this machine, run the below command in another terminal, enter the creds, and press enter to continue..."))
            print(dynamic_command)
            input("press enter to continue, CTRL+C to stop the script...")

        # run wget against every port to retrieve every file, banner grab every port as well
        # proxychains wget -r http://ip:port --timeout=1 --tries=1
        # proxychains wget -r ftp://ip:port --timeout=1 --tries=1
        print(yellow("\n[INFO] Giving dynamic port forward a few seconds to establish..."))
        time.sleep(5)

        no_ports = []
        for output in scan_outputs:
            for ip in output:
                if len(output[ip]):
                    for port in output[ip]:
                        if wget:
                            print(yellow("[INFO] Trying wget with HTTP on "+ip+":"+str(port)+"..."))
                            os.system("proxychains wget -r http://"+ip+":"+str(port)+" --timeout=2 --tries=1")
                            print(yellow("[INFO] Trying wget with FTP on "+ip+":"+str(port)+" enter anonymous if prompted for password..."))
                            os.system("proxychains wget -r ftp://"+ip+":"+str(port)+" --timeout=15 --tries=1")
                        else:
                            print(red("[FAIL] Failed to get files from "+ip+":"+str(port)+", wget exe is missing."))
                    else:
                        no_ports.append(ip)

        print(green("\n\n[PASS] Completed scanning and file collection through "+str(first_hop_ip)))
        if 'localhost' in first_hop_ip:
            print(yellow("[INFO] This scan happened through a proxy, the IP above may not be accurate."))
        for output in scan_outputs:
            for ip in output:
                print("Host "+ip+" is up:")
                if len(output[ip]):
                    for port in output[ip]:
                        print("  - "+str(port)+"/TCP")
                else:
                    print("  - No open TCP ports found, consider re-scanning all ports on this host.")

    else:
        print(red("[FAIL] Proxychains is not located on this machine, retrieve the remote files another way."))


main()
