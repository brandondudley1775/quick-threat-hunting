import os, time

def green(text):
    return('\033[92m'+text+'\033[0m')

def yellow(text):
    return('\033[93m'+text+'\033[0m')

def header(title, description):
    print(yellow("\n###########################################################"))
    print(yellow("# "+title))
    print(yellow("# "+description))
    print(yellow("###########################################################\n"))

# check to see if we are root, if so we can just run any commands we want
ROOT_PRIVS = True
SUDO_CAT = False
SUDO_LS = False
if os.geteuid() != 0:
    ROOT_PRIVS = False
    # check the sudo privs, make a recommendation
    # /bin/cat, /bin/ls, /usr/bin/find, /bin/systemctl
    privs = os.popen("sudo -l | grep $(whoami); sudo -l | grep \\(ALL\\)").read()

    if '/find,' in privs:
        print("This script is not running as root, which may be a problem.")
        print(green("Your sudo privileges appear to include \"find\", for best results"))
        print(green("you should run this command: sudo find /home -exec /bin/bash \\;"))
        print(green("and re-run the python command."))

    print(yellow("If you want to attempt to run this script without root privileges"))
    response = input(yellow("anyway, type \"yes\" >>>"))

    if 'yes' not in response:
        exit()

    if '/ls,' in privs:
        SUDO_LS = True
    if '/cat,' in privs:
        SUDO_CAT = True


if ROOT_PRIVS == False:
    print(yellow("Attempting run without root privileges, for best results re-run with root."))
    if SUDO_CAT:
        print(green("Found sudo privileges with \"cat\"."))
    if SUDO_LS:
        print(green("Found sudo privileges with \"ls\"."))

def gc(path):
    if os.path.exists(path) == False:
        return
    if os.path.isdir(path):
        return

    fstream = open(path, 'r')
    data = fstream.read()
    fstream.close()
    return data

START_DIR = os.popen("pwd").read().strip()

#   332  cd /lib/systemd/system
#   333  ls | awk '{print "-------------------------------\n\n"$1; system("cat /lib/systemd/system/"$1" | grep ExecStart")}'
#   334  ls | awk '{print "-------------------------------\n\n"$1; system("cat /lib/systemd/system/"$1" ")}'
header("Systemd Services", "Checking all non-comment lines of systemd services")
for f in os.listdir('/lib/systemd/system'):
    data = gc(os.path.join('/lib/systemd/system', f))
    if data == None:
        continue

    data = data.split("\n")
    interesting = False
    interesting_lines = []
    for line in data:
        if len(line) == 0 or line[0] == "#":
            continue
        if "/bin/bash" in line.lower() and "execstart" in line.lower():
            interesting_lines.append(line)
            interesting = True

    if interesting:
        print(green("Interesting Filename/Servicename: "+f))
        print(green("\n".join(interesting_lines)))
        print("run this command to see the entire file: cat "+os.path.join('/lib/systemd/system', f))
        print("-------------------------------------------------------")

#################################################################################################################
# find strange sequential/repeating ports and find all associated processes
header("Sequential/repeating ports", "Check all ports for sequential repeating numbers and enumerate process")

def interesting_socket(s):
    # get the port
    try:
        port = s.split(":")[-1]
        int(port)
    except:
        return False

    if port == '443':
        return True

    uninteresting = [0, 22]
    if int(port) in uninteresting:
        return False

    # check for sequential
    last = 0
    interesting = True
    for character in port:
        if last == 0:
            last = int(character)
            continue
        if last+1 != int(character):
            interesting = False
    if interesting:
        return True

    # check for repeating
    if len(set(port)) == 1:
        return True
    return False

if ROOT_PRIVS:
    count = 0
    command_output = os.popen("netstat -anop").read().split("\n")
    for line in command_output[1:]:
        try:
            tokens = line.split()
            proto = tokens[0]
            if 'tcp' not in proto.lower() and 'udp' not in proto.lower():
                continue

            l_socket = tokens[3]
            r_socket = tokens[4]
            if not interesting_socket(l_socket) and not interesting_socket(r_socket):
                continue

            state = tokens[5]
            process = tokens[6]
        except:
            continue

        count += 1

        print(green("Interesting Port Found:"))
        print(green(" -Protocol: "+proto.strip()))
        print(green(" -Local Socket: "+l_socket.strip()))
        print(green(" -Remote Socket: "+r_socket.strip()))
        print(green(" -State: "+state))
        print(green(" -Process pid/name: "+process.strip()))
        print(green(" -Verbose process info:"))
        try:
            pid = process.split("/")[0]
            # ps -p 26360 -lf
            process_info = os.popen("ps -p "+pid.strip()+" -lf").read()
            print(green(process_info.strip()))
        except:
            print("Unable to get process info for above socket.")
        print("------------------------------------------------")

    if count == 0:
        print("No sequential or repeating sockets found.")
else:
    count = 0
    command_output = os.popen("netstat -ano").read().split("\n")
    for line in command_output[1:]:
        try:
            tokens = line.split()
            proto = tokens[0]
            if 'tcp' not in proto.lower() and 'udp' not in proto.lower():
                continue

            l_socket = tokens[3]
            r_socket = tokens[4]
            if not interesting_socket(l_socket) and not interesting_socket(r_socket):
                continue

            state = tokens[5]
            process = tokens[6]
        except:
            continue

        count += 1

        ports = []
        try:
            ports.append(int(l_socket.split(":")[-1]))
        except:
            pass
        try:
            ports.append(int(r_socket.split(":")[-1]))
        except:
            pass

        print(green("Interesting Port Found:"))
        print(green(" -Protocol: "+proto.strip()))
        print(green(" -Local Socket: "+l_socket.strip()))
        print(green(" -Remote Socket: "+r_socket.strip()))
        print(green(" -State: "+state))
        print(green(" -Process pid/name: "+process.strip()))
        print(yellow(" -You need to run this with root privileges to get the pid/name of the process."))
        print(yellow("  The following output is a best effort to identify the process witout root privileges:"))
        for port in ports:
            os.system("ps -elf | grep "+str(port)+" | grep -v grep")

        print("------------------------------------------------")

    if count == 0:
        print("No sequential or repeating sockets found.")

#####################################################################################################################
# check all crontabs for all users
header("User Crons", "Check all users for crons")

if ROOT_PRIVS:
    count = 0
    for user in os.listdir('/home'):
        result = os.popen("crontab -u "+user.strip()+" -l 2> /dev/null").read()
        if len(result) == 0:
            continue
        count += 1
        print(green("User "+user+" has a crontab:"))
        print(result)
        print("-----------------------------------------------")
    result = os.popen("crontab -l 2> /dev/null").read()
    if len(result) != 0:
        count += 1
        print(green("user root has a crontab:"))
        print(result)

    if len(os.listdir('/var/spool/cron/crontabs')):
        print(green("Found crontabs for the following users:"))
        for user in os.listdir('/var/spool/cron/crontabs'):
            print("\nCron for "+user)
            os.system("cat "+os.path.join('/var/spool/cron/crontabs', user))
    elif count == 0:
        print("No crontabs found for other users.")

# SUDO_LS
elif SUDO_LS:
    if len(os.popen('sudo ls /var/spool/cron/crontabs').read().split("\n")) > 1:
        print(green("Found crontabs for the following users:"))
        for user in os.popen('sudo ls /var/spool/cron/crontabs').read().split("\n"):
            if len(user) == 0:
                continue
            print("\nCron exists for "+user)
            if SUDO_CAT:
                os.system("sudo cat "+os.path.join('/var/spool/cron/crontabs', user))
            else:
                print("Missing necessary permissions to read crontab, find another way to read "+os.path.join('/var/spool/cron/crontabs', user))
            print("-------------------------------------------------")
    else:
        print("No crontabs found for other users.")

######################################################################################################################################
# check the linux profiles, convention should have an author listed in the file
header("Checking /etc/profile.d/ persistence", "Check all files in /etc/profile.d that does not specify an author.")
if ROOT_PRIVS:
    files = os.listdir('/etc/profile.d/')
    for f in files:
        fstream = open(os.path.join("/etc/profile.d/", f))
        data = fstream.read()
        fstream.close()
        if 'author' not in data.lower() and 'license' not in data.lower():
            print("No author/license specified for "+os.path.join("/etc/profile.d/", f)+", this is worth looking at.")
            print("Script content:")
            for line in data.split("\n"):
                if len(line) > 0 and line[0] != '#':
                    print(line.strip())
            print("------------------------------------------------------")

else:
    print("No root privileges, manually check /etc/profile.d/ for bash script persistence.")

######################################################################################################################################
# check all of the .bash_profile and .bashrc for each user
header("Checking .bashrc and .bash_profile", "Check all users .bashrc and .bash_profile for persistence.")
if ROOT_PRIVS:
    print("This section counts all lines for all users in linux profiles.  Look at each section, and")
    print("See if any of the numbers toward the top look weird (low numbers are weird, 1 is super weird)")
    for file in ['.bashrc', '.bash_profile', '.profile']:
        print(yellow("\n\nChecking for weird commands in each user's "+file+" file."))
        command = "cat /home/*/"+file+" | sort | uniq -c | sort -n | head"
        os.system(command)

else:
    print("No root privileges, manually check /home/<username>/.bashrc files for persistence.")

######################################################################################################################################
# /etc/init.d/* should specify an author
header("Checking /etc/init.d/ persistence", "Check all files in /etc/init.d that does not specify an author.")
if ROOT_PRIVS:
    files = os.listdir('/etc/init.d/')
    for f in files:
        fstream = open(os.path.join("/etc/init.d/", f))
        data = fstream.read()
        fstream.close()
        if 'author' not in data.lower() and 'BEGIN INIT INFO' not in data:
            print("No author specified for "+os.path.join("/etc/init.d/", f)+", this is worth looking at.")
            print("Script content:")
            for line in data.split("\n"):
                if len(line) > 0 and line[0] != '#':
                    print(line.strip())
            print("------------------------------------------------------")

else:
    print("No root privileges, manually check /etc/init.d/ for bash script persistence.")



os.chdir(START_DIR)