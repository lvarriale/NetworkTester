# NetworkTester
Azure NetworkTester

General Information
The Network Tester is a collection of utilities bundled into a single script that can be useful to any Azure engineer to quickly collect, analyse and diagnose the most common networking issues in a Linux OS.

The script first checks the release of the operating system and then sets packages for installation.
If the user chooses to install packages, the script will install the required packages based on the operating system type. Otherwise, it will skip this step. After prompting the user to install packages or skip, it creates the log file and prints:

Routing tables
IP configurations
DNS settings
Active connections
Microsoft connectivity
Firewall settings
Wireserver connection
Accelerated Network status
Total number of interfaces
If IP routes are missing, the script will prompt the user to fix them. The user will need to input the subnet mask, and the script will calculate the gateway address, add the default gateway, and add two specific routes.

The script then logs the DNS settings and checks the DNS connection to www.microsoft.com . If the DNS connection is not working, this will be logged.

Next, the script logs the firewall settings and checks if a firewall is running. If a firewall is running, the script will log the firewall ruleset.

Finally, the script counts the number of network interfaces and logs the output.

Overall, this script provides a convenient way to gather and log network configuration details on an Azure Linux VM, making it easier to troubleshoot networking issues.

It is distribution agnostic, meaning that, as of now, works on the following flavours:

RHEL 6/7/8
SLES 12/15
Ubuntu 18/20
RHEL based distros (Alma, CentOS and so on)
Prerequisites
The script needs some packages installed to properly run, such as:

bash-completion
curl
sysstat
netfilter
iptables
bind-utils
net-tools
These can be also installed by the script itself at runtime.

Usage
The Script must be run as root or with sudo privileges to gather all the information.
In order to do that, the following methods are allowed:

./NetworkTester.sh
sudo bash NetworkTester.sh
the default output location for the complete log is /tmp

Options and flags
At the time of the first release, the script bundles 4 major areas or utilities, which are:

Network related logs gathering
IP address fix (no DHCP Scenario)
IP routes fix (no Wireserver/Metadata/Default GW routes)
Tcpdump utility
points 1,2,3 are run by default at every iteration whereas the tcpdump utility need the option to be specified like the following:

./NetworkTester --tcp-dump
or

sudo bash NetworkTester --tcp-dump
Tcpdump
Once invoked, the tcpdump utility accepts as argument the source IP and the destination port to be filtered.
The output will be then collected in /tmp ready to be shared and/or analysed with a proper packet analyser software (ex. Wireshark).

The following is an example of the final command run by the script:

tcpdump -nn -v -i eth0 ip and tcp and src host 192.168.1.56 and dst port 22 -w /tmp/NetTester_tcpdump$(date +%Y-%m-%d.%H:%M)
