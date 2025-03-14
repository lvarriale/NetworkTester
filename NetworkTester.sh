#!/bin/bash
## Pasting long strings doesn't work in serial console.
## The serial console limits the length of strings pasted into the terminal to 2048 characters to prevent overloading the serial port bandwidth.
## https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/serial-console-linux#known-issues


        case $1 in

        -h | --help)
        echo -e "\n"
        echo "*** Description ***"
        echo -e "\n"
        echo "NetworkTester Script to collect Azure network information and store them into /tmp directory.
The script includes utilities to fix missing IP address and missing Azure routes. 

---------------------------------------

Usage

sudo ./networktester.sh [option]

---------------------------------------

Options

-h --help: show the help page.

--tcp-dump: provides the tcpdump utility with custom source address and custom destination port as arguments. The utility will run until a ctrl+c is provided. Please be sure tcpdump is installed in the system as well as the ip utility (bash completion package).

---------------------------------------

Notes

This script must be run as root or with sudo privileges.
The script might need some package to be installed (bash-completion, curl, sysstat, netfilter, iptables, bind-utils, net-tools): if they are not installed, you will be prompted to install them at the beginning of the script. 

When the script runs, it will perform the following checks: IP configuration: if the VM has no IP configuration set, the script will ask if you want to fix it.

IP routes: if there are no IP routes set, the script will ask if you want to fix it.

DNS settings: the script checks if the DNS settings are set correctly. If they are not set correctly, it will report the problem.

Microsoft connectivity: the script checks if the VM can connect to Microsoft. If it cannot connect, it will report the problem.

Firewall settings: the script checks the firewall settings and reports the results.

Wireserver connection: the script checks the connection to the wireserver and reports the results.

Number of interfaces: the script counts the number of interfaces and reports the result.

All the information collected by the script will be stored in /tmp/NetLog<date and time>."

        exit 0

        ;;

        --tcp-dump)
        function tcpdump_function () {
                echo "Please insert the source IP to filter in tcpdump"

                read src_ip

                echo "Please enter the destination port"

                read dst_port

                tcpdump -nn -v -i $(ip a s | grep eth | grep -v link | head -n 1 | cut -d: -f2) ip and tcp and src host $src_ip and dst port $dst_port -w /tmp/NetTester_tcpdump$(date +%Y-%m-%d.%H:%M)

        }

        tcpdump_function

        exit 0
        ;;

        esac;

## find the release of the OS
rel=$( cat /etc/os-release )
## set date and time
datetime=$(date +%Y-%m-%d.%H:%M)
## set packages for installation
rhrpms=("bash-completion" "curl" "sysstat" "netfilter" "iptables" "bind-utils" "net-tools")
slesrpms=("bash-completion" "curl" "sysstat" "netfilter" "iptables" "bind-utils" "net-tools")
debpkgs=("bash-completion" "curl" "sysstat" "netfilter" "iptables" "bind9-utils" "net-tools" "isc-dhcp-client")

echo "Attention: this script must be run as root or with sudo privileges (sudo bash scriptname.sh)"

## just a countdown
for i in {5..0};
do sleep 1;  echo "***$i***";
done
echo "************************"
echo "*-NetworkTester Starts-*"
echo "************************"
echo -e "\n"
## prompting warning and install packages if I is pressed
echo "This script might need some package to be installed (bash-completion, curl, sysstat, netfilter, iptables, bind-utils, net-tools): do you want to install or skip? (I: install S: skip)"

        read INSTALL

        case $INSTALL in

                I | yes | y)
                if [[ "$rel" =~ 'rhel' ]]; then
                echo "Red Hat Like"
                    for i in ${rhrpms[@]}; do
                    yum install -y $i;
                    done;
                elif [[ "$rel" =~ 'Oracle' ]]; then
                    echo "Oracle Linux"
                    for i in ${rhrpms[@]}; do
                        yum install -y $i;
                    done;
                elif [[ "$rel" =~ 'debian' ]]; then
                    echo "Ubuntu";
                    apt update
                    for i in ${debpkgs[@]}; do
                        apt install -y $i;
                    done;
                elif [[ "$rel" =~ 'SLES' ]]; then
                    echo "SLES";
                    for i in ${slesrpms[@]}; do
                        zypper in -y $i;
                    done;
                else
                    echo "not found" > /tmp/NetLog$datetime
                    exit 1;
                fi
                    ;;

esac;

echo "Gathering data..."
## create the log file
echo "NetworkTester starts at $datetime" > /tmp/NetLog$datetime
echo "************************" >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime
## print routing tables in the log
echo "Routing Table" >>/tmp/NetLog$datetime
route -n >> /tmp/NetLog$datetime
echo "ip route entries" >> /tmp/NetLog$datetime
ip route show >> /tmp/NetLog$datetime
echo "************************" >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime
## ip configuration check
if [[ -z $(ip a s | grep inet | egrep -v "127|inet6" | awk '{print $2}' | cut -d"/" -f1) ]] ;
then echo "This vm has no ip configuration set: Do you want the script tries to fix the configuration?";
        read ipconfig

        case $ipconfig in

                YES | yes | y)
                echo "insert the private IP address shown in Azure vm's nic settings with the netmask cidr prefix (ex: 10.0.0.1/24)"
                read ipaddr
                nic=$(ip a s | grep eth | grep -v link | head -n 1 | cut -d: -f2)
                ip addr add $ipaddr dev $nic
                dhclient -v
                echo "ip address after NetworkTester ran" >> /tmp/NetLog$datetime
                ip a s >> /tmp/NetLog$datetime
                echo "************************" >> /tmp/NetLog$datetime
                echo -e "\n" >> /tmp/NetLog$datetime
                    ;;

                NO | No | no |n )
                echo "No changes made"
                ;;

                *)
                  echo "Please answer yes or no"
                ;;
esac;

else echo "ip configuration found";
fi


## ip routes fix part
if [[ $(ip route | egrep "168.|169." | wc -l) -gt 1 ]];
        then echo "ok" ;
else echo -n "Routes not found. Do you want the script tries to fix the iproutes?"

        read IPROUTE

        case $IPROUTE in

                YES | yes | y)
				echo "insert the cidr mask (ex: only 24)"
                read cidr
                                function cidr_to_subnet() {
                                cidr=$1
                                mask=$((0xffffffff << (32 - cidr)))
                                IFS='.' read -r -a mask_octets <<< $(printf "%d.%d.%d.%d\n" $((mask >> 24 & 0xff)) $((mask >> 16 & 0xff)) $((mask >> 8 & 0xff)) $((mask & 0xff)))
                                subnet=$(IFS='.'; echo "${mask_octets[*]}")
								let "mask=$(echo $cidr | awk -F "." '{print $4}')+1"
                                }
                cidr_to_subnet $cidr
                nic=$(ip a s | grep eth | grep -v link | head -n 1 | cut -d: -f2)
                net=$(ip a s | grep inet | egrep -v "127|inet6" | awk '{print $2}' | cut -d"/" -f1)
                gw=$(echo $net | awk -v i=$mask -F"." '{ print $1"."$2"."$3"."i}')
                ip route add default via $gw dev $nic
                ip route add 168.63.129.16/32 via $gw dev $nic metric 100
                ip route add 169.254.169.254/32 via $gw dev $nic metric 100
                echo "ip route entries after NetworkTester ran" >> /tmp/NetLog$datetime
                ip route show >> /tmp/NetLog$datetime
                echo "************************" >> /tmp/NetLog$datetime
                echo -e "\n" >> /tmp/NetLog$datetime
                    ;;

                NO | No | no |n )
                echo "No changes made"
                ;;

                *)
                  echo "Please answer yes or no"
                ;;
esac;
fi
##DNS settings part
echo "DNS settings" >>/tmp/NetLog$datetime
cat /etc/resolv.conf >> /tmp/NetLog$datetime
echo "************************" >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime
if [[ "$rel" =~ 'rhel' ]]; then
    if [[ $(cat /etc/resolv.conf | grep -i nameserver | awk '{print $2}' | head -n1) == 168.63.129.16 ]] ;
    then echo "Nameserver 168.63.129.16 found" >> /tmp/NetLog$datetime ;
    else echo "The first Nameserver is not 168.63.129.16" >> /tmp/NetLog$datetime ;
    fi

elif [[ "$rel" =~ 'Oracle' ]]; then
    if [[ $(cat /etc/resolv.conf | grep -i nameserver | awk '{print $2}' | head -n1) == 168.63.129.16 ]] ;
    then echo "Nameserver 168.63.129.16 found" >> /tmp/NetLog$datetime ;
    else echo "The first Nameserver is not 168.63.129.16" >> /tmp/NetLog$datetime ;
    fi
elif [[ "$rel" =~ 'debian' ]]; then
    if [[ $(resolvectl | grep -i "current dns" | awk '{print $4}') == 168.63.129.16 ]] ;
    then echo "Nameserver 168.63.129.16 found" >> /tmp/NetLog$datetime ;
    elif  [[ $(resolvectl | grep -i "current dns" | awk '{print $4}') == 127.0.0.53 ]] ;
    then echo "Resolvectl points to systemd resolution: check /run/systemd/resolve/stub-resolv.conf and /run/systemd/resolve/resolv.conf" >> /tmp/NetLog$datetime ;
    elif [[ $(cat /etc/resolv.conf | grep -i nameserver | awk '{print $2}' | head -n1) == 168.63.129.16 ]] ;
    then echo "Nameserver 168.63.129.16 found" >> /tmp/NetLog$datetime ;
    else echo "The first Nameserver is not 168.63.129.16"
    fi
elif [[ "$rel" =~ 'SLES' ]]; then
    if [[ $(cat /etc/resolv.conf | grep -i nameserver | awk '{print $2}' | head -n1) == 168.63.129.16 ]] ;
    then echo "Nameserver 168.63.129.16 found" >> /tmp/NetLog$datetime ;
    else echo "The first Nameserver is not 168.63.129.16" >> /tmp/NetLog$datetime ;
    fi
else
    echo "not found" > /tmp/NetLog$datetime
        exit 1;
fi
##printing connections
echo "************************" >> /tmp/NetLog$datetime
echo "Active connections" >>/tmp/NetLog$datetime
ss -petua >> /tmp/NetLog$datetime
echo "************************" >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime

echo "IP Configurations" >>/tmp/NetLog$datetime
ip a s >> /tmp/NetLog$datetime
echo "************************" >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime

echo "Check Microsoft Connectivity" >> /tmp/NetLog$datetime
if [[ ! $(curl -m 5 -v www.microsoft.com) ]] ; then
                echo "DNS connection not working" >> /tmp/NetLog$datetime ;
        else curl -m 5 http://168.63.129.16/?comp=versions >> /tmp/NetLog$datetime
        echo -e "\n" >> /tmp/NetLog$datetime
        echo "DNS Connection OK" >> /tmp/NetLog$datetime ;
fi
echo -e "\n" >> /tmp/NetLog$datetime
echo "************************" >> /tmp/NetLog$datetime
##firewall connection settings
echo "Firewall Settings" >>/tmp/NetLog$datetime
grep FirewallBackend= /etc/firewalld/firewalld.conf >> /tmp/NetLog$datetime
if [[ $(grep "FirewallBackend=" /etc/firewalld/firewalld.conf) == FirewallBackend=iptables ]] ;
        then /usr/sbin/iptables -L >> /tmp/NetLog$datetime
        echo "************************" >> /tmp/NetLog$datetime
        echo -e "\n" >> /tmp/NetLog$datetime ;
        elif [[ $(grep "FirewallBackend=" /etc/firewalld/firewalld.conf) == FirewallBackend=nftables ]] ;
        then /usr/sbin/nft list ruleset >> /tmp/NetLog$datetime
        echo "************************" >> /tmp/NetLog$datetime
        echo -e "\n" >> /tmp/NetLog$datetime;
        else echo "Firewall not set/running" >> /tmp/NetLog$datetime
        echo "************************" >> /tmp/NetLog$datetime
        echo -e "\n" >> /tmp/NetLog$datetime;
 fi
## wireserver connection
echo "Check Wireserver connection" >>/tmp/NetLog$datetime
dig www.microsoft.com @168.63.129.16 1> /dev/null
if [[ $? -eq 9 ]] ; then
 echo "Wireserver communication not working: check https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16" >> /tmp/NetLog$datetime ;
else echo "Wireserver Connection OK" >> /tmp/NetLog$datetime
fi
echo "************************" >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime
## counting number of interfaces
echo "Count Number of interfaces" >>/tmp/NetLog$datetime
cat /proc/net/dev | egrep "eth*|lo" | grep -v face | wc -l >> /tmp/NetLog$datetime
echo "************************" >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime
## check for AN enabled and statistics
echo "Check AN" >>/tmp/NetLog$datetime
if [[ ! $(lsmod | grep -i mlx | awk '{print $1}') ]]; then
                echo "AN Disabled" >> /tmp/NetLog$datetime
                echo "AN not enabled, check available SKUS here: https://learn.microsoft.com/en-us/azure/virtual-network/accelerated-networking-overview" >> /tmp/NetLog$datetime
        else
                for i in $(ls /sys/class/net/); do
                                        echo $i && ethtool -S $i | grep -i "vf_" >> /tmp/NetLog$datetime;
                                done
                                for i in $(ls /sys/class/net/); do
                                        echo $i && ethtool -i $i >> /tmp/NetLog$datetime;
                                done
fi
echo "************************" >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime
## check for warning allerts in dmesg
echo "Check for Network entries in dmesg" >>/tmp/NetLog$datetime
dmesg | grep -i eth >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime
## check for changes in config files
echo "Check stat on net config files" >>/tmp/NetLog$datetime
if [[ "$rel" =~ 'rhel' ]]; then
    /usr/bin/stat /etc/sysconfig/network-scripts/ifcfg-eth* >> /tmp/NetLog$datetime ;
elif [[ "$rel" =~ 'Oracle' ]]; then
    /usr/bin/stat /etc/sysconfig/network-scripts/ifcfg-eth* >> /tmp/NetLog$datetime ;
elif [[ "$rel" =~ 'debian' ]]; then
    /usr/bin/stat /etc/netplan/*-cloud* >> /tmp/NetLog$datetime ;
elif [[ "$rel" =~ 'SLES' ]]; then
    /usr/bin/stat /etc/sysconfig/network-scripts/ifcfg-eth* >> /tmp/NetLog$datetime ;
else
    echo "no config file found for NIC" >> /tmp/NetLog$datetime ;
fi
echo "************************" >> /tmp/NetLog$datetime
## check for RH file entries in network config file
echo "check entries in /etc/sysconfig/networking file" >> /tmp/NetLog$datetime
cat /etc/sysconfig/network | egrep -v "^#" | sed '/^[[:space:]]*$/d' >> /tmp/NetLog$datetime
echo "************************" >> /tmp/NetLog$datetime
echo -e "\n" >> /tmp/NetLog$datetime

echo $datetime >> /tmp/NetLog$datetime
echo "END OF FILE" >> /tmp/NetLog$datetime
