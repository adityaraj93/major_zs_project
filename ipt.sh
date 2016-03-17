echo "Sniffer's address: "
read sn_ip

sudo iptables -I FORWARD -i docker0 -j TEE --gateway $sn_ip
sudo iptables -I FORWARD -o docker0 -j TEE --gateway $sn_ip
