program:
	openssl genrsa -out ca.key 4096
	openssl req -new -x509 -days 1826 -key ca.key -out ca.crt
	chmod a+x mitm_attack parse_log pharm_attack
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -F
	sudo iptables -t nat -F
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443

clean:
	-rm connect.log tmp.log