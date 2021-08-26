#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "Please run this script as root" 1>&2
	exit 1
fi

debian_init() {
	echo "Updating and installing dependicies"
	apt update -y
	apt upgrade -y
	apt install git nmap golang dnsutils unzip -y

	update-rc.d nfs-common disable > /dev/null 2>&1
	update-rc.d rpcbind disable > /dev/null 2>&1

	echo "Changing Hostname"

	read -p "Enter your hostname: " -r primary_domain

	cat <<-EOF > /etc/hosts
	127.0.1.1 $primary_domain $primary_domain
	127.0.0.1 localhost
	EOF

	cat <<-EOF > /etc/hostname
	$primary_domain
	EOF

	echo

	echo "The system will now reboot !"
	echo
	echo "3..."
	sleep 1
	echo "2..."
	sleep 1
	echo "1..."
	sleep 1
	reboot
}


firewall() {
	apt install iptables-persistent -y

	iptables -F
	echo "Current iptables rules flushed !"
	sleep 1
	cat <<-ENDOFRULES > /etc/iptables/rules.v4
	*filter

	# Allow all loopback (lo) traffic and reject anything to localhost that does not originate from lo.
	-A INPUT -i lo -j ACCEPT
	-A INPUT ! -i lo -s 127.0.0.0/8 -j REJECT
	-A OUTPUT -o lo -j ACCEPT

	# Allow ping and ICMP error returns.
	-A INPUT -p icmp -m state --state NEW --icmp-type 8 -j ACCEPT
	-A INPUT -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT
	-A OUTPUT -p icmp -j ACCEPT

	# Allow SSH.
	-A INPUT -i  eth0 -p tcp -m state --state NEW,ESTABLISHED --dport 22 -j ACCEPT
	-A OUTPUT -o eth0 -p tcp -m state --state NEW,ESTABLISHED --sport 22 -j ACCEPT

	# Allow DNS resolution and limited HTTP/S on eth0.
	# Necessary for updating the server and keeping time.
	-A INPUT  -p udp -m state --state NEW,ESTABLISHED --sport 53 -j ACCEPT
	-A OUTPUT  -p udp -m state --state NEW,ESTABLISHED --dport 53 -j ACCEPT
	-A INPUT  -p tcp -m state --state ESTABLISHED --sport 80 -j ACCEPT
	-A INPUT  -p tcp -m state --state ESTABLISHED --sport 443 -j ACCEPT
	-A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 80 -j ACCEPT
	-A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 443 -j ACCEPT

	# Allow Mail Server (IMAP, SMTP) Traffic outbound
	-A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 143 -j ACCEPT
	-A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 587 -j ACCEPT
	-A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 993 -j ACCEPT
	-A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 25 -j ACCEPT

	# Allow Mail Server (IMAP, SMTP) Traffic inbound
	-A INPUT  -p tcp -m state --state NEW,ESTABLISHED --sport 143 -j ACCEPT
	-A INPUT  -p tcp -m state --state NEW,ESTABLISHED --sport 587 -j ACCEPT
	-A INPUT  -p tcp -m state --state NEW,ESTABLISHED --sport 993 -j ACCEPT
	-A INPUT  -p tcp -m state --state NEW,ESTABLISHED --sport 25 -j ACCEPT

	COMMIT
	ENDOFRULES

	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT DROP

	echo "Loading new firewall rules..."
	iptables-restore /etc/iptables/rules.v4
	echo "Firewall configuration done !"
}



ssl_cert() {
	echo -e "Remember to setup an A record and to open port 80 or 443 in order for certbot to establish a connection to generate certificates..."
    sleep 4
	echo
    apt install certbot -y
	echo
    read -rp "Enter your server's domain : " -r domain
	echo
    read -rp "Do you wish to configure an email address to be alerted about the renewal of the certificate ? (yY/nN) " answer
	echo
	case ${answer:0:1} in
		y|Y )
			while true
				do
					read -p "Enter your email address : " -r email_address
					if [[ "$email_address" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]
					then
						echo "Email address $email_address is valid."
						break
					else
						echo "Email address $email_address is invalid ! Please verify your input."
					fi
				done
			certbot certonly --noninteractive -m "$email_address" --agree-tos --standalone -d "$domain"
		;;
		* )
			certbot certonly --noninteractive --register-unsafely-without-email --agree-tos --standalone -d "$domain"
		;;
	esac

    ls -l /etc/letsencrypt/live/"$domain"/fullchain.pem
    ls -l /etc/letsencrypt/live/"$domain"/privkey.pem

	sleep 2
}

install_postfix() {
	echo "Installing Dependicies"
	apt install postfix postgrey postfix-policyd-spf-python -y
	apt install opendkim opendkim-tools -y
	apt install opendmarc -y
	apt install mailutils -y

	read -p "Enter your mail server's domain: " -r primary_domain
	read -p "Enter IP's to allow Relay (if none just hit enter): " -r relay_ip
	echo "Configuring Postfix"

	# https://postfix.traduc.org/index.php/postconf_trie.html

	cat <<-EOF > /etc/postfix/main.cf
	smtpd_banner = \$myhostname ESMTP \$mail_name (Debian/GNU)
	biff = no
	append_dot_mydomain = no
	readme_directory = no
	smtpd_tls_cert_file=/etc/letsencrypt/live/${primary_domain}/fullchain.pem
	smtpd_tls_key_file=/etc/letsencrypt/live/${primary_domain}/privkey.pem
	smtpd_tls_security_level = may
	smtp_tls_security_level = encrypt
	smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
	smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
	smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
	myhostname = ${primary_domain}
	alias_maps = hash:/etc/aliases
	alias_database = hash:/etc/aliases
	myorigin = /etc/mailname
	mydestination = ${primary_domain}, localhost.com, , localhost
	relayhost =
	mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 ${relay_ip}
	mailbox_command = procmail -a "\$EXTENSION"
	mailbox_size_limit = 0
	recipient_delimiter = +
	inet_interfaces = all
	inet_protocols = ipv4
	milter_default_action = accept
	milter_protocol = 6
	smtpd_milters = inet:12301,inet:localhost:54321
	non_smtpd_milters = inet:12301,inet:localhost:54321
	EOF

	cat <<-EOF >> /etc/postfix/master.cf
	submission inet n       -       -       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_wrappermode=no
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
	EOF

	echo "Configuring Opendkim"

	mkdir -vp "/etc/opendkim/keys/${primary_domain}"
	cp -v /etc/opendkim.conf /etc/opendkim.conf.orig

	# http://www.opendkim.org/opendkim.conf.5.html
	cat <<-EOF > /etc/opendkim.conf
	domain						*
	AutoRestart					Yes
	AutoRestartRate				10/1h
	Umask						0002
	Syslog						Yes
	SyslogSuccess				Yes
	LogWhy						Yes
	Canonicalization			relaxed/simple
	ExternalIgnoreList			refile:/etc/opendkim/TrustedHosts
	InternalHosts				refile:/etc/opendkim/TrustedHosts
	KeyFile						/etc/opendkim/keys/${primary_domain}/mail.private
	Selector					mail
	Mode						sv
	SignatureAlgorithm			rsa-sha256
	UserID						opendkim:opendkim
	Socket						inet:12301@localhost
	EOF

	cat <<-EOF > /etc/opendkim/TrustedHosts
	127.0.0.1
	localhost
	${primary_domain}
	${relay_ip}
	EOF

	cd /etc/opendkim/keys/"${primary_domain}" || exit
	opendkim-genkey -s mail -d "${primary_domain}"
	echo 'SOCKET="inet:12301"' >> /etc/default/opendkim
	chown -vR opendkim:opendkim /etc/opendkim

	echo "Configuring opendmarc"

	chown -vR opendmarc:opendmarc /var/run/opendmarc/

	# https://manpages.debian.org/unstable/opendmarc/opendmarc.conf.5.en.html
	cat <<-EOF > /etc/opendmarc.conf
	AuthservID ${primary_domain}
	PidFile /var/run/opendmarc/opendmarc.pid
	RejectFailures false
	Syslog true
	TrustedAuthservIDs ${primary_domain}
	Socket  inet:54321@localhost
	UMask 0002
	UserID opendmarc:opendmarc
	IgnoreHosts /etc/opendmarc/ignore.hosts
	HistoryFile /var/run/opendmarc/opendmarc.dat
	EOF

	mkdir "/etc/opendmarc/"
	echo "localhost" > /etc/opendmarc/ignore.hosts
	chown -R opendmarc:opendmarc /etc/opendmarc

	echo 'SOCKET="inet:54321"' >> /etc/default/opendmarc

	read -p "What user would you like to assign to receive email for Root: " -r user_name
	echo "${user_name}: root" >> /etc/aliases
	echo "Root email assigned to ${user_name}"

	sleep 1

	echo "Restarting services..."
	systemctl restart postfix
	systemctl restart opendkim
	systemctl restart opendmarc

	echo "Checking services status..."
	systemctl --no-pager status postfix 
	systemctl --no-pager status opendkim 
	systemctl --no-pager status opendmarc

	sleep 2
}

function add_alias(){
	read -p "What email address do you want to assign: " -r email_address
	read -p "What user do you want to assign to that email address: " -r user
	echo "${email_address}: ${user}" >> /etc/aliases
	newaliases
	echo "${email_address} assigned to ${user}"
	sleep 2
}

function dns_entries(){
	extip=$(curl -s ipinfo.me)
	domain=$(ls /etc/opendkim/keys/ | head -1)
	dkimrecord=$(cut -d '"' -f 2 "/etc/opendkim/keys/${domain}/mail.txt" | tr -d "[:space:]")

	echo
	cat <<-EOF > dnsentries.txt
	DNS Entries for ${domain}:

	====================================================================

	Record Type: A
	Host: @
	Value: ${extip}
	TTL: 5 min

	Record Type: TXT
	Host: @
	Value: v=spf1 ip4:${extip} -all
	TTL: 5 min

	If you are using a subdomain, you MUST put the sub part of your it after "domainkey". Ex : For a subdomain like toto.gouv.fr it would give : mail._domain.toto
	Record Type: TXT
	Host: mail._domainkey
	Value: ${dkimrecord}
	TTL: 5 min

	Record Type: TXT
	Host: ._dmarc
	Value: v=DMARC1; p=reject
	TTL: 5 min

	Change Mail Settings to Custom MX and Add New Record
	Record Type: MX
	Host: @
	Value: ${domain}
	Priority: 10
	TTL: 5 min
	EOF

	cat dnsentries.txt

	dir=$(pwd)
	echo
	echo "You can find this file at this path : $dir/dnsentries.txt"
	
	sleep 2
}


function Install_GoPhish {
	mkdir -vp /opt/gophish
	cd /opt/gophish || exit
	wget https://github.com/gophish/gophish/releases/download/v0.11.0/gophish-v0.11.0-linux-64bit.zip
	unzip -v gophish-v0.11.0-linux-64bit.zip
	useradd -r gophish
	mkdir -vp /var/log/gophish
	chown -v gophish:gophish /var/log/gophish
	chown -vR gophish:gophish /opt/gophish
	setcap 'cap_net_bind_service=+ep' gophish
    sed -i 's/"listen_url" : "127.0.0.1:3333"/"listen_url" : "0.0.0.0:3333"/g' config.json
	read -r -p "Do you want to add an SSL certificate to your GoPhish? [y/N] " response
	case "$response" in
	[yY][eE][sS]|[yY])
        	 read -p "Enter your web server's domain: " -r primary_domain
		 	if [ -f "/etc/letsencrypt/live/${primary_domain}/fullchain.pem" ];then
		 		ssl_cert="/etc/letsencrypt/live/${primary_domain}/fullchain.pem"
       		 	ssl_key="/etc/letsencrypt/live/${primary_domain}/privkey.pem"
       		 	cp "$ssl_cert" "${primary_domain}".crt
        	 	cp "$ssl_key" "${primary_domain}".key
        	 	sed -i "s/0.0.0.0:80/0.0.0.0:443/g" config.json
        	 	sed -i "s/gophish_admin.crt/${primary_domain}.crt/g" config.json
        	 	sed -i "s/gophish_admin.key/${primary_domain}.key/g" config.json
				sed -i 's/"use_tls" : false/"use_tls" : true/g' config.json
        	 	sed -i "s/example.crt/${primary_domain}.crt/g" config.json
        	 	sed -i "s/example.key/${primary_domain}.key/g" config.json
		 	else
				echo "Certificate not found, use Install SSL option first"
		 	fi
       		 	;;
    		*)
        		echo "GoPhish installed"
        		;;
	esac

	echo "Configuration of the GoPhish systemd service..."
	sleep 1

	touch /etc/systemd/system/gophish.service
	cat <<-EOF > /etc/systemd/system/gophish.service
	[Unit]
	Description=Gophish 
	Documentation=https://getgophish.com/documentation/
	After=network.target

	[Service]
	Type=simple
	WorkingDirectory=/opt/gophish
	User=gophish
	ExecStart=/opt/gophish/gophish
	CapabilityBoundingSet=CAP_NET_BIND_SERVICE

	[Install]
	WantedBy=multi-user.target
	EOF

cat /etc/systemd/system/gophish.service
sleep 2
}


PS3="Server Setup Script - Pick an option: "
options=("Debian Initialization" "Firewall Configuration" "Install SSL Cert" "Install Mail Server" "Add Aliases" "Get DNS Entries" "Install GoPhish")
select opt in "${options[@]}" "Quit"; do

    case "$REPLY" in

	1) debian_init;;

	2) firewall;;

	3) ssl_cert;;

	4) install_postfix;;

	5) add_alias;;

	6) dns_entries;;

	7) Install_GoPhish;;

    $(( ${#options[@]}+1 )) ) echo "Goodbye!"; break;;
    *) echo "Invalid option. Try another one.";continue;;

    esac

done
