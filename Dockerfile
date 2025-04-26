FROM debian:12

RUN apt update && apt install -y \
    openssh-server vsftpd samba apache2 mariadb-server postgresql redis-server telnetd nfs-kernel-server php libapache2-mod-php snmp nmap curl net-tools vim wget

COPY install_insecure_services.sh /root/
COPY detect_vulnerabilities.sh /root/
COPY generate_report.sh /root/

RUN chmod +x /root/*.sh

CMD ["tail", "-f", "/dev/null"]
