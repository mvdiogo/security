FROM debian:12

# Set locale to avoid potential issues
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

# Install all necessary packages
# Added netcat-openbsd for telnetd dependencies, and some common tools
RUN apt update && apt install -y \
    openssh-server \
    proftpd \
    samba \
    apache2 \
    mariadb-server \
    postgresql \
    redis-server \
    telnetd \
    openbsd-inetd \
    netcat-openbsd \
    nfs-kernel-server \
    rpcbind \
    php \
    libapache2-mod-php \
    snmp \
    snmpd \
    nmap \
    curl \
    net-tools \
    vim \
    wget \
    supervisor \
    procps \
    systemctl \
    && rm -rf /var/lib/apt/lists/*

# Create necessary users and directories
RUN useradd -m -s /bin/bash testuser && \
    echo 'testuser:password123' | chpasswd && \
    echo 'root:root123' | chpasswd && \
    mkdir -p /srv/samba/insecure_share && \
    mkdir -p /srv/ftp/incoming && \
    mkdir -p /srv/nfs/insecure_share && \
    mkdir -p /var/log/supervisor && \
    mkdir -p /run/sshd && \
    mkdir -p /var/run/postgresql && \
    mkdir -p /var/run/mysqld && \
    mkdir -p /var/log/mysql && \
    chown -R postgres:postgres /var/run/postgresql && \
    chown -R postgres:postgres /var/lib/postgresql /var/lib/postgresql/15/main && \
    chmod -R 750 /var/run/postgresql /var/lib/postgresql/15/main /var/lib/postgresql && \
    chmod 777 /srv/samba/insecure_share && \
    chmod 777 /srv/nfs/insecure_share && \
    chown nobody:nogroup /srv/ftp && \
    chmod 755 /srv/ftp && \
    chown mysql:mysql /var/run/mysqld

# Copy scripts
COPY install_insecure_services.sh /root/
COPY detect_vulnerabilities.sh /root/
COPY generate_report.sh /root/
COPY supervisord.conf /etc/supervisor/conf.d/

# Give permissions to scripts
RUN chmod +x /root/*.sh

# Configure basic services and ensure their directories are correct
# Also initialize MariaDB if it's not already.
RUN /root/install_insecure_services.sh && \
    # Clean up default MariaDB config to avoid conflicts with custom one
    rm -f /etc/mysql/mariadb.conf.d/50-server.cnf && \
    # Initialize MariaDB data directory if it doesn't exist
    if [ ! -d "/var/lib/mysql/mysql" ]; then \
        mysql_install_db --user=mysql --datadir=/var/lib/mysql; \
    fi && \
    # Start MariaDB temporarily to set root password and allow remote connections
    (mysqld_safe --skip-grant-tables &) && \
    sleep 10 && \
    mysql -uroot -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '';" && \
    mysql -uroot -e "FLUSH PRIVILEGES;" && \
    mysql -uroot -e "CREATE DATABASE IF NOT EXISTS test_db;" && \
    mysql -uroot -e "CREATE USER 'testuser'@'%' IDENTIFIED BY 'testpassword';" && \
    mysql -uroot -e "GRANT ALL PRIVILEGES ON test_db.* TO 'testuser'@'%';" && \
    mysql -uroot -e "FLUSH PRIVILEGES;" && \
    killall mysqld_safe || true && \
    # Start PostgreSQL temporarily to allow remote connections and set password
    service postgresql start && \
    systemctl start supervisor && \
    systemctl enable supervisor && \
    sleep 5 && \
    sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'postgres';" && \
    sudo -u postgres psql -c "CREATE DATABASE vulnerable_db;" && \
    service postgresql stop && \
    # Enable Apache modules
    a2enmod php || true && \
    a2enmod rewrite || true && \
    # Enable Telnet via inetd (inetd needs to be started by supervisor)
    echo "telnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd" >> /etc/inetd.conf && \
    # Clean up apt caches
    apt clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Expose all necessary ports (these are for documentation, actual exposure is in docker-compose)
EXPOSE 22 21 80 3306 5432 6379 23 111 2049 161/udp 445 139

# Use supervisor to manage multiple services
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]