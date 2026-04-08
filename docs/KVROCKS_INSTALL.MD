### One-line command
~~~
apt update; apt install -y git gcc g++ make cmake autoconf automake libtool python3 libssl-dev;
git clone https://github.com/apache/kvrocks.git; cd kvrocks; ./x.py build -j16;
~~~

This guide will show you how to install kvrocks into systemd

Add new user: `useradd -r -s /bin/false kvrocks`

Create `kvrocks` working folder, and copy the built binary. Then copy the config file, you can use the example config file in this bob repository `exampleConfigFile/kvrocks.conf`
~~~
mkdir /var/lib/kvrocks/;
cd /var/lib/kvrocks/;
cp ~/kvrocks/build/kvrocks .;
cp ~/qubicbob/exampleConfigFile/kvrocks.conf .;
~~~

Create DB folder:
```
mkdir /kvrocksDB/;
chown -R kvrocks:kvrocks /var/lib/kvrocks/;
chown -R kvrocks:kvrocks /kvrocksDB/;
```

Create service file: `vi /etc/systemd/system/kvrocks.service`
```
[Unit]
Description=Apache Kvrocks - NoSQL Database backed by RocksDB
Documentation=https://kvrocks.apache.org/
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Best practice: Run as a dedicated user, not root
User=kvrocks
Group=kvrocks

# POINT THIS TO YOUR BINARY AND CONFIG
ExecStart=/var/lib/kvrocks/kvrocks -c /var/lib/kvrocks/kvrocks.conf

# Working directory (useful if relative paths are used in config)
WorkingDirectory=/var/lib/kvrocks/

# CRITICAL FOR ROCKSDB PERFORMANCE
# RocksDB keeps many SST files open. Default linux limit (1024) is too low.
LimitNOFILE=100000
# Allow unlimited core dumps for debugging
LimitCORE=infinity

# Restart policy
Restart=on-failure
RestartSec=5s

# Security hardening (optional but recommended)
# PrivateTmp=true
# NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Reload the daemon and start kvrocks:
~~~
systemctl daemon-reload;
systemctl enable kvrocks;
systemctl start kvrocks;
~~~