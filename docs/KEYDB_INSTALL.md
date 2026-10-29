# How to Install KeyDB

This tutorial guides you through installing KeyDB.

---

## Part 1: KeyDB Installation

Choose the installation method that matches your operating system.

### Install on Linux (Ubuntu/Debian)

This is the recommended method for a production server.

1.  **Add the KeyDB PPA (Personal Package Archive):**
    ```bash
    curl -fsSL https://download.keydb.dev/open-source-dist/keyring.gpg | sudo gpg --dearmor -o /usr/share/keyrings/keydb-archive-keyring.gpg
    
    echo "deb [signed-by=/usr/share/keyrings/keydb-archive-keyring.gpg] https://download.keydb.dev/open-source-dist jammy main" | sudo tee /etc/apt/sources.list.d/keydb.list
    ```

2.  **Update and Install KeyDB:**
    ```bash
    sudo apt update
    sudo apt install keydb
    ```

3.  **Manage the KeyDB Service:**
    The installer automatically sets up KeyDB to run as a `systemd` service.
    ```bash
    # Start the service
    sudo systemctl start keydb-server
    
    # Check its status
    sudo systemctl status keydb-server
    
    # Enable it to start on boot
    sudo systemctl enable keydb-server
    ```
    The configuration file is located at: `/etc/keydb/keydb.conf`. You can use the example config file in this bob repository `exampleConfigFile/keydb.conf`
4. Setting the `maxmemory` field in config file so that it fits your machine. Bob usually consumes 5-6gb 
