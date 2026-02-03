# How to Tune Kernel Network Buffer Sizes (rmem_max & wmem_max)

This tutorial explains how to view and increase the maximum network socket send (TX) and receive (RX) buffer sizes in Linux.

* `net.core.wmem_max`: The maximum **send** (write) buffer size, in bytes, that a single socket can allocate. This is for TX (Transmission).

* `net.core.rmem_max`: The maximum **receive** (read) buffer size, in bytes, that a single socket can allocate. This is for RX (Reception).

Tuning these values can sometimes improve network performance, especially on high-speed (e.g., 10Gb+) or high-latency (long-distance) networks. It allows the kernel to buffer more data for a connection, which can help saturate the link.

### **Warning: Read This First!**

Changing kernel parameters can affect system stability and performance. For most standard desktop or server workloads (e.g., web browsing, local file sharing, simple web hosting), **the default values are sufficient.**

Only change these values if you are trying to solve a specific, measurable network performance problem (like packet loss or an inability to reach full bandwidth on a high-speed, high-latency link) and you understand the risk. Increasing buffers too much can consume significant kernel memory and potentially *increase* latency (a problem known as "bufferbloat").

### 1. Check Your Current Values

Before making changes, check your system's current default values. The values are in bytes.
```
# Check current max receive buffer size
sysctl net.core.rmem_max

# Check current max send buffer size
sysctl net.core.wmem_max
```
You will likely see an output like `net.core.rmem_max = 212992`, which is 208KB.

### 2. How to Change Values Temporarily (for Testing)

This method is for testing only. **These changes will be lost after you reboot.**

We will use `sysctl -w` to "write" a new value. You must run these commands as root or with `sudo`.

Let's say you want to test a new value of 16MB.
(16MB = 16 \* 1024 \* 1024 = **16777216** bytes)
```
Example: Set max receive buffer to 16MB
sudo sysctl -w net.core.rmem_max=16777216

Example: Set max send buffer to 16MB
sudo sysctl -w net.core.wmem_max=16777216
```
You can immediately verify the change by running the check commands from Step 1 again. Now is the time to run your network performance tests (e.g., with `iperf3`) to see if this change actually helped.

### 3. How to Make Changes Permanent (Survive Reboot)

Once you have tested your values and are confident you want to keep them, you must add them to a `sysctl` configuration file.

The best practice is to create a new, custom configuration file in the `/etc/sysctl.d/` directory.

#### a. Create a new configuration file

Use a text editor like `nano` or `vim` to create a file. We'll call it `90-network-buffers.conf` (the `90-` prefix ensures it's loaded late in the boot sequence, overriding defaults).

`sudo nano /etc/sysctl.d/90-network-buffers.conf`

#### b. Add your settings to this file

Add the following lines to the file. This is a configuration file, so **do not** use `sudo` or `sysctl -w` inside the file. Use the `key = value` format.

Custom network buffer settings:
```
Set max RX buffer to 16MB
net.core.rmem_max = 16777216

Set max TX buffer to 16MB
net.core.wmem_max = 16777216
```

Save the file and exit the text editor.

#### c. Apply the changes immediately

The system will read this file automatically on the next reboot. To apply the settings *now* without rebooting, run the following command:
```
Load all sysctl configuration files, including your new one
sudo sysctl --system
```

This command will parse all files in `/etc/sysctl.d/` and `/etc/sysctl.conf` and apply the settings. Your changes are now active and will persist after a reboot. You can verify again using `sysctl net.core.rmem_max`.

### How to Revert Your Changes

If your changes cause problems, you can easily revert them.

1. **To revert temporary changes:** Simply reboot your machine.

2. **To revert permanent changes:**

    * Delete the file you created: `sudo rm /etc/sysctl.d/90-network-buffers.conf`

    * ...or, edit the file (`sudo nano /etc/sysctl.d/90-network-buffers.conf`) and put a `#` at the beginning of each line to comment it out.

    * After deleting or commenting, run `sudo sysctl --system` again to re-load the default values.