# Configuration Reference

This document describes the JSON configuration consumed by the application. It covers required and optional fields, types, defaults, validation rules, and how different options interact.

The configuration must be a single JSON object (root must be an object). Invalid JSON or incorrect types produce descriptive errors.

## Quick Start

- The root must be a JSON object.
- You must provide:
    - arbitrator-identity (string)
    - At least one of trusted-node (array of strings) or p2p-node (array of strings) must be present and non-empty.
- Other fields are optional and have sensible defaults (where applicable).

## How to Find Your Configuration File

The configuration file is typically named `bob.json` and should be located in the same folder as your Bob program. When you start Bob, it will look for this file in the current directory by default.

If you want to use a different configuration file, you can specify its path when starting Bob:
```
./bob /path/to/your/custom_config.json
```

## Understanding Configuration Settings

### Basic Node Information

**`node-seed`**
- **What it does:** This is your node's secret key that creates your unique identity on the Qubic network
- **Default value:** `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- **Important note:** For security, you should change this to a random 55-character lowercase string

**`node-alias`**
- **What it does:** A nickname for your node that others can see when they connect to your node
- **Default value:** `"Big fat bob"`

### Network Settings

**`p2p-nodes`**
- **What it does:** Lists other Bob nodes you want to connect to directly
- **Default value:** Empty (will automatically find peers from qubic.global)
- **Example:** `["192.168.1.100:21842", "10.0.0.50:21842"]`

**`is-testnet`**
- **What it does:** Tells Bob whether to connect to the test network or main network
- **Default value:** `false` (main network)
- **Use case:** Set to `true` if you're testing things

### Logging and Debugging

**`log-level`**
- **What it does:** Controls how much information your node logs to the screen or file
- **Options:** `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`, `"fatal"`
- **Default value:** `"info"`

### Storage Settings (Important!)

**`tick-storage-mode`**
- **What it does:** Determines how your node stores information about network ticks (the equivalent of blockchain blocks)
- **Options:**
  - `lastNTick`: Stores only the most recent N ticks in memory
  - `kvrocks`: Uses a special database for storage
  - `free`: Doesn't store anything (for advanced users)

**`tx-storage-mode`**
- **What it does:** Determines how your node stores transaction information
- **Options:** Same as tick-storage-mode
- **Default value:** `lastNTick`

**`last_n_tick_storage`**
- **What it does:** When using `lastNTick` mode, this sets how many recent ticks to keep in memory
- **Default value:** `1000`
- **Note:** Higher values = more memory usage but better performance

### Database Connections

**`keydb-url`**
- **What it does:** Where your node connects to store data (KeyDB is a Redis-compatible database)
- **Default value:** Not set by default
- **Example:** `"redis://localhost:6379"`

**`kvrocks-url`**
- **What it does:** Where your node connects to store data when using `kvrocks` storage mode
- **Default value:** `"tcp://127.0.0.1:6666"`

### Performance Settings

**`max-thread`**
- **What it does:** Sets the maximum number of computer processor threads Bob can use
- **Default value:** `0` (automatically uses all available cores)
- **Note:** Setting this to a specific number can help control system resource usage

**`request-cycle-ms`**
- **What it does:** How often Bob checks for new network data (in milliseconds)
- **Default value:** `0` (uses default timing)

**`server-port`**
- **What it does:** The port number where your node will accept direct connections from other nodes
- **Default value:** `21842`
- **Note:** Must be between 1 and 65535

### RPC Settings

**`rpc-port`**
- **What it does:** The port number for external applications to connect to your node's API
- **Default value:** `40420`

**`enable-admin-endpoints`**
- **What it does:** Allows access to special administrative functions (use with caution)
- **Default value:** `false`
- **Security note:** Only enable if you need admin access

### Security and Privacy

**`allow-check-in-qubic-global`**
- **What it does:** Controls whether your node reports its presence to the main Qubic network
- **Default value:** `true`

**`allow-receive-log-from-incoming-connections`**
- **What it does:** Allows other nodes to send log information directly to your node
- **Default value:** `false`

### Advanced Settings

**`spam-qu-threshold`**
- **What it does:** Helps identify and ignore spam transactions with very small amounts
- **Default value:** `0` (disabled)

**`n-tickdata-to-store`**
- **What it does:** How many tick data items to keep in memory when using certain storage modes
- **Default value:** `5`

**`indexer-max-activities-per-key`**
- **What it does:** Limits how many activities are indexed per key for performance reasons
- **Default value:** `100000`

## Example Configuration File

Here's a basic example of what a configuration file might look like:

```json
{
  "node-seed": "your_random_55_character_seed_here",
  "node-alias": "My Bob Node",
  "log-level": "info",
  "p2p-nodes": [],
  "is-testnet": false,
  "tick-storage-mode": "kvrocks",
  "tx-storage-mode": "kvrocks",
  "last_n_tick_storage": 1000,
  "server-port": 21842,
  "rpc-port": 40420,
  "enable-admin-endpoints": false
}
```

## Important Notes

1. **File Format:** The configuration file must be valid JSON format - this means it uses proper brackets, commas, and quotes.

2. **Security:** Never share your node-seed with anyone as it gives full control over your node.

3. **Testing:** If you're testing, set `is-testnet` to `true` to avoid affecting the main network.

4. **Performance:** Adjust memory-related settings based on your computer's available resources.

5. **Backup:** Always keep a backup of your configuration file before making changes.

## Troubleshooting Common Issues

**Problem: Node won't start**
- Check that the JSON syntax is correct (no trailing commas, proper quotes)
- Verify all required fields are present
- Make sure file permissions allow reading

**Problem: Node connects to wrong network**
- Check that `is-testnet` is set correctly for your needs

**Problem: High memory usage**
- Reduce `last_n_tick_storage` value
- Consider using different storage modes

Remember, this configuration file gives you complete control over how your Qubic Bob node operates. Start with the default settings and only change what you understand and need to change.

## Default config

~~~json
{
  "request-cycle-ms": 300,
  "request-logging-cycle-ms": 10,
  "future-offset": 32,
  "log-level": "info",
  "keydb-url": "tcp://127.0.0.1:6379",
  "run-server": true,
  "server-port": 21842,
  "arbitrator-identity": "AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ",
  "tick-storage-mode": "kvrocks",
  "kvrocks-url": "tcp://127.0.0.1:6666",
  "tx-storage-mode": "kvrocks",
  "tx_tick_to_live": 100000,
  "max-thread": 6,
  "spam-qu-threshold": 0
}
~~~