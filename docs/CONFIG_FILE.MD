# Configuration Reference

This document describes the JSON configuration consumed by the application. It covers required and optional fields, types, defaults, validation rules, and how different options interact.

The configuration must be a single JSON object (root must be an object). Invalid JSON or incorrect types produce descriptive errors.

Keys officially use `_` (e.g. `log_level`). Keys are lowercased and `-` is converted to `_` on load, so legacy `-` keys still work.

## Quick Start

- The root must be a JSON object.
- You must provide:
    - arbitrator_identity (string)
- p2p_node (array of strings) is optional; if empty or omitted, Bob finds peers automatically (peer discovery).
- Other fields are optional and have sensible defaults (where applicable).

## How to Find Your Configuration File

The configuration file is typically named `bob.json` and should be located in the directory you start Bob from. When you start Bob without a path, it looks for `bob.json` in the current working directory.

If you want to use a different configuration file, you can specify its path when starting Bob:
```
./bob /path/to/your/custom_config.json
```

## Understanding Configuration Settings

### Basic Node Information

**`node_seed`**
- **What it does:** This is your node's secret key that creates your unique identity on the Qubic network
- **Default value:** `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- **Important note:** For security, you should change this to a random 55-character lowercase string

**`node_alias`**
- **What it does:** A nickname for your node that others can see when they connect to your node
- **Default value:** `"Big fat bob"`

### Network Settings

**`p2p_node`**
- **What it does:** Lists other nodes you want to connect to directly
- **Default value:** Empty (will automatically find peers from qubic.global)
- **Format:** `BM:IP:PORT[:P0-P1-P2-P3]` or `bob:IP:PORT[:P0-P1-P2-P3]` (the `BM:`/`bob:` prefix is required)
- **Example:** `["bob:192.168.1.100:21842", "bob:10.0.0.50:21842"]`

**`is_testnet`**
- **What it does:** Currently ignored (Bob always runs on main network). The key is parsed but has no effect
- **Default value:** `false`

### Logging and Debugging

**`log_level`**
- **What it does:** Controls how much information your node logs to the screen or file
- **Options:** `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`, `"critical"`, `"off"`
- **Default value:** None. If omitted (or set to an unknown name), logging is off, so set it explicitly (e.g. `"info"`)

### Storage Settings (Important!)

**`tick_storage_mode`**
- **What it does:** Determines how your node stores information about network ticks (the equivalent of blockchain blocks)
- **Options:**
  - `lastNTick`: Stores only the most recent N ticks in memory
  - `kvrocks`: Uses a special database for storage
  - `free`: Never deletes old data; everything stays in KeyDB (for advanced users)

**`tx_storage_mode`**
- **What it does:** Determines how your node stores transaction information
- **Options:** Same as tick_storage_mode
- **Default value:** `lastNTick`

**`last_n_tick_storage`**
- **What it does:** When using `lastNTick` mode, this sets how many recent ticks to keep in memory
- **Default value:** `1000`
- **Note:** Higher values = more memory usage but better performance

### Database Connections

**`keydb_url`**
- **What it does:** Where your node connects to store data (KeyDB is a Redis-compatible database)
- **Default value:** Not set by default
- **Example:** `"redis://localhost:6379"`

**`kvrocks_url`**
- **What it does:** Where your node connects to store data when using `kvrocks` storage mode
- **Default value:** `"tcp://127.0.0.1:6666"`

### Performance Settings

**`max_thread`**
- **What it does:** Sets the maximum number of computer processor threads Bob can use
- **Default value:** `0` (automatically uses all available cores)
- **Note:** Setting this to a specific number can help control system resource usage

**`request_cycle_ms`**
- **What it does:** How often Bob checks for new network data (in milliseconds)
- **Default value:** `0` (no delay between request rounds; `100` is typical and used in shipped configs)

**`server_port`**
- **What it does:** The port number where your node will accept direct connections from other nodes
- **Default value:** None (`0`). Must be set when `run_server` is `true`, otherwise Bob exits with "Invalid server_port"; shipped configs use `21842`
- **Note:** Must be between 1 and 65535

### RPC Settings

**`rpc_port`**
- **What it does:** The port number for external applications to connect to your node's API
- **Default value:** `40420`

**`enable_admin_endpoints`**
- **What it does:** Allows access to special administrative functions (use with caution)
- **Default value:** `false`
- **Security note:** Only enable if you need admin access

### Security and Privacy

**`allow_check_in_qubic_global`**
- **What it does:** Controls whether your node reports its presence to the main Qubic network
- **Default value:** `true`

**`allow_receive_log_from_incoming_connections`**
- **What it does:** Allows other nodes to send log information directly to your node
- **Default value:** `false`

**`autoban`**
- **What it does:** Rotates out a discovered peer that fails most of bob's log requests (two bad windows in a row) and keeps its IP out of discovery: 10 min if it answers but has no logs, 12 h if it does not answer at all. Static `p2p_node` peers are never judged. Only matters with peer discovery on.
- **Default value:** `false`

### Advanced Settings

**`spam_qu_threshold`**
- **What it does:** Helps identify and ignore spam transactions with very small amounts
- **Default value:** `0` (disabled)

**`n_tickdata_to_store`**
- **What it does:** How many tick data items to keep in memory when using certain storage modes
- **Default value:** `5`

**`indexer_max_activities_per_key`**
- **What it does:** Limits how many activities are indexed per key for performance reasons
- **Default value:** `100000`

## Example Configuration File

Here's a basic example of what a configuration file might look like:

```json
{
  "node_seed": "your_random_55_character_seed_here",
  "node_alias": "My Bob Node",
  "log_level": "info",
  "arbitrator_identity": "AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ",
  "p2p_node": [],
  "tick_storage_mode": "kvrocks",
  "tx_storage_mode": "kvrocks",
  "last_n_tick_storage": 1000,
  "server_port": 21842,
  "rpc_port": 40420,
  "enable_admin_endpoints": false
}
```

## Important Notes

1. **File Format:** The configuration file must be valid JSON format - this means it uses proper brackets, commas, and quotes.

2. **Security:** Never share your node_seed with anyone as it gives full control over your node.

3. **Performance:** Adjust memory-related settings based on your computer's available resources.

4. **Backup:** Always keep a backup of your configuration file before making changes.

## Troubleshooting Common Issues

**Problem: Node won't start**
- Check that the JSON syntax is correct (no trailing commas, proper quotes)
- Verify all required fields are present
- Make sure file permissions allow reading

**Problem: High memory usage**
- Reduce `last_n_tick_storage` value
- Consider using different storage modes

Remember, this configuration file gives you complete control over how your Qubic Bob node operates. Start with the default settings and only change what you understand and need to change.

## Default config

~~~json
{
  "request_cycle_ms": 100,
  "request_logging_cycle_ms": 100,
  "future_offset": 10,
  "log_level": "info",
  "keydb_url": "tcp://127.0.0.1:6379",
  "run_server": false,
  "server_port": 21842,
  "arbitrator_identity": "AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ",
  "tick_storage_mode": "kvrocks",
  "kvrocks_url": "tcp://127.0.0.1:6666",
  "tx_storage_mode" : "kvrocks",
  "tx_tick_to_live" : 1111,
  "max_thread": 4,
  "spam_qu_threshold": 0
}
~~~