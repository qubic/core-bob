### How to Query with POST /findLog
`ASSET_OWNERSHIP_CHANGE` `ASSET_POSSESSION_CHANGE` are system events, so use `scIndex = 0`. The event maps to topics as follows:
- topic1: Source public key (previous owner)
- topic2: Destination public key (new owner)
- topic3: Asset ID (derived from issuer public key and asset name): K12(issuer public key with asset name)

Notes:
- To match any value for a topic, use the wildcard “null” identity: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib
- The asset identifier (topic3) is a 32-byte value derived from the issuer’s public key and the 7-byte asset name; use the canonical 32-byte identifier recognized by your client tooling.


### Example Queries
#### Find all ASSET_OWNERSHIP_CHANGE events for GARTH from `37830000` to `37842856`
Since we want to find ALL, `topic1` and `topic2` will be a wildcard `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib`
topic3 is K12 of GARTH issuer and the "GARTH" name. Below is the example code how to get topic3 hash:
``` C/C++
    uint8_t assetHash[39];
    getPublicKeyFromIdentity("GARTHFANXMPXMDPEZFQPWFPYMHOAWTKILINCTRMVLFFVATKVJRKEDYXGHJBF", assetHash);
    char name[7] = {'G','A','R','T','H',0,0};
    memcpy(assetHash + 32, name, 7);
    uint8_t out[32];
    char hash[64] = {0};
    KangarooTwelve(assetHash, 39, out, 32);
    getIdentityFromPublicKey(out, hash, true);
    printf("%s\n", hash);
```

The query command should be look like below:
~~~
curl -s -X POST '157.180.10.49:40420/findLog' \
  -H 'Content-Type: application/json' \
  -d '{
    "fromTick": 37830000,
    "toTick": 37842856,
    "scIndex": 0,
    "logType": 2,
    "topic1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib",
    "topic2": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafxib",
    "topic3": "ydhjsfkjdkeviecrrdwtzvdjxqhexwpdefdkxggcxaxwujnqedtjhzscwjkh"
  }'
~~~

Response: `[37831593,37835356,37835444,37839262,37841735]` (from mainnet)