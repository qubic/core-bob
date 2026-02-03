### Easy Asset / QU Transfer Queries (REST)

This document describes three convenience endpoints that return transfer activity over a tick range, without requiring you to manually compute log topics or call \`/findLog\`.

---

## 1) POST \`/getAllAssetTransfers\`

Fetch **all transfers for a specific asset** (any sender/receiver) within a tick range.

### Request body
- \`fromTick\` (uint32) — start tick (inclusive)
- \`toTick\` (uint32) — end tick (inclusive)
- \`assetIssuer\` (string) — issuer identity/public identifier for the asset
- \`assetName\` (string) — asset name

### Example
    curl -s -X POST '23.88.1.189:40420/getAllAssetTransfers' \
        -H 'Content-Type: application/json' \
        -d '{
        "fromTick": 39862000,
        "toTick": 39862999,
        "assetIssuer": "GARTHFANXMPXMDPEZFQPWFPYMHOAWTKILINCTRMVLFFVATKVJRKEDYXGHJBF",
        "assetName": "GARTH"
    }'

expected returns:
```
["jllpcfguyhukpbxqhvrfknhzfcqaxmyesyhfburnabyxwsuhdsuzqigcwjko","wyuobinwixtxtbvgywezerjmsvggcypwyxmgawjaffnknygdwonpiyxfjpko","xtwbjpcbyqurrfjjdfukppaadawbjardmzmpqypepabeggrwayloarsbttai","mhiaugvahrgdgcizvchlpwvwviccofzpeamltzddpafklbxilrmgnyzgqgah","rdxqnshxxeokdhhqsgzcnvbfbpocxvihmfcketlsihvxcapalcfpiawbhkpm","irwtydezfvxmegpnruznlzpxwvbhtsnjddrnuvaeyfcldcynyzrklybfjnnl","kruztjiyouefpfzhbgaznmsyjryetaygyfqtyhpsgfjncpbdsvygpsvelinf","rgacxfqiwkagvbsnttvkuocmwpehyghqntcgmscdmehmfpcgofcrdolaejud"]
```

---

## 2) POST \`/getAssetTransfersForIdentity\`

Fetch **asset transfers involving a specific identity** (as sender and/or receiver) for a given asset within a tick range.

### Request body
- \`fromTick\` (uint32) — start tick (inclusive)
- \`toTick\` (uint32) — end tick (inclusive)
- \`identity\` (string) — identity to filter by
- \`assetIssuer\` (string) — issuer identity/public identifier for the asset
- \`assetName\` (string) — asset name

### Example
    curl -s -X POST '23.88.1.189:40420/getAssetTransfersForIdentity' \
        -H 'Content-Type: application/json' \
        -d '{
        "fromTick": 39863000,
        "toTick": 39863999,
        "assetIssuer": "GARTHFANXMPXMDPEZFQPWFPYMHOAWTKILINCTRMVLFFVATKVJRKEDYXGHJBF",
        "assetName": "GARTH",
        "identity": "KEUFMJGWUMBSKEXWTEBIXYNUQXCCXLGLXKHTMPDIVDPYYVRSDGTOCEKEQANG"
    }'
expected return:
```
{"in":["gqjpisxiulommfhhvnadrigeqhdbswponbdnddjbbglkzoxerdgjrjscsmuf"],"out":["pefqwdimpvyglcxcijijfjyiobgbpfumoajnkpdzagidbctbxzzpvjggyhwi"]}
```

---

## 3) POST \`/getQuTransfersForIdentity\`

Fetch **QU transfers involving a specific identity** within a tick range.

### Request body
- \`fromTick\` (uint32) — start tick (inclusive)
- \`toTick\` (uint32) — end tick (inclusive)
- \`identity\` (string) — identity to filter by

### Example
    curl -s -X POST '23.88.1.189:40420/getQuTransfersForIdentity' \
        -H 'Content-Type: application/json' \
        -d '{
        "fromTick": 39863000,
        "toTick": 39863999,
        "identity": "NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAML"
    }'
expected return:
```
{"in":["gqjpisxiulommfhhvnadrigeqhdbswponbdnddjbbglkzoxerdgjrjscsmuf","bdupcbikltlnhdzlmkiguezsunfdxoufjptkqyfriezdycuokucztbndpytb","embtgqowsligxbvwcwvoekqwoltgbwotodqeamkhcbzxyzzsasuqmqocmlhl","ealonicladlkwaizpsyiwxutbbvagrxuveafsrakuekfxmcoarudkjhbosun"],"out":["SC_END_TICK_TX_39863139","bdupcbikltlnhdzlmkiguezsunfdxoufjptkqyfriezdycuokucztbndpytb","SC_END_TICK_TX_39863560","SC_END_TICK_TX_39863799"]}
```

---

## Notes
- All endpoints require a JSON body (\`Content-Type: application/json\`).
- \`fromTick\` must be \`<= toTick\`.
- Use these endpoints when you want “just the transfers” without building \`/findLog\` queries and topic hashes manually.
