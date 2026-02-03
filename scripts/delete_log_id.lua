-- redis
-- Usage:
--   EVAL "<this-script>" 0 2559639 1000
-- ARGV[1] = threshold (logId >= threshold will be deleted)
-- ARGV[2] = optional SCAN COUNT per iteration (default 1000)
local threshold = tonumber(ARGV[1])
local scan_count = tonumber(ARGV[2]) or 1000
if not threshold then
  return redis.error_reply("threshold (ARGV[1]) is required")
end

local cursor = "0"
local deleted = 0

repeat
  local res = redis.call('SCAN', cursor, 'MATCH', 'log:*:*', 'COUNT', scan_count)
  cursor = res[1]
  local keys = res[2]
  for i = 1, #keys do
    local k = keys[i]
    local id = string.match(k, '^log:%d+:(%d+)$')
    if id then
      local num = tonumber(id)
      if num and num >= threshold then
        redis.call('DEL', k)
        deleted = deleted + 1
      end
    end
  end
until cursor == "0"

return deleted