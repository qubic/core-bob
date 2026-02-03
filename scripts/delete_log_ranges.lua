-- deleting log ranges and log id based on tick number
local tick = ARGV[1]
local key_summary = 'tick_log_range' .. tick
local key_struct  = 'log_ranges:' .. tick

-- Fetch the [fromLogId, length] summary for this tick
local fromStr = redis.call('HGET', key_summary, 'fromLogId')
local lenStr  = redis.call('HGET', key_summary, 'length')

local deleted_logs = 0
local deleted_meta = 0

-- If no range info, just remove any lingering range keys and return
if (not fromStr) or (not lenStr) then
  if redis.call('DEL', key_struct) > 0 then deleted_meta = deleted_meta + 1 end
  if redis.call('DEL', key_summary) > 0 then deleted_meta = deleted_meta + 1 end
  return {deleted_logs, deleted_meta, 'no range info for tick'}
end

local fromId = tonumber(fromStr)
local length = tonumber(lenStr)

-- If tick had no logs
if (fromId == -1) or (length == -1) or (length == 0) then
  if redis.call('DEL', key_struct) > 0 then deleted_meta = deleted_meta + 1 end
  if redis.call('DEL', key_summary) > 0 then deleted_meta = deleted_meta + 1 end
  return {deleted_logs, deleted_meta, 'tick had no logs'}
end

-- Delete log:*:<logId> for all ids in [fromId, fromId+length)
for id = fromId, (fromId + length - 1) do
  local cursor = '0'
  local match = 'log:*:' .. tostring(id)
  repeat
    local res = redis.call('SCAN', cursor, 'MATCH', match, 'COUNT', 1000)
    cursor = res[1]
    local keys = res[2]
    for i = 1, #keys do
      redis.call('DEL', keys[i])
      deleted_logs = deleted_logs + 1
    end
  until cursor == '0'
end

-- Delete the per-tick range metadata
if redis.call('DEL', key_struct) > 0 then deleted_meta = deleted_meta + 1 end
if redis.call('DEL', key_summary) > 0 then deleted_meta = deleted_meta + 1 end

return {deleted_logs, deleted_meta, 'done'}