DELETE LOG EVENT from LOG_ID:
redis-cli --raw EVAL "
local cursor = '0'
local threshold = tonumber(ARGV[1])
local checked = 0
local deleted = 0
repeat
  local res = redis.call('SCAN', cursor, 'MATCH', 'log:*', 'COUNT', 1000)
  cursor = res[1]
  local keys = res[2]
  for i = 1, #keys do
    local k = keys[i]
    checked = checked + 1
    local idx = 0
    local logId = nil
    for part in string.gmatch(k, '([^:]+)') do
      idx = idx + 1
      if idx == 6 then
        logId = tonumber(part)
        break
      end
    end
    if logId and logId >= threshold then
      redis.call('DEL', k)
      deleted = deleted + 1
    end
  end
until cursor == '0'
return {checked, deleted}
" 0 2559639



DELETE log events and log ranges given a tick number:

redis-cli --raw EVAL "
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
" 0 TICK_NUMBER


DELETE TICK_DATA and TICK_VOTE from tick number
redis-cli --raw EVAL "
local threshold = tonumber(ARGV[1])
local del_td = 0
local del_tv = 0
local scanned_td = 0
local scanned_tv = 0

-- Delete tick_data:<tick> where tick >= threshold
do
  local cursor = '0'
  repeat
    local res = redis.call('SCAN', cursor, 'MATCH', 'tick_data:*', 'COUNT', 1000)
    cursor = res[1]
    local keys = res[2]
    for i = 1, #keys do
      local k = keys[i]
      scanned_td = scanned_td + 1
      local idx = 0
      local t = nil
      for part in string.gmatch(k, '([^:]+)') do
        idx = idx + 1
        if idx == 2 then
          t = tonumber(part)
          break
        end
      end
      if t and t >= threshold then
        del_td = del_td + redis.call('DEL', k)
      end
    end
  until cursor == '0'
end

-- Delete tick_vote:<tick>:<computorIndex> where tick >= threshold
do
  local cursor = '0'
  repeat
    local res = redis.call('SCAN', cursor, 'MATCH', 'tick_vote:*', 'COUNT', 1000)
    cursor = res[1]
    local keys = res[2]
    for i = 1, #keys do
      local k = keys[i]
      scanned_tv = scanned_tv + 1
      local idx = 0
      local t = nil
      for part in string.gmatch(k, '([^:]+)') do
        idx = idx + 1
        if idx == 2 then
          t = tonumber(part)
          break
        end
      end
      if t and t >= threshold then
        del_tv = del_tv + redis.call('DEL', k)
      end
    end
  until cursor == '0'
end

return {del_td, del_tv, scanned_td, scanned_tv}
" 0 TICK_NUMBER