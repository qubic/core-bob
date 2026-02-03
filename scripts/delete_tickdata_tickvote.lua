/*deleting tickdata and tickvote based on tick number*/
local threshold = tonumber(ARGV[1])
local del_td = 0
local del_tv = 0
local scanned_td = 0
local scanned_tv = 0

-- tick_data:<tick>
do
  local cursor = '0'
  repeat
    local res = redis.call('SCAN', cursor, 'MATCH', 'tick_data:*', 'COUNT', 1000)
    cursor = res[1]
    local keys = res[2]
    for i = 1, #keys do
      local k = keys[i]
      scanned_td = scanned_td + 1
      local idx, t = 0, nil
      for part in string.gmatch(k, '([^:]+)') do
        idx = idx + 1
        if idx == 2 then t = tonumber(part); break end
      end
      if t and t >= threshold then
        del_td = del_td + redis.call('DEL', k)
      end
    end
  until cursor == '0'
end

-- tick_vote:<tick>:<computorIndex>
do
  local cursor = '0'
  repeat
    local res = redis.call('SCAN', cursor, 'MATCH', 'tick_vote:*', 'COUNT', 1000)
    cursor = res[1]
    local keys = res[2]
    for i = 1, #keys do
      local k = keys[i]
      scanned_tv = scanned_tv + 1
      local idx, t = 0, nil
      for part in string.gmatch(k, '([^:]+)') do
        idx = idx + 1
        if idx == 2 then t = tonumber(part); break end
      end
      if t and t >= threshold then
        del_tv = del_tv + redis.call('DEL', k)
      end
    end
  until cursor == '0'
end

return {del_td, del_tv, scanned_td, scanned_tv}