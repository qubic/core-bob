local epoch  = tonumber(ARGV[1])
local target = tonumber(ARGV[2])

local epoch_key = 'db_status:epoch:' .. tostring(epoch)
redis.call('HSET', epoch_key, 'latest_verified_tick', target)

local ge = redis.call('HGET', 'db_status', 'latest_epoch')
if ge and tonumber(ge) == epoch then
  redis.call('HSET', 'db_status', 'latest_tick', target)
end

local gee = redis.call('HGET', 'db_status', 'latest_event_epoch')
if gee and tonumber(gee) == epoch then
  redis.call('HSET', 'db_status', 'latest_event_tick', target)
end

return {'ok', epoch, target}