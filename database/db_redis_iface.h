#pragma once
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <unordered_map>
#include "sw/redis++/redis++.h"

/// Abstract pipeline interface
struct IPipeline {
    virtual ~IPipeline() = default;

    virtual IPipeline& set(const std::string& key, sw::redis::StringView val,
                           std::chrono::seconds ttl) = 0;
    virtual void exec() = 0;  // wraps Pipeline::exec()
};

struct IRedis {
    virtual ~IRedis() = default;

    virtual void ping() = 0;
    virtual bool exists(const std::string& key) = 0;

    virtual void set(const std::string& key, sw::redis::StringView val,
                     std::chrono::milliseconds ttl = std::chrono::milliseconds(0),
                     sw::redis::UpdateType type    = sw::redis::UpdateType::ALWAYS) = 0;
    virtual void set(const std::string& key, const std::string& val) = 0;
    virtual void set(const std::string& key, sw::redis::StringView val,
                     std::chrono::seconds ttl) = 0;

    virtual sw::redis::OptionalString get(const std::string& key) = 0;

    virtual void unlink(const std::string& key) = 0;
    virtual void unlink(std::vector<std::string>::const_iterator first,
                        std::vector<std::string>::const_iterator last) = 0;

    virtual void mget(std::vector<std::string>::const_iterator first,
                      std::vector<std::string>::const_iterator last,
                      std::back_insert_iterator<std::vector<sw::redis::OptionalString>> out) = 0;
    virtual void mset(std::vector<std::pair<std::string,std::string>>::iterator first,
                      std::vector<std::pair<std::string,std::string>>::iterator last) = 0;

    virtual void hmset(const std::string& key,
                       std::unordered_map<std::string,std::string>::iterator first,
                       std::unordered_map<std::string,std::string>::iterator last) = 0;
    virtual void hmget(const std::string& key,
                       std::initializer_list<std::string> fields,
                       std::back_insert_iterator<std::vector<sw::redis::Optional<std::string>>> out) = 0;
    virtual sw::redis::OptionalString hget(const std::string& key, const std::string& field) = 0;
    // single field overload — used as: hset(key, field, value)
    virtual void hset(const std::string& key,
                      const std::string& field,
                      const std::string& value) = 0;

    // multi-field overload — used as: hset(key, initializer_list<pair<string,string>>{...})
    virtual void hset(const std::string& key,
                      std::initializer_list<std::pair<std::string, std::string>> items) = 0;

    // eval returning long long — wraps Redis::eval<long long>(...)
    virtual long long eval_ll(const std::string& script,
                              std::vector<std::string>::const_iterator keys_first,
                              std::vector<std::string>::const_iterator keys_last,
                              std::vector<std::string>::const_iterator args_first,
                              std::vector<std::string>::const_iterator args_last) = 0;

    virtual void rename(const std::string& src, const std::string& dst) = 0;

    virtual void zadd(const std::string& key, const std::string& member,
                      double score, sw::redis::UpdateType type) = 0;
    virtual long long zcard(const std::string& key) = 0;
    virtual void zpopmin(const std::string& key, long long count,
                         std::back_insert_iterator<std::vector<std::pair<std::string,double>>> out) = 0;
    virtual void zrangebyscore(const std::string& key,
                               const sw::redis::BoundedInterval<double>& range,
                               std::back_insert_iterator<std::vector<std::string>> out) = 0;

    virtual bool expire(const std::string& key, std::chrono::seconds ttl) = 0;

    /// Returns a heap-allocated pipeline; caller owns the pointer.
    virtual std::unique_ptr<IPipeline> pipeline() = 0;

    virtual void hgetall(const std::string& key,
                         std::insert_iterator<std::unordered_map<std::string, std::string>> out) = 0;
    virtual sw::redis::Redis *getPtr() = 0;
};