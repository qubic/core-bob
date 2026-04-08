#pragma once
#include "db_redis_iface.h"

// ---- pipeline wrapper ---------------------------------------------------

class RealPipeline final : public IPipeline {
    sw::redis::Pipeline _p;
public:
    explicit RealPipeline(sw::redis::Pipeline p) : _p(std::move(p)) {}

    IPipeline& set(const std::string& key, sw::redis::StringView val,
                   std::chrono::seconds ttl) override {
        _p.set(key, val, ttl);
        return *this;
    }

    void exec() override { _p.exec(); }  // exec() returns QueuedReplies; we discard it
};

// ---- Redis wrapper ------------------------------------------------------

class RealRedis final : public IRedis {
    sw::redis::Redis _r;
public:
    explicit RealRedis(const std::string& uri) : _r(uri) {}
    sw::redis::Redis *getPtr() { return &_r; }
    void ping() override { _r.ping(); }
    bool exists(const std::string& k) override { return _r.exists(k); }

    void set(const std::string& k, sw::redis::StringView v,
             std::chrono::milliseconds ttl, sw::redis::UpdateType type) override {
        _r.set(k, v, ttl, type);
    }
    void set(const std::string& k, const std::string& v) override { _r.set(k, v); }
    void set(const std::string& k, sw::redis::StringView v,
             std::chrono::seconds ttl) override { _r.set(k, v, ttl); }

    sw::redis::OptionalString get(const std::string& k) override { return _r.get(k); }

    void unlink(const std::string& k) override { _r.unlink(k); }
    void unlink(std::vector<std::string>::const_iterator f,
                std::vector<std::string>::const_iterator l) override { _r.unlink(f, l); }

    void mget(std::vector<std::string>::const_iterator f,
              std::vector<std::string>::const_iterator l,
              std::back_insert_iterator<std::vector<sw::redis::OptionalString>> o) override {
        _r.mget(f, l, o);
    }
    void mset(std::vector<std::pair<std::string,std::string>>::iterator f,
              std::vector<std::pair<std::string,std::string>>::iterator l) override {
        _r.mset(f, l);
    }

    void hmset(const std::string& k,
               std::unordered_map<std::string,std::string>::iterator f,
               std::unordered_map<std::string,std::string>::iterator l) override {
        _r.hmset(k, f, l);
    }
    void hmget(const std::string& k, std::initializer_list<std::string> fields,
               std::back_insert_iterator<std::vector<sw::redis::Optional<std::string>>> o) override {
        _r.hmget(k, fields, o);
    }
    sw::redis::OptionalString hget(const std::string& k, const std::string& f) override {
        return _r.hget(k, f);
    }
    void hset(const std::string& k,
              const std::string& f,
              const std::string& v) override {
        _r.hset(k, f, v);
    }

    void hset(const std::string& k,
              std::initializer_list<std::pair<std::string, std::string>> items) override {
        _r.hset(k, items);
    }

    void hgetall(const std::string& k,
                 std::insert_iterator<std::unordered_map<std::string, std::string>> o) override {
        _r.hgetall(k, o);
    }

    long long eval_ll(const std::string& script,
                      std::vector<std::string>::const_iterator kf, std::vector<std::string>::const_iterator kl,
                      std::vector<std::string>::const_iterator af, std::vector<std::string>::const_iterator al) override {
        return _r.eval<long long>(script, kf, kl, af, al);
    }

    void rename(const std::string& s, const std::string& d) override { _r.rename(s, d); }

    void zadd(const std::string& k, const std::string& m,
              double score, sw::redis::UpdateType type) override {
        _r.zadd(k, m, score, type);
    }
    long long zcard(const std::string& k) override { return _r.zcard(k); }
    void zpopmin(const std::string& k, long long n,
                 std::back_insert_iterator<std::vector<std::pair<std::string,double>>> o) override {
        _r.zpopmin(k, n, o);
    }
    void zrangebyscore(const std::string& k,
                       const sw::redis::BoundedInterval<double>& range,
                       std::back_insert_iterator<std::vector<std::string>> o) override {
        _r.zrangebyscore(k, range, o);
    }

    bool expire(const std::string& k, std::chrono::seconds ttl) override {
        return _r.expire(k, ttl);
    }

    std::unique_ptr<IPipeline> pipeline() override {
        return std::make_unique<RealPipeline>(_r.pipeline());
    }
};