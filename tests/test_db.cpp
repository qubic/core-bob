
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "database/db.h"
#include "database/db_redis_iface.h"

using StringPairVecIter = std::vector<std::pair<std::string, std::string>>::iterator;
using StringPairVec     = std::vector<std::pair<std::string, std::string>>;
using OptStringVec      = std::vector<sw::redis::OptionalString>;
using StringPairDoubleVec = std::vector<std::pair<std::string, double>>;
using OptionalStringVec = std::vector<sw::redis::Optional<std::string>>;
using StringStringMap   = std::unordered_map<std::string, std::string>;
using StringPairInitList = std::initializer_list<std::pair<std::string, std::string>>;

class MockRedis : public IRedis {
public:
    MOCK_METHOD(void, ping, (), (override));
    MOCK_METHOD(bool, exists, (const std::string&), (override));

    MOCK_METHOD(void, set, (const std::string&, sw::redis::StringView, std::chrono::milliseconds, sw::redis::UpdateType), (override));
    MOCK_METHOD(void, set, (const std::string&, const std::string&), (override));
    MOCK_METHOD(void, set, (const std::string&, sw::redis::StringView, std::chrono::seconds), (override));

    MOCK_METHOD(sw::redis::OptionalString, get, (const std::string&), (override));

    MOCK_METHOD(void, unlink, (const std::string&), (override));
    MOCK_METHOD(void, unlink, (std::vector<std::string>::const_iterator, std::vector<std::string>::const_iterator), (override));

    MOCK_METHOD(void, mset, (StringPairVecIter, StringPairVecIter), (override));
    MOCK_METHOD(void, mget, (std::vector<std::string>::const_iterator, std::vector<std::string>::const_iterator, std::back_insert_iterator<OptStringVec>), (override));
    MOCK_METHOD(void, hmset, (const std::string&, StringStringMap::iterator, StringStringMap::iterator), (override));
    MOCK_METHOD(void, hmget, (const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec>), (override));
    MOCK_METHOD(void, hgetall, (const std::string&, std::insert_iterator<StringStringMap>), (override));
    MOCK_METHOD(void, zpopmin, (const std::string&, long long, std::back_insert_iterator<StringPairDoubleVec>), (override));
    MOCK_METHOD(void, hset, (const std::string&, StringPairInitList), (override));

    MOCK_METHOD(long long, eval_ll, (const std::string&, std::vector<std::string>::const_iterator, std::vector<std::string>::const_iterator, std::vector<std::string>::const_iterator, std::vector<std::string>::const_iterator), (override));

    MOCK_METHOD(void, rename, (const std::string&, const std::string&), (override));

    MOCK_METHOD(void, zadd, (const std::string&, const std::string&, double, sw::redis::UpdateType), (override));
    MOCK_METHOD(long long, zcard, (const std::string&), (override));
    MOCK_METHOD(void, zrangebyscore, (const std::string&, const sw::redis::BoundedInterval<double>&, std::back_insert_iterator<std::vector<std::string>>), (override));

    MOCK_METHOD(bool, expire, (const std::string&, std::chrono::seconds), (override));
    MOCK_METHOD(std::unique_ptr<IPipeline>, pipeline, (), (override));
    MOCK_METHOD(sw::redis::OptionalString, hget, (const std::string&, const std::string&), (override));
    MOCK_METHOD(void, hset, (const std::string&, const std::string&, const std::string&), (override));
    MOCK_METHOD(sw::redis::Redis *, getPtr, (), (override));
};

class MockPipeline : public IPipeline {
public:
    MOCK_METHOD(IPipeline&, set, (const std::string&, sw::redis::StringView, std::chrono::seconds), (override));
    MOCK_METHOD(void, exec, (), (override));
};

class DbTest : public ::testing::Test {
protected:
    MockRedis mockRedis;
    MockRedis mockKvrocks;

    void SetUp() override   { db_inject_redis(&mockRedis, &mockKvrocks); }
    void TearDown() override { db_inject_redis(nullptr, nullptr); }
};