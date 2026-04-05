#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "spdlog/sinks/null_sink.h"
#include "database/db.h"
#include "database/db_redis_iface.h"

#include "K12AndKeyUtil.h"
#include "LogEvent.h"
using ::testing::_;
using ::testing::Return;
using ::testing::DoAll;

using StringPairVecIter   = std::vector<std::pair<std::string, std::string>>::iterator;
using OptStringVec        = std::vector<sw::redis::OptionalString>;
using StringPairDoubleVec = std::vector<std::pair<std::string, double>>;
using OptionalStringVec   = std::vector<sw::redis::Optional<std::string>>;
using StringStringMap     = std::unordered_map<std::string, std::string>;
using StringPairInitList  = std::initializer_list<std::pair<std::string, std::string>>;

class MockPipeline : public IPipeline {
public:
    MOCK_METHOD(IPipeline&, set, (const std::string&, sw::redis::StringView, std::chrono::seconds), (override));
    MOCK_METHOD(void, exec, (), (override));
};

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

    MOCK_METHOD(void, mget, (std::vector<std::string>::const_iterator, std::vector<std::string>::const_iterator, std::back_insert_iterator<OptStringVec>), (override));
    MOCK_METHOD(void, mset, (StringPairVecIter, StringPairVecIter), (override));

    MOCK_METHOD(void, hmset, (const std::string&, StringStringMap::iterator, StringStringMap::iterator), (override));
    MOCK_METHOD(void, hmget, (const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec>), (override));

    MOCK_METHOD(sw::redis::OptionalString, hget, (const std::string&, const std::string&), (override));
    MOCK_METHOD(void, hset, (const std::string&, const std::string&, const std::string&), (override));
    MOCK_METHOD(void, hset, (const std::string&, StringPairInitList), (override));
    MOCK_METHOD(void, hgetall, (const std::string&, std::insert_iterator<StringStringMap>), (override));

    MOCK_METHOD(long long, eval_ll, (const std::string&, std::vector<std::string>::const_iterator, std::vector<std::string>::const_iterator, std::vector<std::string>::const_iterator, std::vector<std::string>::const_iterator), (override));

    MOCK_METHOD(void, rename, (const std::string&, const std::string&), (override));

    MOCK_METHOD(void, zadd, (const std::string&, const std::string&, double, sw::redis::UpdateType), (override));
    MOCK_METHOD(long long, zcard, (const std::string&), (override));
    MOCK_METHOD(void, zpopmin, (const std::string&, long long, std::back_insert_iterator<StringPairDoubleVec>), (override));
    MOCK_METHOD(void, zrangebyscore, (const std::string&, const sw::redis::BoundedInterval<double>&, std::back_insert_iterator<std::vector<std::string>>), (override));

    MOCK_METHOD(bool, expire, (const std::string&, std::chrono::seconds), (override));
    MOCK_METHOD(std::unique_ptr<IPipeline>, pipeline, (), (override));
    MOCK_METHOD(sw::redis::Redis*, getPtr, (), (override));
};

class DbTest : public ::testing::Test {
protected:
    testing::NiceMock<MockRedis> mockRedis;
    testing::NiceMock<MockRedis> mockKvrocks;

    void SetUp() override {
        Logger::init("critical");
        auto null_sink = std::make_shared<spdlog::sinks::null_sink_mt>();
        auto null_logger = std::make_shared<spdlog::logger>("null", null_sink);
        spdlog::set_default_logger(null_logger);
        db_inject_redis(&mockRedis, &mockKvrocks);
    }
    void TearDown() override {
        spdlog::shutdown();
        db_inject_redis(nullptr, nullptr);
    }
};

// ---------------------------------------------------------------------------
// db_insert_tick_vote
// ---------------------------------------------------------------------------

TEST_F(DbTest, InsertTickVote_Success) {
    EXPECT_CALL(mockRedis, set(_, _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST)).Times(1);
    TickVote vote{};
    vote.tick = 100;
    vote.computorIndex = 1;
    EXPECT_TRUE(db_insert_tick_vote(vote));
}

TEST_F(DbTest, InsertTickVote_RedisThrows_ReturnsFalse) {
    EXPECT_CALL(mockRedis, set(_, _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST))
        .WillOnce(testing::Throw(sw::redis::Error("fail")));
    TickVote vote{};
    EXPECT_FALSE(db_insert_tick_vote(vote));
}

TEST_F(DbTest, InsertTickVote_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    TickVote vote{};
    EXPECT_FALSE(db_insert_tick_vote(vote));
}

// ---------------------------------------------------------------------------
// db_insert_tick_data
// ---------------------------------------------------------------------------

TEST_F(DbTest, InsertTickData_Success) {
    EXPECT_CALL(mockRedis, set(_, _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST)).Times(1);
    TickData data{};
    data.tick = 42;
    EXPECT_TRUE(db_insert_tick_data(data));
}

TEST_F(DbTest, InsertTickData_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    TickData data{};
    EXPECT_FALSE(db_insert_tick_data(data));
}

TEST_F(DbTest, InsertTickData_RedisThrows_ReturnsFalse) {
    EXPECT_CALL(mockRedis, set(_, _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST))
        .WillOnce(testing::Throw(sw::redis::Error("fail")));
    TickData data{};
    EXPECT_FALSE(db_insert_tick_data(data));
}

// ---------------------------------------------------------------------------
// db_insert_log
// ---------------------------------------------------------------------------

TEST_F(DbTest, InsertLog_Success) {
    EXPECT_CALL(mockRedis, set(_, _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST)).Times(1);
    uint8_t content[16] = {};
    EXPECT_TRUE(db_insert_log(1, 100, 999, sizeof(content), content));
}

TEST_F(DbTest, InsertLog_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    uint8_t content[16] = {};
    EXPECT_FALSE(db_insert_log(1, 100, 999, sizeof(content), content));
}

TEST_F(DbTest, InsertLog_RedisThrows_ReturnsFalse) {
    EXPECT_CALL(mockRedis, set(_, _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST))
        .WillOnce(testing::Throw(sw::redis::Error("fail")));
    uint8_t content[16] = {};
    EXPECT_FALSE(db_insert_log(1, 100, 999, sizeof(content), content));
}

// ---------------------------------------------------------------------------
// db_check_log_range
// ---------------------------------------------------------------------------

TEST_F(DbTest, CheckLogRange_ExistsReturnsTrue) {
    EXPECT_CALL(mockRedis, exists("log_ranges:55")).WillOnce(Return(true));
    EXPECT_TRUE(db_check_log_range(55));
}

TEST_F(DbTest, CheckLogRange_NotExists_ReturnsFalse) {
    EXPECT_CALL(mockRedis, exists("log_ranges:55")).WillOnce(Return(false));
    EXPECT_FALSE(db_check_log_range(55));
}

TEST_F(DbTest, CheckLogRange_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_check_log_range(55));
}

// ---------------------------------------------------------------------------
// db_log_exists
// ---------------------------------------------------------------------------

TEST_F(DbTest, LogExists_Found) {
    EXPECT_CALL(mockRedis, exists("log:1:42")).WillOnce(Return(true));
    EXPECT_TRUE(db_log_exists(1, 42));
}

TEST_F(DbTest, LogExists_NotFound) {
    EXPECT_CALL(mockRedis, exists("log:1:42")).WillOnce(Return(false));
    EXPECT_FALSE(db_log_exists(1, 42));
}

TEST_F(DbTest, LogExists_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_log_exists(1, 42));
}

// ---------------------------------------------------------------------------
// db_delete_log_ranges
// ---------------------------------------------------------------------------

TEST_F(DbTest, DeleteLogRanges_Success) {
    EXPECT_CALL(mockRedis, unlink(std::string("log_ranges:10"))).Times(1);
    EXPECT_CALL(mockRedis, unlink(std::string("tick_log_range:10"))).Times(1);
    EXPECT_TRUE(db_delete_log_ranges(10));
}

TEST_F(DbTest, DeleteLogRanges_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_delete_log_ranges(10));
}

// ---------------------------------------------------------------------------
// db_delete_tick_data
// ---------------------------------------------------------------------------

TEST_F(DbTest, DeleteTickData_Success) {
    EXPECT_CALL(mockRedis, unlink(std::string("tick_data:7"))).Times(1);
    EXPECT_TRUE(db_delete_tick_data(7));
}

TEST_F(DbTest, DeleteTickData_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_delete_tick_data(7));
}

// ---------------------------------------------------------------------------
// db_delete_tick_vote
// ---------------------------------------------------------------------------

TEST_F(DbTest, DeleteTickVote_Success) {
    EXPECT_CALL(mockRedis, unlink(_, _)).Times(1);
    EXPECT_TRUE(db_delete_tick_vote(5));
}

TEST_F(DbTest, DeleteTickVote_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_delete_tick_vote(5));
}

// ---------------------------------------------------------------------------
// db_delete_transaction
// ---------------------------------------------------------------------------

TEST_F(DbTest, DeleteTransaction_Success) {
    EXPECT_CALL(mockRedis, unlink(std::string("transaction:abc"))).Times(1);
    EXPECT_TRUE(db_delete_transaction("abc"));
}

TEST_F(DbTest, DeleteTransaction_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_delete_transaction("abc"));
}

// ---------------------------------------------------------------------------
// db_delete_many
// ---------------------------------------------------------------------------

TEST_F(DbTest, DeleteMany_EmptyKeys_ReturnsTrue) {
    EXPECT_TRUE(db_delete_many({}));
}

TEST_F(DbTest, DeleteMany_WithKeys_CallsUnlink) {
    EXPECT_CALL(mockRedis, unlink(_, _)).Times(1);
    EXPECT_TRUE(db_delete_many({"key1", "key2"}));
}

TEST_F(DbTest, DeleteMany_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_delete_many({"key1"}));
}

// ---------------------------------------------------------------------------
// db_delete_logs
// ---------------------------------------------------------------------------

TEST_F(DbTest, DeleteLogs_Success) {
    EXPECT_CALL(mockRedis, unlink(_, _)).Times(1);
    EXPECT_TRUE(db_delete_logs(1, 10, 12));
}

TEST_F(DbTest, DeleteLogs_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_delete_logs(1, 10, 12));
}

// ---------------------------------------------------------------------------
// db_update_latest_tick_and_epoch
// ---------------------------------------------------------------------------

TEST_F(DbTest, UpdateLatestTickAndEpoch_Success) {
    EXPECT_CALL(mockRedis, eval_ll(_, _, _, _, _)).WillOnce(Return(1));
    EXPECT_TRUE(db_update_latest_tick_and_epoch(100, 5));
}

TEST_F(DbTest, UpdateLatestTickAndEpoch_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_update_latest_tick_and_epoch(100, 5));
}

TEST_F(DbTest, UpdateLatestTickAndEpoch_Throws_ReturnsFalse) {
    EXPECT_CALL(mockRedis, eval_ll(_, _, _, _, _)).WillOnce(testing::Throw(sw::redis::Error("fail")));
    EXPECT_FALSE(db_update_latest_tick_and_epoch(100, 5));
}

// ---------------------------------------------------------------------------
// db_get_latest_tick_and_epoch
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetLatestTickAndEpoch_Success) {
    EXPECT_CALL(mockRedis, hmget("db_status", _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec> out) {
            *out++ = std::string("200");
            *out++ = std::string("6");
        }));
    uint32_t tick = 0; uint16_t epoch = 0;
    EXPECT_TRUE(db_get_latest_tick_and_epoch(tick, epoch));
    EXPECT_EQ(tick, 200u);
    EXPECT_EQ(epoch, 6u);
}

TEST_F(DbTest, GetLatestTickAndEpoch_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    uint32_t tick; uint16_t epoch;
    EXPECT_FALSE(db_get_latest_tick_and_epoch(tick, epoch));
}

// ---------------------------------------------------------------------------
// db_update_latest_event_tick_and_epoch
// ---------------------------------------------------------------------------

TEST_F(DbTest, UpdateLatestEventTickAndEpoch_Success) {
    EXPECT_CALL(mockRedis, hset(std::string("db_status"), _)).Times(1);
    EXPECT_TRUE(db_update_latest_event_tick_and_epoch(50, 3));
}

TEST_F(DbTest, UpdateLatestEventTickAndEpoch_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_update_latest_event_tick_and_epoch(50, 3));
}

// ---------------------------------------------------------------------------
// db_get_latest_event_tick_and_epoch
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetLatestEventTickAndEpoch_Success) {
    EXPECT_CALL(mockRedis, hmget("db_status", _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec> out) {
            *out++ = std::string("300");
            *out++ = std::string("7");
        }));
    uint32_t tick = 0; uint16_t epoch = 0;
    EXPECT_TRUE(db_get_latest_event_tick_and_epoch(tick, epoch));
    EXPECT_EQ(tick, 300u);
    EXPECT_EQ(epoch, 7u);
}

TEST_F(DbTest, GetLatestEventTickAndEpoch_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    uint32_t tick; uint16_t epoch;
    EXPECT_FALSE(db_get_latest_event_tick_and_epoch(tick, epoch));
}

// ---------------------------------------------------------------------------
// db_update_latest_log_id
// ---------------------------------------------------------------------------

TEST_F(DbTest, UpdateLatestLogId_Success) {
    EXPECT_CALL(mockRedis, eval_ll(_, _, _, _, _)).WillOnce(Return(1));
    EXPECT_TRUE(db_update_latest_log_id(1, 999));
}

TEST_F(DbTest, UpdateLatestLogId_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_update_latest_log_id(1, 999));
}

// ---------------------------------------------------------------------------
// db_get_latest_log_id
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetLatestLogId_Found) {
    EXPECT_CALL(mockRedis, hget("db_status:epoch:1", "latest_log_id"))
        .WillOnce(Return(sw::redis::OptionalString("42")));
    EXPECT_EQ(db_get_latest_log_id(1), 42LL);
}

TEST_F(DbTest, GetLatestLogId_NotFound_ReturnsMinusOne) {
    EXPECT_CALL(mockRedis, hget("db_status:epoch:1", "latest_log_id"))
        .WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_EQ(db_get_latest_log_id(1), -1LL);
}

TEST_F(DbTest, GetLatestLogId_NoRedis_ReturnsMinusOne) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_EQ(db_get_latest_log_id(1), -1LL);
}

// ---------------------------------------------------------------------------
// db_update_latest_verified_tick
// ---------------------------------------------------------------------------

TEST_F(DbTest, UpdateLatestVerifiedTick_Success) {
    EXPECT_CALL(mockRedis, eval_ll(_, _, _, _, _)).WillOnce(Return(1));
    EXPECT_TRUE(db_update_latest_verified_tick(88));
}

TEST_F(DbTest, UpdateLatestVerifiedTick_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_update_latest_verified_tick(88));
}

// ---------------------------------------------------------------------------
// db_get_latest_verified_tick
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetLatestVerifiedTick_Found) {
    EXPECT_CALL(mockRedis, hget("db_status", "latest_verified_tick"))
        .WillOnce(Return(sw::redis::OptionalString("77")));
    EXPECT_EQ(db_get_latest_verified_tick(), 77LL);
}

TEST_F(DbTest, GetLatestVerifiedTick_NotFound_ReturnsMinusOne) {
    EXPECT_CALL(mockRedis, hget("db_status", "latest_verified_tick"))
        .WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_EQ(db_get_latest_verified_tick(), -1LL);
}

TEST_F(DbTest, GetLatestVerifiedTick_NoRedis_ReturnsMinusOne) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_EQ(db_get_latest_verified_tick(), -1LL);
}

// ---------------------------------------------------------------------------
// db_get_tick_vote_count
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetTickVoteCount_NoRedis_ReturnsMinusOne) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_EQ(db_get_tick_vote_count(1), -1LL);
}

TEST_F(DbTest, GetTickVoteCount_AllMissing_ReturnsZero) {
    EXPECT_CALL(mockRedis, mget(_, _, _))
        .WillRepeatedly(testing::Return());
    EXPECT_EQ(db_get_tick_vote_count(1), 0LL);
}

// ---------------------------------------------------------------------------
// db_get_tick_vote
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetTickVote_Found) {
    TickVote expected{};
    expected.tick = 10;
    expected.computorIndex = 2;
    std::string raw(reinterpret_cast<char*>(&expected), sizeof(TickVote));
    EXPECT_CALL(mockRedis, get("tick_vote:10:2")).WillOnce(Return(sw::redis::OptionalString(raw)));
    TickVote out{};
    EXPECT_TRUE(db_get_tick_vote(10, 2, out));
    EXPECT_EQ(out.tick, 10u);
    EXPECT_EQ(out.computorIndex, 2u);
}

TEST_F(DbTest, GetTickVote_NotFound) {
    EXPECT_CALL(mockRedis, get("tick_vote:10:2")).WillOnce(Return(sw::redis::OptionalString{}));
    TickVote out{};
    EXPECT_FALSE(db_get_tick_vote(10, 2, out));
}

TEST_F(DbTest, GetTickVote_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    TickVote out{};
    EXPECT_FALSE(db_get_tick_vote(10, 2, out));
}

// ---------------------------------------------------------------------------
// db_get_tick_votes
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetTickVotes_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    std::vector<TickVote> votes;
    EXPECT_FALSE(db_get_tick_votes(1, votes));
}

TEST_F(DbTest, GetTickVotes_EmptyResult) {
    EXPECT_CALL(mockRedis, mget(_, _, _)).WillRepeatedly(testing::Return());
    std::vector<TickVote> votes;
    EXPECT_TRUE(db_get_tick_votes(1, votes));
    EXPECT_TRUE(votes.empty());
}

// ---------------------------------------------------------------------------
// db_get_tick_data
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetTickData_Found) {
    TickData expected{};
    expected.tick = 99;
    std::string raw(reinterpret_cast<char*>(&expected), sizeof(TickData));
    EXPECT_CALL(mockRedis, get("tick_data:99")).WillOnce(Return(sw::redis::OptionalString(raw)));
    TickData out{};
    EXPECT_TRUE(db_get_tick_data(99, out));
    EXPECT_EQ(out.tick, 99u);
}

TEST_F(DbTest, GetTickData_NotFound) {
    EXPECT_CALL(mockRedis, get("tick_data:99")).WillOnce(Return(sw::redis::OptionalString{}));
    TickData out{};
    EXPECT_FALSE(db_get_tick_data(99, out));
}

TEST_F(DbTest, GetTickData_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    TickData out{};
    EXPECT_FALSE(db_get_tick_data(99, out));
}

// ---------------------------------------------------------------------------
// db_has_tick_data
// ---------------------------------------------------------------------------

TEST_F(DbTest, HasTickData_TickDataKeyExists) {
    EXPECT_CALL(mockRedis, exists("tick_data:5")).WillOnce(Return(true));
    EXPECT_TRUE(db_has_tick_data(5));
}

TEST_F(DbTest, HasTickData_VtickKeyExists) {
    EXPECT_CALL(mockRedis, exists("tick_data:5")).WillOnce(Return(false));
    EXPECT_CALL(mockRedis, exists("vtick:5")).WillOnce(Return(true));
    EXPECT_TRUE(db_has_tick_data(5));
}

TEST_F(DbTest, HasTickData_NeitherExists) {
    EXPECT_CALL(mockRedis, exists("tick_data:5")).WillOnce(Return(false));
    EXPECT_CALL(mockRedis, exists("vtick:5")).WillOnce(Return(false));
    EXPECT_FALSE(db_has_tick_data(5));
}

TEST_F(DbTest, HasTickData_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_has_tick_data(5));
}

// ---------------------------------------------------------------------------
// db_check_transaction_exist
// ---------------------------------------------------------------------------

TEST_F(DbTest, CheckTransactionExist_Found) {
    EXPECT_CALL(mockRedis, exists("transaction:hash123")).WillOnce(Return(true));
    EXPECT_TRUE(db_check_transaction_exist("hash123"));
}

TEST_F(DbTest, CheckTransactionExist_NotFound) {
    EXPECT_CALL(mockRedis, exists("transaction:hash123")).WillOnce(Return(false));
    EXPECT_FALSE(db_check_transaction_exist("hash123"));
}

TEST_F(DbTest, CheckTransactionExist_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_check_transaction_exist("hash123"));
}

// ---------------------------------------------------------------------------
// db_try_get_transaction
// ---------------------------------------------------------------------------

TEST_F(DbTest, TryGetTransaction_FoundInRedis) {
    std::string data = "txdata";
    EXPECT_CALL(mockRedis, get("transaction:abc")).WillOnce(Return(sw::redis::OptionalString(data)));
    std::vector<uint8_t> out;
    EXPECT_TRUE(db_try_get_transaction("abc", out));
    EXPECT_EQ(out.size(), data.size());
}

TEST_F(DbTest, TryGetTransaction_NotInRedisFallsToKvrocks) {
    std::string data = "txdata";
    EXPECT_CALL(mockRedis, get("transaction:abc")).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockKvrocks, get("transaction:abc")).WillOnce(Return(sw::redis::OptionalString(data)));
    std::vector<uint8_t> out;
    EXPECT_TRUE(db_try_get_transaction("abc", out));
}

TEST_F(DbTest, TryGetTransaction_NotFound_ReturnsFalse) {
    EXPECT_CALL(mockRedis, get("transaction:abc")).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockKvrocks, get("transaction:abc")).WillOnce(Return(sw::redis::OptionalString{}));
    std::vector<uint8_t> out;
    EXPECT_FALSE(db_try_get_transaction("abc", out));
}

// ---------------------------------------------------------------------------
// db_get_many_transaction_from_keydb
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetManyTransactionFromKeydb_EmptyKeys_ReturnsTrue) {
    std::vector<std::optional<std::string>> out;
    EXPECT_TRUE(db_get_many_transaction_from_keydb({}, out));
}

TEST_F(DbTest, GetManyTransactionFromKeydb_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    std::vector<std::optional<std::string>> out;
    EXPECT_FALSE(db_get_many_transaction_from_keydb({"k1"}, out));
}

TEST_F(DbTest, GetManyTransactionFromKeydb_CallsMget) {
    EXPECT_CALL(mockRedis, mget(_, _, _)).Times(1);
    std::vector<std::optional<std::string>> out;
    EXPECT_TRUE(db_get_many_transaction_from_keydb({"k1", "k2"}, out));
}

// ---------------------------------------------------------------------------
// db_insert_computors / db_get_computors
// ---------------------------------------------------------------------------

TEST_F(DbTest, InsertComputors_Success) {
    Computors comps{};
    comps.epoch = 3;
    EXPECT_TRUE(db_insert_computors(comps));
}

TEST_F(DbTest, InsertComputors_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    Computors comps{};
    EXPECT_FALSE(db_insert_computors(comps));
}

TEST_F(DbTest, GetComputors_Found) {
    Computors expected{};
    expected.epoch = 3;
    std::string raw(reinterpret_cast<char*>(&expected), sizeof(Computors));
    EXPECT_CALL(mockRedis, get("computor:3")).WillOnce(Return(sw::redis::OptionalString(raw)));
    Computors out{};
    EXPECT_TRUE(db_get_computors(3, out));
    EXPECT_EQ(out.epoch, 3u);
}

TEST_F(DbTest, GetComputors_NotFound) {
    EXPECT_CALL(mockRedis, get("computor:3")).WillOnce(Return(sw::redis::OptionalString{}));
    Computors out{};
    EXPECT_FALSE(db_get_computors(3, out));
}

TEST_F(DbTest, GetComputors_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    Computors out{};
    EXPECT_FALSE(db_get_computors(3, out));
}

// ---------------------------------------------------------------------------
// db_update_field
// ---------------------------------------------------------------------------

TEST_F(DbTest, UpdateField_Success) {
    EXPECT_CALL(mockRedis, hset("mykey", "myfield", "myval")).Times(1);
    EXPECT_TRUE(db_update_field("mykey", "myfield", "myval"));
}

TEST_F(DbTest, UpdateField_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_update_field("mykey", "myfield", "myval"));
}

// ---------------------------------------------------------------------------
// db_insert_u32 / db_get_u32
// ---------------------------------------------------------------------------

TEST_F(DbTest, InsertU32_Success) {
    EXPECT_CALL(mockRedis, set(std::string("mykey"), std::string("42"))).Times(1);
    EXPECT_TRUE(db_insert_u32("mykey", 42));
}

TEST_F(DbTest, InsertU32_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_insert_u32("mykey", 42));
}

TEST_F(DbTest, GetU32_Found) {
    EXPECT_CALL(mockRedis, get("mykey")).WillOnce(Return(sw::redis::OptionalString("123")));
    uint32_t val = 0;
    EXPECT_TRUE(db_get_u32("mykey", val));
    EXPECT_EQ(val, 123u);
}

TEST_F(DbTest, GetU32_NotFound) {
    EXPECT_CALL(mockRedis, get("mykey")).WillOnce(Return(sw::redis::OptionalString{}));
    uint32_t val = 0;
    EXPECT_FALSE(db_get_u32("mykey", val));
}

TEST_F(DbTest, GetU32_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    uint32_t val = 0;
    EXPECT_FALSE(db_get_u32("mykey", val));
}

// ---------------------------------------------------------------------------
// db_key_exists
// ---------------------------------------------------------------------------

TEST_F(DbTest, KeyExists_True) {
    EXPECT_CALL(mockRedis, exists("k")).WillOnce(Return(true));
    EXPECT_TRUE(db_key_exists("k"));
}

TEST_F(DbTest, KeyExists_False) {
    EXPECT_CALL(mockRedis, exists("k")).WillOnce(Return(false));
    EXPECT_FALSE(db_key_exists("k"));
}

TEST_F(DbTest, KeyExists_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_key_exists("k"));
}

// ---------------------------------------------------------------------------
// db_rename
// ---------------------------------------------------------------------------

TEST_F(DbTest, Rename_Success) {
    EXPECT_CALL(mockRedis, rename("k1", "k2")).Times(1);
    EXPECT_TRUE(db_rename("k1", "k2"));
}

TEST_F(DbTest, Rename_Throws_ReturnsFalse) {
    EXPECT_CALL(mockRedis, rename("k1", "k2")).WillOnce(testing::Throw(sw::redis::Error("fail")));
    EXPECT_FALSE(db_rename("k1", "k2"));
}

TEST_F(DbTest, Rename_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_rename("k1", "k2"));
}

// ---------------------------------------------------------------------------
// db_copy
// ---------------------------------------------------------------------------

TEST_F(DbTest, Copy_Success) {
    EXPECT_CALL(mockRedis, get("k1")).WillOnce(Return(sw::redis::OptionalString("val")));
    EXPECT_CALL(mockRedis, set(std::string("k2"), std::string("val"))).Times(1);
    EXPECT_TRUE(db_copy("k1", "k2"));
}

TEST_F(DbTest, Copy_SourceNotFound_ReturnsFalse) {
    EXPECT_CALL(mockRedis, get("k1")).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_FALSE(db_copy("k1", "k2"));
}

TEST_F(DbTest, Copy_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_copy("k1", "k2"));
}

// ---------------------------------------------------------------------------
// db_hcopy
// ---------------------------------------------------------------------------

TEST_F(DbTest, Hcopy_Success) {
    EXPECT_CALL(mockRedis, hgetall("k1", _)).Times(1);
    EXPECT_TRUE(db_hcopy("k1", "k2"));
}

TEST_F(DbTest, Hcopy_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_hcopy("k1", "k2"));
}

// ---------------------------------------------------------------------------
// db_get_last_indexed_tick / db_update_last_indexed_tick
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetLastIndexedTick_Found) {
    EXPECT_CALL(mockRedis, hget("db_status", "last_indexed_tick"))
        .WillOnce(Return(sw::redis::OptionalString("500")));
    EXPECT_EQ(db_get_last_indexed_tick(), 500LL);
}

TEST_F(DbTest, GetLastIndexedTick_NotFound_ReturnsMinusOne) {
    EXPECT_CALL(mockRedis, hget("db_status", "last_indexed_tick"))
        .WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_EQ(db_get_last_indexed_tick(), -1LL);
}

TEST_F(DbTest, GetLastIndexedTick_NoRedis_ReturnsMinusOne) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_EQ(db_get_last_indexed_tick(), -1LL);
}

TEST_F(DbTest, UpdateLastIndexedTick_Success) {
    EXPECT_CALL(mockRedis, eval_ll(_, _, _, _, _)).WillOnce(Return(1));
    EXPECT_TRUE(db_update_last_indexed_tick(600));
}

TEST_F(DbTest, UpdateLastIndexedTick_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    EXPECT_FALSE(db_update_last_indexed_tick(600));
}

// ---------------------------------------------------------------------------
// db_set_indexed_tx
// ---------------------------------------------------------------------------

TEST_F(DbTest, SetIndexedTx_Success) {
    EXPECT_CALL(mockKvrocks, set(_, _, _)).Times(1);
    EXPECT_TRUE(db_set_indexed_tx("itx:hash1", 0, 10, 20, 1000, true));
}

TEST_F(DbTest, SetIndexedTx_NoKvrocks_ReturnsFalse) {
    db_inject_redis(&mockRedis, nullptr);
    EXPECT_FALSE(db_set_indexed_tx("itx:hash1", 0, 10, 20, 1000, true));
}

// ---------------------------------------------------------------------------
// db_set_many_indexed_tx
// ---------------------------------------------------------------------------

TEST_F(DbTest, SetManyIndexedTx_EmptyList_ReturnsTrue) {
    EXPECT_TRUE(db_set_many_indexed_tx({}));
}

TEST_F(DbTest, SetManyIndexedTx_NoKvrocks_ReturnsFalse) {
    db_inject_redis(&mockRedis, nullptr);
    std::vector<std::tuple<std::string, int, long long, long long, uint64_t, bool>> list = {
        {"itx:h1", 0, 1, 2, 100, true}
    };
    EXPECT_FALSE(db_set_many_indexed_tx(list));
}

TEST_F(DbTest, SetManyIndexedTx_UsesPipeline) {
    auto* rawPipe = new MockPipeline();
    EXPECT_CALL(*rawPipe, set(_, _, _)).WillRepeatedly(testing::ReturnRef(*rawPipe));
    EXPECT_CALL(*rawPipe, exec()).Times(1);
    EXPECT_CALL(mockKvrocks, pipeline()).WillOnce(Return(std::unique_ptr<IPipeline>(rawPipe)));

    std::vector<std::tuple<std::string, int, long long, long long, uint64_t, bool>> list = {
        {"itx:h1", 0, 1, 2, 100, true},
        {"itx:h2", 1, 3, 4, 200, false}
    };
    EXPECT_TRUE(db_set_many_indexed_tx(list));
}

// ---------------------------------------------------------------------------
// db_get_indexed_tx
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetIndexedTx_FoundInRedis) {
    indexedTxData data{1, true, 10, 20, 5000};
    std::string raw(reinterpret_cast<char*>(&data), sizeof(data));
    EXPECT_CALL(mockRedis, get("itx:hash1")).WillOnce(Return(sw::redis::OptionalString(raw)));
    int idx; long long from, to; uint64_t ts; bool exec;
    EXPECT_TRUE(db_get_indexed_tx("hash1", idx, from, to, ts, exec));
    EXPECT_EQ(idx, 1);
    EXPECT_TRUE(exec);
}

TEST_F(DbTest, GetIndexedTx_NotFoundAnywhere_ReturnsFalse) {
    EXPECT_CALL(mockRedis, get("itx:hash1")).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockKvrocks, get("itx:hash1")).WillOnce(Return(sw::redis::OptionalString{}));
    int idx; long long from, to; uint64_t ts; bool exec;
    EXPECT_FALSE(db_get_indexed_tx("hash1", idx, from, to, ts, exec));
}

// ---------------------------------------------------------------------------
// db_add_many_indexer
// ---------------------------------------------------------------------------

TEST_F(DbTest, AddManyIndexer_EmptyKeys_ReturnsFalse) {
    EXPECT_FALSE(db_add_many_indexer({}, 100));
}

TEST_F(DbTest, AddManyIndexer_NoKvrocks_ReturnsFalse) {
    db_inject_redis(&mockRedis, nullptr);
    EXPECT_FALSE(db_add_many_indexer({"key1"}, 100));
}

TEST_F(DbTest, AddManyIndexer_Success) {
    EXPECT_CALL(mockKvrocks, eval_ll(_, _, _, _, _)).WillOnce(Return(1));
    EXPECT_TRUE(db_add_many_indexer({"indexed:1", "indexed:2"}, 100));
}

// ---------------------------------------------------------------------------
// db_get_combined_log_range_for_ticks
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetCombinedLogRangeForTicks_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    long long from, len;
    EXPECT_FALSE(db_get_combined_log_range_for_ticks(1, 5, from, len));
}

TEST_F(DbTest, GetCombinedLogRangeForTicks_StartGtEnd_ReturnsFalse) {
    long long from, len;
    EXPECT_FALSE(db_get_combined_log_range_for_ticks(10, 5, from, len));
}

// ---------------------------------------------------------------------------
// db_copy_transaction_to_kvrocks
// ---------------------------------------------------------------------------

TEST_F(DbTest, CopyTransactionToKvrocks_NotFoundInRedis_ReturnsFalse) {
    EXPECT_CALL(mockRedis, get("transaction:abc")).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_FALSE(db_copy_transaction_to_kvrocks("abc"));
}

TEST_F(DbTest, CopyTransactionToKvrocks_Success) {
    EXPECT_CALL(mockRedis, get("transaction:abc")).WillOnce(Return(sw::redis::OptionalString("data")));
    EXPECT_CALL(mockKvrocks, set(std::string("transaction:abc"), _, _)).Times(1);
    EXPECT_TRUE(db_copy_transaction_to_kvrocks("abc"));
}

TEST_F(DbTest, CopyTransactionToKvrocks_NoKvrocks_ReturnsFalse) {
    db_inject_redis(&mockRedis, nullptr);
    EXPECT_FALSE(db_copy_transaction_to_kvrocks("abc"));
}

// ---------------------------------------------------------------------------
// db_add_many_transactions_to_kvrocks
// ---------------------------------------------------------------------------

TEST_F(DbTest, AddManyTransactionsToKvrocks_EmptyKeys_ReturnsTrue) {
    EXPECT_TRUE(db_add_many_transactions_to_kvrocks({}, {}));
}

TEST_F(DbTest, AddManyTransactionsToKvrocks_SizeMismatch_ReturnsFalse) {
    EXPECT_FALSE(db_add_many_transactions_to_kvrocks({"k1"}, {}));
}

TEST_F(DbTest, AddManyTransactionsToKvrocks_UsesPipeline) {
    auto* rawPipe = new MockPipeline();
    EXPECT_CALL(*rawPipe, set(_, _, _)).WillRepeatedly(testing::ReturnRef(*rawPipe));
    EXPECT_CALL(*rawPipe, exec()).Times(1);
    EXPECT_CALL(mockKvrocks, pipeline()).WillOnce(Return(std::unique_ptr<IPipeline>(rawPipe)));

    std::vector<std::string> keys = {"k1"};
    std::vector<std::optional<std::string>> vals = {std::string("v1")};
    EXPECT_TRUE(db_add_many_transactions_to_kvrocks(keys, vals));
}

// ---------------------------------------------------------------------------
// db_move_logs_to_kvrocks_by_range
// ---------------------------------------------------------------------------

TEST_F(DbTest, MoveLogsToKvrocksByRange_NegativeRange_ReturnsTrue) {
    EXPECT_TRUE(db_move_logs_to_kvrocks_by_range(1, -1, -1));
}

TEST_F(DbTest, MoveLogsToKvrocksByRange_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, &mockKvrocks);
    EXPECT_FALSE(db_move_logs_to_kvrocks_by_range(1, 0, 5));
}

TEST_F(DbTest, MoveLogsToKvrocksByRange_LogMissingInRedis_ReturnsFalse) {
    EXPECT_CALL(mockRedis, mget(_, _, _))
        .WillOnce(testing::Invoke([](auto, auto, std::back_insert_iterator<OptStringVec> out) {
            *out++ = sw::redis::OptionalString{};
        }));
    EXPECT_FALSE(db_move_logs_to_kvrocks_by_range(1, 0, 0));
}

// ---------------------------------------------------------------------------
// db_get_end_epoch_log_range
// ---------------------------------------------------------------------------

TEST_F(DbTest, GetEndEpochLogRange_Found) {
    long long from, len;
    EXPECT_CALL(mockRedis, hmget("end_epoch:tick_log_range:5", _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec> out) {
            *out++ = std::string("100");
            *out++ = std::string("50");
        }));
    EXPECT_TRUE(db_get_end_epoch_log_range(5, from, len));
    EXPECT_EQ(from, 100LL);
    EXPECT_EQ(len, 50LL);
}

TEST_F(DbTest, GetEndEpochLogRange_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    long long from, len;
    EXPECT_FALSE(db_get_end_epoch_log_range(5, from, len));
}

// ---------------------------------------------------------------------------
// db_try_get_tick_data
// ---------------------------------------------------------------------------

TEST_F(DbTest, TryGetTickData_FoundInRedis) {
    TickData expected{};
    expected.tick = 11;
    std::string raw(reinterpret_cast<char*>(&expected), sizeof(TickData));
    EXPECT_CALL(mockRedis, get("tick_data:11")).WillOnce(Return(sw::redis::OptionalString(raw)));
    TickData out{};
    EXPECT_TRUE(db_try_get_tick_data(11, out));
    EXPECT_EQ(out.tick, 11u);
}

TEST_F(DbTest, TryGetTickData_NotFoundAnywhere_ReturnsFalse) {
    EXPECT_CALL(mockRedis, get("tick_data:11")).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockKvrocks, get("vtick:11")).WillOnce(Return(sw::redis::OptionalString{}));
    TickData out{};
    EXPECT_FALSE(db_try_get_tick_data(11, out));
}

// ---------------------------------------------------------------------------
// db_search_log
// ---------------------------------------------------------------------------

TEST_F(DbTest, SearchLog_InvalidTopic1Size_ReturnsEmpty) {
    auto result = db_search_log(1, 0, 0, 100, "short", std::string(60, 'a'), std::string(60, 'a'));
    EXPECT_TRUE(result.empty());
}

TEST_F(DbTest, SearchLog_NoKvrocks_ReturnsEmpty) {
    db_inject_redis(&mockRedis, nullptr);
    auto result = db_search_log(1, 0, 0, 100, std::string(60, 'a'), std::string(60, 'a'), std::string(60, 'a'));
    EXPECT_TRUE(result.empty());
}

TEST_F(DbTest, SearchLog_AllWildcardNoLogType_CallsZrangebyscore) {
    EXPECT_CALL(mockRedis, zrangebyscore(std::string("indexed:1"), _, _)).Times(1);
    EXPECT_CALL(mockKvrocks, zrangebyscore(std::string("indexed:1"), _, _)).Times(1);
    db_search_log(1, 0xffffffff, 0, 100, std::string(WILDCARD), std::string(WILDCARD), std::string(WILDCARD));
}

TEST_F(DbTest, InsertTransaction_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    Transaction tx{};
    tx.inputSize = 0;
    EXPECT_FALSE(db_insert_transaction(&tx));
}

TEST_F(DbTest, InsertTransaction_Success) {
    size_t tx_size = sizeof(Transaction) + SIGNATURE_SIZE;
    std::vector<uint8_t> buf(tx_size, 0);
    Transaction* tx = reinterpret_cast<Transaction*>(buf.data());
    tx->inputSize = 0;

    char expectedHash[64] = {0};
    getQubicHash(buf.data(), tx_size, expectedHash);
    std::string expectedKey = "transaction:" + std::string(expectedHash);

    EXPECT_CALL(mockRedis, set(expectedKey, _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST)).Times(1);
    EXPECT_TRUE(db_insert_transaction(tx));
}

TEST_F(DbTest, InsertTransaction_RedisThrows_ReturnsFalse) {
    Transaction tx{};
    tx.inputSize = 0;

    EXPECT_CALL(mockRedis, set(_, _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST))
        .WillOnce(testing::Throw(sw::redis::Error("fail")));
    EXPECT_FALSE(db_insert_transaction(&tx));
}

// ---------------------------------------------------------------------------
// db_insert_log_range
// ---------------------------------------------------------------------------

TEST_F(DbTest, InsertLogRange_NoRedis_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    LogRangesPerTxInTick lr{};
    EXPECT_FALSE(db_insert_log_range(10, lr));
}

TEST_F(DbTest, InsertLogRange_AllZero_ReturnsFalse) {
    LogRangesPerTxInTick lr{};
    memset(&lr, 0, sizeof(lr));
    EXPECT_FALSE(db_insert_log_range(10, lr));
}

TEST_F(DbTest, InsertLogRange_ValidData_CallsSetAndHmset) {
    LogRangesPerTxInTick lr{};
    memset(&lr, 0, sizeof(lr));
    lr.fromLogId[0] = 5;
    lr.length[0]    = 3;

    EXPECT_CALL(mockRedis, set(std::string("log_ranges:10"), _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST)).Times(1);
    EXPECT_CALL(mockRedis, hmset(std::string("tick_log_range:10"), _, _)).Times(1);
    EXPECT_TRUE(db_insert_log_range(10, lr));
}

TEST_F(DbTest, InsertLogRange_RedisThrows_ReturnsFalse) {
    LogRangesPerTxInTick lr{};
    memset(&lr, 0, sizeof(lr));
    lr.fromLogId[0] = 5;
    lr.length[0]    = 3;

    EXPECT_CALL(mockRedis, set(_, _, std::chrono::milliseconds(0), sw::redis::UpdateType::NOT_EXIST))
        .WillOnce(testing::Throw(sw::redis::Error("fail")));
    EXPECT_FALSE(db_insert_log_range(10, lr));
}

// ---------------------------------------------------------------------------
// db_try_get_log_ranges
// ---------------------------------------------------------------------------

TEST_F(DbTest, TryGetLogRanges_NoRedisNoKvrocks_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    LogRangesPerTxInTick lr{};
    EXPECT_FALSE(db_try_get_log_ranges(10, lr));
}

TEST_F(DbTest, TryGetLogRanges_FoundInRedis) {
    LogRangesPerTxInTick expected{};
    memset(&expected, 0, sizeof(expected));
    expected.fromLogId[0] = 10;
    expected.length[0]    = 5;

    std::string raw(reinterpret_cast<char*>(&expected), sizeof(LogRangesPerTxInTick));
    EXPECT_CALL(mockRedis, get(std::string("log_ranges:10"))).WillOnce(Return(sw::redis::OptionalString(raw)));

    LogRangesPerTxInTick out{};
    EXPECT_TRUE(db_try_get_log_ranges(10, out));
    EXPECT_EQ(out.fromLogId[0], 10LL);
    EXPECT_EQ(out.length[0],    5LL);
}

TEST_F(DbTest, TryGetLogRanges_NotInRedis_FallsBackToKvrocks_NotFound) {
    EXPECT_CALL(mockRedis,   get(std::string("log_ranges:10"))).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockKvrocks, get(std::string("cLogRange:10"))).WillOnce(Return(sw::redis::OptionalString{}));

    LogRangesPerTxInTick out{};
    EXPECT_FALSE(db_try_get_log_ranges(10, out));
}

// ---------------------------------------------------------------------------
// db_try_get_log_range_for_tick
// ---------------------------------------------------------------------------

TEST_F(DbTest, TryGetLogRangeForTick_NoRedisNoKvrocks_ReturnsFalse) {
    db_inject_redis(nullptr, nullptr);
    long long from, len;
    EXPECT_FALSE(db_try_get_log_range_for_tick(5, from, len));
    EXPECT_EQ(from, -1LL);
    EXPECT_EQ(len,  -1LL);
}

TEST_F(DbTest, TryGetLogRangeForTick_FoundInRedis) {
    EXPECT_CALL(mockRedis, hmget(std::string("tick_log_range:5"), _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec> out) {
            *out++ = std::string("100");
            *out++ = std::string("50");
        }));

    long long from, len;
    EXPECT_TRUE(db_try_get_log_range_for_tick(5, from, len));
    EXPECT_EQ(from, 100LL);
    EXPECT_EQ(len,   50LL);
}

TEST_F(DbTest, TryGetLogRangeForTick_EmptyTick_ReturnsNegativeOne) {
    EXPECT_CALL(mockRedis, hmget(std::string("tick_log_range:5"), _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec> out) {
            *out++ = std::string("-1");
            *out++ = std::string("-1");
        }));

    long long from, len;
    EXPECT_TRUE(db_try_get_log_range_for_tick(5, from, len));
    EXPECT_EQ(from, -1LL);
    EXPECT_EQ(len,  -1LL);
}

TEST_F(DbTest, TryGetLogRangeForTick_NotInRedis_FallsBackToKvrocks) {
    EXPECT_CALL(mockRedis, hmget(std::string("tick_log_range:5"), _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec> out) {}));

    EXPECT_CALL(mockKvrocks, hmget(std::string("tick_log_range:5"), _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec> out) {
            *out++ = std::string("200");
            *out++ = std::string("10");
        }));

    long long from, len;
    EXPECT_TRUE(db_try_get_log_range_for_tick(5, from, len));
    EXPECT_EQ(from, 200LL);
    EXPECT_EQ(len,   10LL);
}

TEST_F(DbTest, TryGetLogRangeForTick_NotFoundAnywhere_ReturnsFalse) {
    EXPECT_CALL(mockRedis,   hmget(std::string("tick_log_range:5"), _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec>) {}));
    EXPECT_CALL(mockKvrocks, hmget(std::string("tick_log_range:5"), _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec>) {}));

    long long from, len;
    EXPECT_FALSE(db_try_get_log_range_for_tick(5, from, len));
    EXPECT_EQ(from, -1LL);
    EXPECT_EQ(len,  -1LL);
}

TEST_F(DbTest, TryGetLogRangeForTick_RedisThrows_ReturnsFalse) {
    EXPECT_CALL(mockRedis, hmget(std::string("tick_log_range:5"), _, _))
        .WillOnce(testing::Throw(sw::redis::Error("fail")));
    EXPECT_CALL(mockKvrocks, hmget(std::string("tick_log_range:5"), _, _))
        .WillOnce(testing::Invoke([](const std::string&, std::initializer_list<std::string>, std::back_insert_iterator<OptionalStringVec>) {}));

    long long from, len;
    EXPECT_FALSE(db_try_get_log_range_for_tick(5, from, len));
}

namespace {
    std::string makeLogBlob(uint16_t epoch, uint32_t tick, uint64_t logId, uint32_t bodySize = 0) {
        std::vector<uint8_t> buf(LogEvent::PackedHeaderSize + bodySize, 0);

        memcpy(buf.data() + 0,  &epoch,  sizeof(epoch));
        memcpy(buf.data() + 2,  &tick,   sizeof(tick));

        uint32_t combo = (bodySize & 0x00FFFFFFu);
        memcpy(buf.data() + 6,  &combo,  sizeof(combo));
        memcpy(buf.data() + 10, &logId,  sizeof(logId));

        uint64_t digest = 0;
        if (bodySize > 0) {
            KangarooTwelve(buf.data() + LogEvent::PackedHeaderSize, bodySize, reinterpret_cast<uint8_t*>(&digest), 8);
        }
        memcpy(buf.data() + 18, &digest, sizeof(digest));

        return std::string(reinterpret_cast<char*>(buf.data()), buf.size());
    }
}

// ---------------------------------------------------------------------------
// db_try_get_logs
// ---------------------------------------------------------------------------

TEST_F(DbTest, TryGetLogs_NoRedis_ReturnsEmpty) {
    db_inject_redis(nullptr, nullptr);
    auto result = db_try_get_logs(1, 0, 2);
    EXPECT_TRUE(result.empty());
}

TEST_F(DbTest, TryGetLogs_EmptyRange_ReturnsEmpty) {
    auto result = db_try_get_logs(1, 5, 4);
    EXPECT_TRUE(result.empty());
}

TEST_F(DbTest, TryGetLogs_AllMissingInBothStores_ReturnsEmpty) {
    EXPECT_CALL(mockRedis,   get(std::string("log:1:0"))).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockKvrocks, get(std::string("log:1:0"))).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockRedis,   get(std::string("log:1:1"))).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockKvrocks, get(std::string("log:1:1"))).WillOnce(Return(sw::redis::OptionalString{}));

    auto result = db_try_get_logs(1, 0, 1);
    EXPECT_TRUE(result.empty());
}

TEST_F(DbTest, TryGetLogs_ValidLogs_ReturnsAll) {
    const uint16_t epoch  = 2;
    const uint64_t logId0 = 10;
    const uint64_t logId1 = 11;
    const uint32_t tick   = 99;

    EXPECT_CALL(mockRedis, get(std::string("log:2:10")))
        .WillOnce(Return(sw::redis::OptionalString(makeLogBlob(epoch, tick, logId0))));
    EXPECT_CALL(mockRedis, get(std::string("log:2:11")))
        .WillOnce(Return(sw::redis::OptionalString(makeLogBlob(epoch, tick, logId1))));

    auto result = db_try_get_logs(epoch, logId0, logId1);
    EXPECT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].getLogId(), logId0);
    EXPECT_EQ(result[1].getLogId(), logId1);
    EXPECT_EQ(result[0].getEpoch(), epoch);
    EXPECT_EQ(result[1].getEpoch(), epoch);
}

TEST_F(DbTest, TryGetLogs_PartialMissing_ReturnsOnlyFound) {
    const uint16_t epoch = 3;

    EXPECT_CALL(mockRedis, get(std::string("log:3:7")))
        .WillOnce(Return(sw::redis::OptionalString(makeLogBlob(epoch, 50, 7))));
    EXPECT_CALL(mockRedis,   get(std::string("log:3:8"))).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockKvrocks, get(std::string("log:3:8"))).WillOnce(Return(sw::redis::OptionalString{}));

    auto result = db_try_get_logs(epoch, 7, 8);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].getLogId(), 7ull);
}

TEST_F(DbTest, TryGetLogs_WrongEpochInBlob_Skipped) {
    const uint16_t epoch       = 4;
    const uint16_t wrongEpoch  = 5;

    EXPECT_CALL(mockRedis, get(std::string("log:4:20")))
        .WillOnce(Return(sw::redis::OptionalString(makeLogBlob(wrongEpoch, 10, 20))));
    EXPECT_CALL(mockKvrocks, get(std::string("log:4:20")))
        .WillOnce(Return(sw::redis::OptionalString{}));

    auto result = db_try_get_logs(epoch, 20, 20);
    EXPECT_TRUE(result.empty());
}

TEST_F(DbTest, TryGetLogs_WrongLogIdInBlob_Skipped) {
    const uint16_t epoch = 4;

    EXPECT_CALL(mockRedis, get(std::string("log:4:20")))
        .WillOnce(Return(sw::redis::OptionalString(makeLogBlob(epoch, 10, 99))));
    EXPECT_CALL(mockKvrocks, get(std::string("log:4:20")))
        .WillOnce(Return(sw::redis::OptionalString{}));

    auto result = db_try_get_logs(epoch, 20, 20);
    EXPECT_TRUE(result.empty());
}

TEST_F(DbTest, TryGetLogs_TooSmallBlob_Skipped) {
    EXPECT_CALL(mockRedis, get(std::string("log:1:0")))
        .WillOnce(Return(sw::redis::OptionalString("tiny")));
    EXPECT_CALL(mockKvrocks, get(std::string("log:1:0")))
        .WillOnce(Return(sw::redis::OptionalString{}));

    auto result = db_try_get_logs(1, 0, 0);
    EXPECT_TRUE(result.empty());
}

TEST_F(DbTest, TryGetLogs_FallsBackToKvrocks) {
    const uint16_t epoch = 5;
    const uint64_t logId = 30;

    EXPECT_CALL(mockRedis,   get(std::string("log:5:30"))).WillOnce(Return(sw::redis::OptionalString{}));
    EXPECT_CALL(mockKvrocks, get(std::string("log:5:30")))
        .WillOnce(Return(sw::redis::OptionalString(makeLogBlob(epoch, 10, logId))));

    auto result = db_try_get_logs(epoch, logId, logId);
    EXPECT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].getLogId(), logId);
}

// ---------------------------------------------------------------------------
// Cannot test (require real Redis/Kvrocks or complex internal state):
// - db_get_logs_by_tick_range (depends on db_try_get_log_range_for_tick and LogEvent internals)
// - db_get_quorum_unixtime_from_votes (depends on db_try_to_get_votes + timegm)
// - db_is_tick_empty (depends on db_try_to_get_votes + m256i)
// - db_try_to_get_votes (depends on db_get_tick_votes_from_vtick -> db_get_vtick_from_kvrocks -> zstd)
// - db_try_get_tick_vote (same zstd/vtick dependency)
// - db_insert_vtick_to_kvrocks / db_get_vtick_from_kvrocks (require zstd compression)
// - db_insert_cLogRange_to_kvrocks / db_get_cLogRange_from_kvrocks (require zstd compression)
// - db_insert_TickLogRange_to_kvrocks (requires kvrocks + expire)
// - db_get_endepoch_log_range_info (requires LogRangesPerTxInTick binary blob)