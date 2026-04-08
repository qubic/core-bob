#include "connection/connection.h"
// mapping from dejavu to requested data
// usage: some response doesn't contain requested info
// if code makes several queries, we need this map to know which
// response to which request
class RequestMap
{
public:
    // Convert input to RequestedData and add/replace entry for given dejavu.
    void add(const uint32_t dejavu, const uint8_t* data, const int size, QCPtr conn)
    {
        std::lock_guard<std::mutex> lock(mtx_);

        RequestedData rd;
        const uint64_t now =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count());
        rd.timestamp = now;

        if (data != nullptr && size > 0) {
            rd.data.assign(data, data + static_cast<size_t>(size));
        } else {
            rd.data.clear();
        }
        rd.conn = std::move(conn);
        mem[dejavu] = std::move(rd);
    }

    // Look up dejavu; if found copy into dataOut; return true, else false.
    bool get(uint32_t dejavu, std::vector<uint8_t>& dataOut, QCPtr& conn)
    {
        std::lock_guard<std::mutex> lock(mtx_);

        auto it = mem.find(dejavu);
        if (it == mem.end()) {
            return false;
        }

        dataOut = it->second.data;
        conn = it->second.conn;
        return true;
    }

    bool get(uint32_t dejavu, std::vector<uint8_t>& dataOut)
    {
        std::lock_guard<std::mutex> lock(mtx_);

        auto it = mem.find(dejavu);
        if (it == mem.end()) {
            return false;
        }

        dataOut = it->second.data;
        return true;
    }

    // Remove entries older than 60 seconds.
    void clean(uint32_t period = 60)
    {
        std::lock_guard<std::mutex> lock(mtx_);

        const uint64_t now =
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count());
        for (auto it = mem.begin(); it != mem.end(); ) {
            const uint64_t age = (now >= it->second.timestamp) ? (now - it->second.timestamp) : 0;
            if (age > period) {
                it = mem.erase(it);
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief Returns a string containing the current map usage information.
     * @return String with map size and entries count.
     */
    std::string GetMapUsageString() {
        std::lock_guard<std::mutex> lock(mtx_);
        return "Map Usage: " + std::to_string(mem.size()) + " entries";
    }

private:
    struct RequestedData
    {
        uint64_t timestamp;
        QCPtr conn;
        std::vector<uint8_t> data;
    };
    std::map <uint32_t, RequestedData> mem;
    std::mutex mtx_;
};