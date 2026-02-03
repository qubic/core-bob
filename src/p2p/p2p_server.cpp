#include <atomic>
#include <thread>
#include <vector>
#include <memory>
#include <mutex>
#include <cstring>
#include <unordered_map>
#include <chrono>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "src/connection/connection.h"
#include "src/logger/logger.h"
#include "src/shim.h"

// Forward declaration from IOProcessor.cpp
void connReceiver(QCPtr conn, const bool isTrustedNode);

namespace {
    // Simple connection limiter with global and per-IP limits
    class ConnectionLimiter {
    public:
        ConnectionLimiter(size_t max_global, size_t max_per_ip)
                : max_global_(max_global), max_per_ip_(max_per_ip) {}

        // Try to accept a new connection from the given IP
        // Returns true if allowed, false if limits exceeded
        bool tryAccept(const std::string& ip) {
            std::lock_guard<std::mutex> lk(mutex_);

            // Check global limit
            if (total_connections_ >= max_global_) {
                Logger::get()->warn("ConnectionLimiter: Global limit reached ({}/{})",
                                    total_connections_, max_global_);
                return false;
            }

            // Check per-IP limit
            auto current_ip_count = ip_connections_[ip];
            if (current_ip_count >= max_per_ip_) {
                Logger::get()->warn("ConnectionLimiter: IP {} limit reached ({}/{})",
                                    ip, current_ip_count, max_per_ip_);
                return false;
            }

            // Accept the connection
            ip_connections_[ip]++;
            total_connections_++;

            Logger::get()->debug("ConnectionLimiter: Accepted {} (IP: {}/{}, Global: {}/{})",
                                 ip, ip_connections_[ip], max_per_ip_,
                                 total_connections_, max_global_);
            return true;
        }

        // Release a connection from the given IP
        void release(const std::string& ip) {
            std::lock_guard<std::mutex> lk(mutex_);

            auto it = ip_connections_.find(ip);
            if (it != ip_connections_.end()) {
                if (--it->second == 0) {
                    ip_connections_.erase(it);
                }
            }

            if (total_connections_ > 0) {
                total_connections_--;
            }

            Logger::get()->debug("ConnectionLimiter: Released {} (Global: {}/{})",
                                 ip, total_connections_, max_global_);
        }

        // Get current statistics
        size_t getTotalConnections() const {
            std::lock_guard<std::mutex> lk(mutex_);
            return total_connections_;
        }

        size_t getIpConnectionCount(const std::string& ip) const {
            std::lock_guard<std::mutex> lk(mutex_);
            auto it = ip_connections_.find(ip);
            return (it != ip_connections_.end()) ? it->second : 0;
        }

    private:
        mutable std::mutex mutex_;
        std::unordered_map<std::string, size_t> ip_connections_;
        size_t total_connections_ = 0;
        const size_t max_global_;
        const size_t max_per_ip_;
    };

    class QubicServer {
    public:
        static QubicServer& instance() {
            static QubicServer inst;
            return inst;
        }

        bool start(uint16_t port = 21842, size_t max_connections = 64, size_t max_per_ip = 5) {
            std::lock_guard<std::mutex> lk(m_);
            if (running_) return true;

            // Initialize connection limiter
            limiter_ = std::make_unique<ConnectionLimiter>(max_connections, max_per_ip);

            listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
            if (listen_fd_ < 0) {
                Logger::get()->critical("QubicServer: socket() failed (errno={})", errno);
                return false;
            }

            int yes = 1;
            ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
            ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(port);

            if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
                Logger::get()->critical("QubicServer: bind() failed on port {} (errno={})", port, errno);
                ::close(listen_fd_);
                listen_fd_ = -1;
                return false;
            }

            if (::listen(listen_fd_, max_connections) < 0) {
                Logger::get()->critical("QubicServer: listen() failed (errno={})", errno);
                ::close(listen_fd_);
                listen_fd_ = -1;
                return false;
            }

            running_ = true;
            accept_thread_ = std::thread(&QubicServer::acceptLoop, this);
            cleanup_thread_ = std::thread(&QubicServer::cleanupThreadFunc, this);

            Logger::get()->info("QubicServer: listening on port {} (max {} connections, {} per IP)",
                                port, max_connections, max_per_ip);
            return true;
        }

        void stop() {
            std::lock_guard<std::mutex> lk(m_);
            if (!running_) return;
            running_ = false;

            if (listen_fd_ >= 0) {
                ::shutdown(listen_fd_, SHUT_RDWR);
                ::close(listen_fd_);
                listen_fd_ = -1;
            }

            if (accept_thread_.joinable()) {
                accept_thread_.join();
            }

            if (cleanup_thread_.joinable()) {
                cleanup_thread_.join();
            }

            // Signal all client handlers to stop
            std::vector<std::shared_ptr<ClientCtx>> local_clients;
            {
                std::lock_guard<std::mutex> lk2(clients_m_);
                local_clients = clients_;
                for (auto& c : local_clients) {
                    c->stopFlag.store(true, std::memory_order_relaxed);
                    if (c->conn) {
                        c->conn->disconnect();
                    }
                }
            }

            // Wait for all client threads to finish
            for (auto& c : local_clients) {
                if (c->th.joinable()) {
                    c->th.join();
                }
            }

            // Clear the list
            {
                std::lock_guard<std::mutex> lk2(clients_m_);
                clients_.clear();
            }

            Logger::get()->info("QubicServer: stopped");
        }

        void setConnectionPool(ConnectionPool* ptr)
        {
            pConnPool = ptr;
        }

        ConnectionPool* getConnectionPool()
        {
            return pConnPool;
        }

    private:
        struct ClientCtx {
            std::atomic_bool stopFlag{false};
            QCPtr conn;
            std::thread th;
            int fd{-1};
            std::atomic_bool finished{false};
            std::string client_ip;
            std::chrono::steady_clock::time_point connected_at;
            std::atomic<std::chrono::steady_clock::time_point> last_activity;  // Track activity
        };

        QubicServer() = default;
        ~QubicServer() { stop(); }

        void cleanupFinishedClients() {
            std::lock_guard<std::mutex> lk(clients_m_);

            size_t before = clients_.size();
            clients_.erase(
                    std::remove_if(clients_.begin(), clients_.end(),
                                   [this](const std::shared_ptr<ClientCtx>& ctx) {
                                       if (ctx->finished.load(std::memory_order_acquire)) {
                                           // Join the thread
                                           if (ctx->th.joinable()) {
                                               ctx->th.join();
                                           }
                                           // Release connection from limiter
                                           if (limiter_) {
                                               limiter_->release(ctx->client_ip);
                                           }
                                           return true;  // Remove from vector
                                       }
                                       return false;
                                   }),
                    clients_.end()
            );

            size_t after = clients_.size();
            if (before != after) {
                Logger::get()->debug("QubicServer: Cleaned up {} finished client(s), {} active",
                                     before - after, after);
            }
        }

        void cleanupThreadFunc() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                cleanupFinishedClients();
                pConnPool->removeDisconnectedClient();
            }
        }

        void acceptLoop() {
            while (running_) {
                sockaddr_in cli{};
                socklen_t len = sizeof(cli);

                // Set accept timeout for periodic cleanup
                struct timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                ::setsockopt(listen_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                int cfd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&cli), &len);
                if (cfd < 0) {
                    if (!running_) break;
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        // Timeout or interrupted - this is normal, continue
                        continue;
                    }
                    Logger::get()->warn("QubicServer: accept() failed with errno={}", errno);
                    continue;
                }

                // Get client IP address
                char client_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &cli.sin_addr, client_ip_str, INET_ADDRSTRLEN);
                std::string client_ip(client_ip_str);

                if (!limiter_->tryAccept(client_ip)) {
                    Logger::get()->warn("QubicServer: Rejecting connection from {} (limits exceeded)",
                                        client_ip);
                    ::shutdown(cfd, SHUT_RDWR);
                    ::close(cfd);
                    continue;
                }

                // Set socket options
                int one = 1;
                ::setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                ::setsockopt(cfd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

                // Create client context
                auto ctx = std::make_shared<ClientCtx>();
                ctx->fd = cfd;
                ctx->client_ip = client_ip;
                ctx->connected_at = std::chrono::steady_clock::now();

                // Create QubicConnection (this allocates memory and spawns send thread)
                try {
                    ctx->conn = make_qc_by_socket(cfd);
                    if (gAllowReceiveLogFromIncomingConnection)
                    {
                        // add to conn pool for data querying
                        pConnPool->add(ctx->conn);
                    }
                } catch (const std::exception& e) {
                    Logger::get()->error("QubicServer: Failed to create connection for {}: {}",
                                         client_ip, e.what());
                    ::close(cfd);
                    limiter_->release(client_ip);  // Release the slot
                    continue;
                }

                // Add to active clients list
                {
                    std::lock_guard<std::mutex> lk(clients_m_);
                    clients_.push_back(ctx);
                }

                Logger::get()->debug("QubicServer: Accepted connection from {} (total active: {})",
                                     client_ip, limiter_->getTotalConnections());

                // Non-trusted connections
                const bool isTrustedNode = false;

                // Launch per-connection receiver thread
                ctx->th = std::thread([this, ctx, isTrustedNode]() {
                    try {
                        ctx->conn->doHandshake();
                        // Run the main receiver loop
                        connReceiver(ctx->conn, isTrustedNode);

                    } catch (const std::exception& ex) {
                        Logger::get()->debug("QubicServer: Exception for {}: {}",
                                             ctx->client_ip, ex.what());
                    } catch (...) {
                        Logger::get()->debug("QubicServer: Unknown exception for {}", ctx->client_ip);
                    }

                    // Cleanup when receiver exits
                    if (ctx->conn) {
                        ctx->conn->disconnect();
                        ctx->conn.reset();
                    }
                    ctx->fd = -1;

                    // Mark as finished for cleanup thread
                    ctx->finished.store(true, std::memory_order_release);

                    Logger::get()->debug("QubicServer: Client {} disconnected", ctx->client_ip);
                });
            }
        }

    private:
        std::mutex m_;
        std::atomic_bool running_{false};
        int listen_fd_{-1};
        std::thread accept_thread_;
        std::thread cleanup_thread_;

        std::mutex clients_m_;
        std::vector<std::shared_ptr<ClientCtx>> clients_;

        std::unique_ptr<ConnectionLimiter> limiter_;

        ConnectionPool * pConnPool{nullptr};
    };
} // namespace

// Public helpers to control the server
bool startQubicServer(ConnectionPool* cp, uint16_t port = 21842)
{
    QubicServer::instance().setConnectionPool(cp);
    return QubicServer::instance().start(port, 64, 5);  // 64 global, 5 per IP
}

void stopQubicServer() {
    QubicServer::instance().stop();
    Logger::get()->info("Stop qubic server");
}