#include "harness.h"

#include "cache.h"
#include "dispatch.h"
#include "dns.h"
#include "doh_worker.h"
#include "tcp_conn.h"

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

// The shed path returns before it ever touches a worker, so the tests link
// stubs instead of the curl event loop.
DohWorker::DohWorker(const Config& cfg, DnsCache& cache, Stats& stats)
    : cfg_(cfg), cache_(cache), stats_(stats) {}
DohWorker::~DohWorker() = default;
void DohWorker::submit(Transfer* t) { delete t; }

namespace {

std::vector<std::uint8_t> query(const std::string& name) {
    std::vector<std::uint8_t> q{0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    std::size_t label = 0;
    for (std::size_t i = 0; i <= name.size(); ++i) {
        if (i == name.size() || name[i] == '.') {
            q.push_back(static_cast<std::uint8_t>(i - label));
            for (std::size_t j = label; j < i; ++j)
                q.push_back(static_cast<std::uint8_t>(name[j]));
            label = i + 1;
        }
    }

    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x01);  // QTYPE A
    q.push_back(0x00);
    q.push_back(0x01);  // QCLASS IN
    return q;
}

// One end stands in for the client socket, the other is what the dispatcher
// answers on.
struct Pair {
    int fds[2] = {-1, -1};

    Pair() { socketpair(AF_UNIX, SOCK_DGRAM, 0, fds); }
    ~Pair() {
        for (int fd : fds)
            if (fd >= 0) close(fd);
    }

    std::unique_ptr<Transfer> transfer(const std::vector<std::uint8_t>& payload,
                                       const char* client = "10.0.0.1") {
        auto t     = std::make_unique<Transfer>();
        t->payload = payload;
        t->udp_fd  = fds[1];

        // The address is what the rate limiter keys on. `addr_len` stays zero:
        // the reply goes down a socketpair, which takes no destination.
        auto& in4      = reinterpret_cast<sockaddr_in&>(t->client_addr);
        in4.sin_family = AF_INET;
        inet_pton(AF_INET, client, &in4.sin_addr);
        return t;
    }

    // Bytes waiting on the client end, empty when the query was answered with
    // silence.
    std::vector<std::uint8_t> received() {
        std::vector<std::uint8_t> buf(dns::kMaxMessage);
        ssize_t                   n = recv(fds[0], buf.data(), buf.size(), MSG_DONTWAIT);
        if (n <= 0) return {};
        buf.resize(static_cast<std::size_t>(n));
        return buf;
    }
};

struct Fixture {
    Config                                  cfg;
    DnsCache                                cache{0};
    Stats                                   stats;
    std::vector<std::unique_ptr<DohWorker>> workers;
    Dispatcher                              dispatcher{cfg, cache, stats, workers};
};

}  // namespace

TEST(a_shed_query_is_answered_with_servfail) {
    Fixture f;
    f.cfg.max_inflight = 4;
    f.stats.inflight   = f.cfg.max_inflight;

    Pair                      p;
    std::vector<std::uint8_t> q = query("example.com");
    f.dispatcher.dispatch(p.transfer(q));

    std::vector<std::uint8_t> r = p.received();
    CHECK(r.size() == q.size());
    CHECK(r[0] == q[0] && r[1] == q[1]);          // the client's transaction ID
    CHECK((r[2] & 0x80) != 0);                    // QR
    CHECK(dns::rcode(r.data(), r.size()) == dns::kRcodeServFail);
    CHECK(r[4] == 0 && r[5] == 1);                // the question is echoed
    CHECK(std::memcmp(r.data() + dns::kHeaderLen, q.data() + dns::kHeaderLen,
                      q.size() - dns::kHeaderLen) == 0);

    CHECK(f.stats.dropped.load() == 1);
    CHECK(f.stats.inflight.load() == f.cfg.max_inflight);  // no slot was taken
}

TEST(a_shed_query_over_tcp_is_answered_with_a_length_prefix) {
    Fixture f;
    f.cfg.max_inflight = 1;
    f.stats.inflight   = 1;

    Pair p;
    auto conn = std::make_shared<TcpConn>(p.fds[1]);
    p.fds[1]  = -1;  // TcpConn closes it

    std::vector<std::uint8_t> q = query("example.com");
    auto                      t = p.transfer(q);
    t->udp_fd                   = -1;
    t->conn                     = conn;
    f.dispatcher.dispatch(std::move(t));

    conn->flush();

    std::vector<std::uint8_t> r = p.received();
    CHECK(r.size() == q.size() + 2);
    CHECK((r[0] << 8 | r[1]) == static_cast<int>(q.size()));
    CHECK(dns::rcode(r.data() + 2, r.size() - 2) == dns::kRcodeServFail);
}

TEST(a_query_under_the_cap_is_not_shed) {
    Fixture f;
    f.cfg.max_inflight = 4;
    f.stats.inflight   = 3;
    f.workers.push_back(std::make_unique<DohWorker>(f.cfg, f.cache, f.stats));

    Pair p;
    f.dispatcher.dispatch(p.transfer(query("example.com")));

    CHECK(p.received().empty());  // the answer comes from the worker, not here
    CHECK(f.stats.dropped.load() == 0);
    CHECK(f.stats.inflight.load() == 4);
}

TEST(a_query_over_the_client_rate_is_answered_with_servfail) {
    // The limiter is built with the dispatcher, so the rate has to be set
    // before the fixture is constructed.
    Config cfg;
    cfg.rate_limit_qps   = 1;
    cfg.rate_limit_burst = 1;

    DnsCache                                cache{0};
    Stats                                   stats;
    std::vector<std::unique_ptr<DohWorker>> workers;
    workers.push_back(std::make_unique<DohWorker>(cfg, cache, stats));
    Dispatcher dispatcher{cfg, cache, stats, workers};

    Pair                      p;
    std::vector<std::uint8_t> q = query("example.com");

    dispatcher.dispatch(p.transfer(q));
    CHECK(p.received().empty());  // the first one goes to the worker
    CHECK(stats.throttled.load() == 0);

    dispatcher.dispatch(p.transfer(q));

    std::vector<std::uint8_t> r = p.received();
    CHECK(r.size() == q.size());
    CHECK(r[0] == q[0] && r[1] == q[1]);
    CHECK(dns::rcode(r.data(), r.size()) == dns::kRcodeServFail);
    CHECK(stats.throttled.load() == 1);
    CHECK(stats.inflight.load() == 1);  // the throttled query took no slot
}

TEST(one_throttled_client_does_not_throttle_another) {
    Config cfg;
    cfg.rate_limit_qps       = 1;
    cfg.rate_limit_burst     = 1;
    cfg.rate_limit_v4_prefix = 32;

    DnsCache                                cache{0};
    Stats                                   stats;
    std::vector<std::unique_ptr<DohWorker>> workers;
    workers.push_back(std::make_unique<DohWorker>(cfg, cache, stats));
    Dispatcher dispatcher{cfg, cache, stats, workers};

    std::vector<std::uint8_t> q = query("example.com");

    Pair loud;
    dispatcher.dispatch(loud.transfer(q, "10.0.0.1"));
    dispatcher.dispatch(loud.transfer(q, "10.0.0.1"));
    CHECK(!loud.received().empty());  // second one was refused

    Pair quiet;
    dispatcher.dispatch(quiet.transfer(q, "10.0.0.2"));
    CHECK(quiet.received().empty());
    CHECK(stats.throttled.load() == 1);
}

TEST(a_cache_hit_is_charged_to_the_client_rate) {
    // Answering from cache still puts a packet on the wire, so it has to cost
    // a token: otherwise a source picks one name and floods with it for free.
    Config cfg;
    cfg.rate_limit_qps   = 1;
    cfg.rate_limit_burst = 1;
    cfg.cache_ttl        = 60;

    DnsCache                                cache{cfg.cache_ttl};
    Stats                                   stats;
    std::vector<std::unique_ptr<DohWorker>> workers;
    Dispatcher dispatcher{cfg, cache, stats, workers};

    std::vector<std::uint8_t> q = query("example.com");

    std::vector<std::uint8_t> answer = q;
    answer[2] |= 0x80;
    cache.store(DnsCache::key_of(q.data(), q.size()), answer);

    Pair p;
    dispatcher.dispatch(p.transfer(q));
    CHECK(!p.received().empty());
    CHECK(stats.cache_hits.load() == 1);

    dispatcher.dispatch(p.transfer(q));
    std::vector<std::uint8_t> r = p.received();
    CHECK(dns::rcode(r.data(), r.size()) == dns::kRcodeServFail);
    CHECK(stats.cache_hits.load() == 1);
    CHECK(stats.throttled.load() == 1);
}

TEST(a_malformed_query_is_rejected_in_silence) {
    Fixture f;
    f.cfg.max_inflight = 1;
    f.stats.inflight   = 1;

    Pair                      p;
    std::vector<std::uint8_t> q{0x12, 0x34, 0x01};
    f.dispatcher.dispatch(p.transfer(q));

    CHECK(p.received().empty());
    CHECK(f.stats.rejected.load() == 1);
    CHECK(f.stats.dropped.load() == 0);
}
