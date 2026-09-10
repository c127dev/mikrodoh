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

    std::unique_ptr<Transfer> transfer(const std::vector<std::uint8_t>& payload) {
        auto t     = std::make_unique<Transfer>();
        t->payload = payload;
        t->udp_fd  = fds[1];
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
