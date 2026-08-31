#include "tcp_conn.h"

#include <cerrno>

#include <sys/socket.h>
#include <unistd.h>

namespace {

// Reclaim the consumed prefix once it dominates the buffer, so a long-lived
// pipelining connection does not grow without bound.
constexpr std::size_t kCompactThreshold = 4096;

}  // namespace

TcpConn::TcpConn(int fd) : fd_(fd) {}

TcpConn::~TcpConn() {
    if (fd_ >= 0) close(fd_);
}

void TcpConn::send_message(const std::uint8_t* data, std::size_t len) {
    if (len > 0xFFFF) return;

    std::lock_guard<std::mutex> lock(mutex_);
    if (failed_) return;

    out_.push_back(static_cast<std::uint8_t>(len >> 8));
    out_.push_back(static_cast<std::uint8_t>(len & 0xFF));
    out_.insert(out_.end(), data, data + len);

    write_locked();
}

bool TcpConn::write_locked() {
    while (out_pos_ < out_.size()) {
        ssize_t n = send(fd_, out_.data() + out_pos_, out_.size() - out_pos_, MSG_NOSIGNAL);
        if (n > 0) {
            out_pos_ += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return true;
        if (n < 0 && errno == EINTR) continue;
        failed_ = true;
        return false;
    }

    out_.clear();
    out_pos_ = 0;
    return true;
}

bool TcpConn::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (failed_) return false;
    if (out_pos_ >= out_.size()) return true;

    bool ok = write_locked();

    if (out_pos_ > kCompactThreshold) {
        out_.erase(out_.begin(), out_.begin() + static_cast<std::ptrdiff_t>(out_pos_));
        out_pos_ = 0;
    }

    return ok;
}

bool TcpConn::want_write() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !failed_ && out_pos_ < out_.size();
}

bool TcpConn::failed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return failed_;
}

void TcpConn::mark_failed() {
    std::lock_guard<std::mutex> lock(mutex_);
    failed_ = true;
}
