#include "harness.h"

#include "coalesce.h"
#include "transfer.h"

#include <string>

namespace {

Transfer with_key(const std::string& key) {
    Transfer t;
    t.cache_key = key;
    return t;
}

}  // namespace

TEST(the_first_query_for_a_key_is_started) {
    Coalescer c;
    Transfer  a = with_key("k");
    CHECK(!c.join(&a));
}

TEST(an_identical_query_joins_the_pending_one) {
    Coalescer c;
    Transfer  a = with_key("k");
    Transfer  b = with_key("k");
    Transfer  d = with_key("k");

    CHECK(!c.join(&a));
    CHECK(c.join(&b));
    CHECK(c.join(&d));

    std::vector<Transfer*> followers = c.release(&a);
    CHECK(followers.size() == 2);
    CHECK(followers[0] == &b);
    CHECK(followers[1] == &d);
}

TEST(different_keys_are_not_coalesced) {
    Coalescer c;
    Transfer  a = with_key("k1");
    Transfer  b = with_key("k2");

    CHECK(!c.join(&a));
    CHECK(!c.join(&b));
    CHECK(c.release(&a).empty());
    CHECK(c.release(&b).empty());
}

TEST(an_empty_key_is_never_coalesced) {
    Coalescer c;
    Transfer  a = with_key("");
    Transfer  b = with_key("");

    CHECK(!c.join(&a));
    CHECK(!c.join(&b));
}

TEST(release_ends_the_pending_query) {
    Coalescer c;
    Transfer  a = with_key("k");
    Transfer  b = with_key("k");

    CHECK(!c.join(&a));
    c.release(&a);
    CHECK(!c.join(&b));
}

TEST(release_by_a_follower_returns_nothing) {
    Coalescer c;
    Transfer  a = with_key("k");
    Transfer  b = with_key("k");

    CHECK(!c.join(&a));
    CHECK(c.join(&b));
    CHECK(c.release(&b).empty());
    CHECK(c.release(&a).size() == 1);
}
