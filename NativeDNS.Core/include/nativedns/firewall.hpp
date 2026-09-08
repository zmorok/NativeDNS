#pragma once
#include <cstdint>

namespace nd::detail {

// Temporary, program-scoped Windows Firewall rule for the reflected TCP
// listener. The rule is removed on normal stop and replaced after a crash.
class FirewallPortRule final {
public:
    FirewallPortRule();
    ~FirewallPortRule();
    void enable(uint16_t local_port);
    void disable() noexcept;
    FirewallPortRule(const FirewallPortRule&) = delete;
    FirewallPortRule& operator=(const FirewallPortRule&) = delete;
private:
    bool com_initialized_ = false;
    bool enabled_ = false;
};

}
