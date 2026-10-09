#include <nativedns/network.hpp>
#include <iostream>
#include <stdexcept>

void check(bool value, const char* message) {
    if (!value)
        throw std::runtime_error(message);
}
int main() {
    try {
        std::vector<nd::InterfaceInfo> state(2);
        state[0].id = "wifi";
        state[0].up = true;
        state[0].dns_servers = {"192.0.2.1"};
        state[1].id = "vpn";
        bool fail = false;
        nd::NetworkMonitor monitor(
            [&] {
                if (fail)
                    throw std::runtime_error("enumeration failed");
                return state;
            },
            false);
        const auto first = monitor.snapshot();
        check(first->generation == 1 && first->interfaces.front().id == "vpn", "Stable ordering");
        monitor.refresh();
        check(monitor.snapshot() == first, "Unchanged network preserves immutable snapshot");
        state[0].dns_servers = {"192.0.2.2"};
        monitor.refresh();
        check(monitor.snapshot()->generation == 2, "DHCP DNS change advances generation");
        check(first->interfaces.back().dns_servers.front() == "192.0.2.1",
              "Old snapshot immutable");
        state[0].up = false;
        monitor.refresh();
        check(monitor.snapshot()->generation == 3, "Disconnect advances generation");
        fail = true;
        monitor.refresh();
        check(!monitor.snapshot()->error.empty(), "Enumeration failure is visible");
        fail = false;
        state.erase(state.begin());
        monitor.refresh();
        check(monitor.snapshot()->error.empty() && monitor.snapshot()->interfaces.size() == 1,
              "Recovery and interface removal are published");
        const auto native = nd::platform::enumerate_interfaces();
        for (const auto& info : native)
            check(!info.id.empty(), "Native adapter has stable identifier");
        std::cout << "Network snapshot tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
