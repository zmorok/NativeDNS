#include <nativedns/network.hpp>
#include <nativedns/config.hpp>
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
        check(nd::parse_numeric_endpoint("fe80::1%7").scope6 == 7, "Numeric IPv6 scope retained");
        for (const auto* bad : {"192.0.2.1%2", "fe80::1%0", "fe80::1%abc", "fe80::1%2%3"}) {
            bool rejected = false;
            try {
                (void)nd::parse_numeric_endpoint(bad);
            } catch (const nd::Error&) {
                rejected = true;
            }
            check(rejected, "Invalid scope rejected");
        }
        auto network = std::make_shared<nd::NetworkSnapshot>();
        network->generation = 10;
        nd::InterfaceInfo vpn;
        vpn.id = "{vpn}";
        vpn.name = "VPN";
        vpn.index4 = vpn.index6 = 7;
        vpn.up = true;
        vpn.dns_servers = {"192.0.2.53"};
        network->interfaces.push_back(vpn);
        auto rules = nd::default_config();
        auto bound = rules.rules.back();
        bound.id = 2;
        bound.is_default = false;
        bound.name = "Bound";
        bound.interface_id = "guid:{VPN}";
        rules.rules.insert(rules.rules.begin(), bound);
        auto decision = nd::evaluate_rule(rules, "example.com", network);
        check(decision.rule->id == 2 && decision.route.index4 == 7 && !decision.reinject_udp &&
                  decision.interface_dns.front() == "192.0.2.53",
              "Process/0 requires interface processing");
        network->interfaces.front().up = false;
        check(nd::evaluate_rule(rules, "example.com", network).error_code == "INTERFACE_DOWN",
              "Disconnected bound rule cannot use another adapter");
        rules.settings["yoga.settings.ignore_rule_if_interface_down"] = "1";
        check(nd::evaluate_rule(rules, "example.com", network).rule->is_default,
              "Ignore-down skips the bound rule");
        network->interfaces.front().up = true;
        rules.rules.front().metadata["interface_id_type"] = "name";
        rules.rules.front().metadata["interface_name"] = "vpn";
        check(nd::evaluate_rule(rules, "example.com", network).route.interface_id == "{vpn}",
              "Imported interface name resolves");
        std::cout << "Network snapshot tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
