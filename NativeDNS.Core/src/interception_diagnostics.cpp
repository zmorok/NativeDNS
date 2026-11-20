#include <nativedns/interception.hpp>
#include <sstream>

namespace nd {
std::string format_interception_test(const InterceptionTestResult& v) {
    std::ostringstream out;
    out << "probe_transport=UDP/IPv4\nprobe_in_progress=" << v.in_progress
        << "\nprobe_timestamp_ms=" << v.timestamp_ms
        << "\nprobe_interface_index=" << v.interface_index << "\nprobe_sent=" << v.sent
        << "\nprobe_captured=" << v.captured << "\nprobe_parsed=" << v.parsed
        << "\nprobe_injected=" << v.injected << "\nprobe_received=" << v.received
        << "\nprobe_success=" << v.success() << "\nprobe_failure_stage=" << v.failure_stage
        << "\nprobe_message=" << v.message << '\n';
    return out.str();
}
std::string format_interception_diagnostics(const InterceptionDiagnostics& v) {
    std::ostringstream out;
    out << "diagnostic_version=1\ninterception_supported=" << v.supported
        << "\ninterception_health=" << v.health << "\nlibrary_loaded=" << v.library_loaded
        << "\nhandle_open=" << v.handle_open << "\nreceiver_active=" << v.receiver_active
        << "\nwindivert_priority=" << v.priority << "\nwindivert_filter=" << v.filter << '\n';
#define ND_COUNTER(name) out << #name "=" << v.name << '\n'
    ND_COUNTER(packets_received);
    ND_COUNTER(udp_dns_captured);
    ND_COUNTER(tcp_dns_captured);
    ND_COUNTER(dns_parse_errors);
    ND_COUNTER(rules_evaluated);
    ND_COUNTER(queries_processed);
    ND_COUNTER(queries_bypassed);
    ND_COUNTER(queries_blocked);
    ND_COUNTER(upstream_bypassed);
    ND_COUNTER(packets_injected);
    ND_COUNTER(send_errors);
    ND_COUNTER(receive_errors);
    ND_COUNTER(worker_queue_overflows);
    ND_COUNTER(processing_errors);
    ND_COUNTER(negative_replies);
    ND_COUNTER(upstream_error_rcodes);
    ND_COUNTER(last_capture_timestamp);
    ND_COUNTER(active_workers);
    ND_COUNTER(queued_jobs);
    ND_COUNTER(queued_bytes);
    ND_COUNTER(upstream_attempts);
    ND_COUNTER(upstream_replies);
    ND_COUNTER(upstream_errors);
#undef ND_COUNTER
    out << format_interception_test(v.last_test);
    return out.str();
}
} // namespace nd
