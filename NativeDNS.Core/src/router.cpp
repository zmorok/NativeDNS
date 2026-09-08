#include <nativedns/router.hpp>
#include <algorithm>
namespace nd {
namespace {
Packet answer(const Packet& request, const Question& q, uint16_t rcode, bool zero) {
    Packet result(request.begin(),request.begin() + static_cast<ptrdiff_t>(q.end));
    result[2] = static_cast<uint8_t>(0x80 | ((q.flags >> 8) & 1));
    result[3] = static_cast<uint8_t>(0x80 | (q.flags & 0x10) | rcode);
    for (size_t i = 6; i < 12; ++i) result[i] = 0;
    if (zero && q.klass == 1 && (q.type == 1 || q.type == 28)) {
        result[7] = 1;
        const uint8_t length = q.type == 1 ? 4 : 16;
        const Packet record{0xc0,0x0c,0,static_cast<uint8_t>(q.type),0,1,0,0,0,0,0,length};
        result.insert(result.end(),record.begin(),record.end()); result.insert(result.end(),length,0);
    }
    return result;
}
}
Router::Router(Config config, Logger& logger) : config_(std::move(config)), logger_(logger) { validate(config_); }
RouteResult Router::route(const Packet& request, const Server& original) const {
    RouteResult result;
    Question question;
    bool valid_question = false;
    try {
        question = parse_question(request);
        if (question.flags & 0x8000) throw Error("DNS_MALFORMED","Cannot route a reply as a query");
        valid_question = true;
        const auto& rule = match_rule(config_,question.name);
        result.rule_id = rule.id; result.server_id = rule.server_id; result.action = rule.action;
        logger_.write(Level::normal,"DNS_ROUTE",question.name + " rule=" + rule.name + " action=" + action_name(rule.action) + " server=" + std::to_string(rule.server_id));
        if (!rule.interface_id.empty() || rule.dnssec_validate || rule.dnssec_reject_unsigned)
            throw Error("NOT_IMPLEMENTED","Selected rule requires interface binding or local DNSSEC validation");
        if (rule.action == Action::bypass) {
            result.disposition = Disposition::forward_original; result.packet = request; return result;
        }
        if (rule.action == Action::block) {
            if (rule.block_mode == BlockMode::silent_drop) { result.disposition = Disposition::silent_drop; return result; }
            const uint16_t rcode = rule.block_mode == BlockMode::nxdomain ? 3 : rule.block_mode == BlockMode::refused ? 5 : 0;
            result.packet = answer(request,question,rcode,rule.block_mode == BlockMode::zero_address); return result;
        }
        const Server* server = &original;
        if (rule.server_id) {
            const auto it = std::find_if(config_.servers.begin(),config_.servers.end(),[&](const Server& s) { return s.id == rule.server_id; });
            if (it == config_.servers.end()) throw Error("SERVER_REFERENCE","Missing selected server");
            server = &*it;
        }
        const auto start = std::chrono::steady_clock::now();
        result.packet = make_transport(server->protocol)->exchange(request,*server);
        const auto parsed = parse_response(result.packet,question);
        if (parsed.rcode) {
            result.error_code = "DNS_RCODE"; result.message = "Upstream returned RCODE " + std::to_string(parsed.rcode);
            logger_.write(Level::errors_only,result.error_code,question.name + " " + result.message);
        } else logger_.write(Level::normal,"DNS_REPLY",question.name + " protocol=" + protocol_name(server->protocol) + " elapsed_ms=" +
            std::to_string(std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now() - start).count()));
    } catch (const Error& error) {
        result.error_code = error.code; result.message = error.what();
        logger_.write(Level::errors_only,error.code,question.name + " " + error.what());
        if (valid_question) result.packet = answer(request,question,2,false);
        else result.disposition = Disposition::silent_drop;
    } catch (const std::exception& error) {
        result.error_code = "INTERNAL"; result.message = error.what();
        logger_.write(Level::errors_only,result.error_code,result.message);
        if (valid_question) result.packet = answer(request,question,2,false);
        else result.disposition = Disposition::silent_drop;
    }
    return result;
}
}
