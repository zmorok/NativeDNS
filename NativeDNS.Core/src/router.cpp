#include <nativedns/router.hpp>
#include <algorithm>
#include <iomanip>
#include <sstream>
namespace nd {
namespace {
std::string protocol_log_suffix(Protocol protocol) {
    switch(protocol) {
    case Protocol::udp:return " (UDP) (DNS over UDP)";
    case Protocol::tcp:return " (TCP) (DNS over TCP)";
    case Protocol::doh:return " (DoH) (DNS over HTTPS)";
    case Protocol::dot:return " (DoT) (DNS over TLS)";
    case Protocol::doh3:return " (DoH3) (DNS over HTTPS/3)";
    case Protocol::doq:return " (DoQ) (DNS over QUIC)";
    case Protocol::dnscrypt:return " (DNSCrypt)";
    case Protocol::anonymized_dnscrypt:return " (Anonymized DNSCrypt)";
    }
    return {};
}
}
std::string route_log_message(const Question& question,const Rule& rule,const Server* server,std::optional<double> elapsed_ms) {
    std::ostringstream output;
    output<<question.name<<" ["<<dns_type_name(question.type)<<"] - "<<action_name(rule.action)<<" : ";
    if(server) {
        const auto identity=rule.server_id&&!server->name.empty()?server->name:(!server->ip.empty()?server->ip:server->name);
        output<<"server="<<identity<<protocol_log_suffix(server->protocol)<<", ";
    }
    output<<"rule="<<rule.name;
    if(elapsed_ms)output<<", time="<<std::fixed<<std::setprecision(2)<<*elapsed_ms<<" ms";
    return output.str();
}
Router::Router(Config config, Logger& logger) : config_(std::move(config)), logger_(logger) { validate(config_); }
Packet Router::exchange(const Packet& request,const Server& server) const {
    const auto index=static_cast<size_t>(server.protocol);
    if(index>=transports_.size()) throw Error("PROTOCOL","Invalid DNS transport");
    std::call_once(transport_once_[index],[this,index,&server]{transports_[index]=make_transport(server.protocol);});
    return transports_[index]->exchange(request,server);
}
RouteResult Router::route(const Packet& request, const Server& original) const {
    RouteResult result;
    Question question;
    bool valid_question = false;
    const Rule* matched_rule=nullptr;
    const Server* selected_server=nullptr;
    auto exchange_started=std::chrono::steady_clock::time_point{};
    try {
        question = parse_question(request);
        if (question.flags & 0x8000) throw Error("DNS_MALFORMED","Cannot route a reply as a query");
        valid_question = true;
        const auto& rule = match_rule(config_,question.name);
        matched_rule=&rule;
        result.rule_id = rule.id; result.server_id = rule.server_id; result.action = rule.action;
        if (!rule.interface_id.empty() || rule.dnssec_validate || rule.dnssec_reject_unsigned)
            throw Error("NOT_IMPLEMENTED","Selected rule requires interface binding or local DNSSEC validation");
        if (rule.action == Action::bypass) {
            logger_.write(Level::normal,"DNS_ROUTE",route_log_message(question,rule,&original));
            result.disposition = Disposition::forward_original; result.packet = request; return result;
        }
        if (rule.action == Action::block) {
            logger_.write(Level::normal,"DNS_ROUTE",route_log_message(question,rule,nullptr));
            if (rule.block_mode == BlockMode::silent_drop) { result.disposition = Disposition::silent_drop; return result; }
            result.packet=make_block_response(request,rule.block_mode);return result;
        }
        const Server* server = &original;
        if (rule.server_id) {
            const auto it = std::find_if(config_.servers.begin(),config_.servers.end(),[&](const Server& s) { return s.id == rule.server_id; });
            if (it == config_.servers.end()) throw Error("SERVER_REFERENCE","Missing selected server");
            server = &*it;
        }
        selected_server=server;
        logger_.write(Level::verbose,"DNS_UPSTREAM","name="+question.name+" server="+server->name+" protocol="+protocol_name(server->protocol)+" address="+server->ip+" port="+std::to_string(server->port));
        exchange_started=std::chrono::steady_clock::now();
        result.packet = exchange(request,*server);
        const auto parsed = parse_response(result.packet,question);
        const auto elapsed=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-exchange_started).count();
        if (parsed.rcode) {
            result.error_code = "DNS_RCODE"; result.message = "Upstream returned RCODE " + std::to_string(parsed.rcode);
            logger_.write(Level::errors_only,result.error_code,route_log_message(question,rule,server,elapsed)+", error="+result.message);
        } else {
            logger_.write(Level::normal,"DNS_ROUTE",route_log_message(question,rule,server,elapsed));
            logger_.write(Level::debug,"DNS_REPLY_DETAIL",question.name+" bytes="+std::to_string(result.packet.size())+" addresses="+std::to_string(parsed.addresses.size()));
        }
    } catch (const Error& error) {
        result.error_code = error.code; result.message = error.what();
        if(valid_question&&matched_rule) {
            const auto elapsed=exchange_started==std::chrono::steady_clock::time_point{}?std::optional<double>{}:std::optional<double>{std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-exchange_started).count()};
            logger_.write(Level::errors_only,error.code,route_log_message(question,*matched_rule,selected_server,elapsed)+", error="+error.what());
        } else logger_.write(Level::errors_only,error.code,question.name + " " + error.what());
        if (valid_question) result.packet = make_error_response(request,2);
        else result.disposition = Disposition::silent_drop;
    } catch (const std::exception& error) {
        result.error_code = "INTERNAL"; result.message = error.what();
        if(valid_question&&matched_rule) {
            const auto elapsed=exchange_started==std::chrono::steady_clock::time_point{}?std::optional<double>{}:std::optional<double>{std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-exchange_started).count()};
            logger_.write(Level::errors_only,result.error_code,route_log_message(question,*matched_rule,selected_server,elapsed)+", error="+error.what());
        } else logger_.write(Level::errors_only,result.error_code,result.message);
        if (valid_question) result.packet = make_error_response(request,2);
        else result.disposition = Disposition::silent_drop;
    }
    return result;
}
}
