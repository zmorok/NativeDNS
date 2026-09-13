#include <nativedns/router.hpp>
#include <algorithm>
#include <functional>
#include <iomanip>
#include <set>
#include <sstream>
namespace nd {
namespace {
std::string protocol_log_suffix(Protocol protocol) {
    switch (protocol) {
        case Protocol::udp:
            return " (UDP) (DNS over UDP)";
        case Protocol::tcp:
            return " (TCP) (DNS over TCP)";
        case Protocol::doh:
            return " (DoH) (DNS over HTTPS)";
        case Protocol::dot:
            return " (DoT) (DNS over TLS)";
        case Protocol::doh3:
            return " (DoH3) (DNS over HTTPS/3)";
        case Protocol::doq:
            return " (DoQ) (DNS over QUIC)";
        case Protocol::dnscrypt:
            return " (DNSCrypt)";
        case Protocol::anonymized_dnscrypt:
            return " (Anonymized DNSCrypt)";
    }
    return {};
}
} // namespace
std::string route_log_message(const Question& question,
                              const Rule& rule,
                              const Server* server,
                              std::optional<double> elapsed_ms) {
    std::ostringstream output;
    output << question.name << " [" << dns_type_name(question.type) << "] - "
           << action_name(rule.action) << " : ";
    if (server) {
        const auto identity = rule.server_id && !server->name.empty()
                                  ? server->name
                                  : (!server->ip.empty() ? server->ip : server->name);
        output << "server=" << identity << protocol_log_suffix(server->protocol) << ", ";
    }
    output << "rule=" << rule.name;
    if (elapsed_ms)
        output << ", time=" << std::fixed << std::setprecision(2) << *elapsed_ms << " ms";
    return output.str();
}
Router::Router(Config config, Logger& logger) : config_(std::move(config)), logger_(logger) {
    validate(config_);
}
Packet Router::exchange(const Packet& request, const Server& server) const {
    const auto index = static_cast<size_t>(server.protocol);
    if (index >= transports_.size())
        throw Error("PROTOCOL", "Invalid DNS transport");
    std::call_once(transport_once_[index], [this, index, &server] {
        transports_[index] = make_transport(server.protocol);
    });
    return transports_[index]->exchange(request, server);
}
std::pair<Packet, const Server*> Router::exchange_group(const Packet& request,
                                                        const Server& primary) const {
    if (!primary.id || primary.fallback_ids.empty())
        return {exchange(request, primary), &primary};
    std::vector<const Server*> candidates;
    std::set<uint32_t> added;
    std::function<void(const Server&)> append = [&](const Server& server) {
        if (!added.insert(server.id).second)
            return;
        candidates.push_back(&server);
        for (const auto id : server.fallback_ids) {
            const auto found = std::find_if(config_.servers.begin(),
                                            config_.servers.end(),
                                            [&](const Server& value) { return value.id == id; });
            if (found != config_.servers.end())
                append(*found);
        }
    };
    append(primary);
    std::erase_if(candidates, [](const Server* server) { return !server->enabled; });
    if (candidates.empty())
        throw Error("SERVER_DISABLED", "All servers in fallback group are disabled");
    const auto started = std::chrono::steady_clock::now();
    uint64_t budget_ms = 0;
    for (const auto* server : candidates)
        budget_ms = std::min<uint64_t>(120000, budget_ms + server->timeout_ms);
    const auto deadline = started + std::chrono::milliseconds(budget_ms);
    {
        std::lock_guard lock(health_mutex_);
        const auto now = std::chrono::steady_clock::now();
        for (const auto* candidate : candidates)
            health_.try_emplace(candidate->id);
        const bool any_ready =
            std::any_of(candidates.begin(), candidates.end(), [&](const Server* server) {
                return health_.at(server->id).retry_after <= now;
            });
        std::stable_sort(
            candidates.begin(), candidates.end(), [&](const Server* left, const Server* right) {
                const auto& a = health_.at(left->id);
                const auto& b = health_.at(right->id);
                const bool a_open = any_ready && a.retry_after > now,
                           b_open = any_ready && b.retry_after > now;
                if (a_open != b_open)
                    return !a_open;
                const bool a_probe = a.consecutive_failures >= 2 && a.retry_after <= now,
                           b_probe = b.consecutive_failures >= 2 && b.retry_after <= now;
                if (a_probe != b_probe)
                    return a_probe;
                if (a.latency_ms && b.latency_ms)
                    return *a.latency_ms < *b.latency_ms;
                return false;
            });
    }
    std::string last_code = "UPSTREAM_UNAVAILABLE", last_message = "No upstream attempt completed";
    for (const auto* candidate : candidates) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            break;
        {
            std::lock_guard lock(health_mutex_);
            const bool another_ready =
                std::any_of(candidates.begin(), candidates.end(), [&](const Server* server) {
                    return server != candidate && health_[server->id].retry_after <= now;
                });
            if (health_[candidate->id].retry_after > now && another_ready)
                continue;
        }
        auto attempt = *candidate;
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        attempt.timeout_ms = static_cast<uint32_t>(
            std::min<int64_t>(attempt.timeout_ms, std::max<int64_t>(1, remaining)));
        const auto attempt_started = std::chrono::steady_clock::now();
        try {
            auto packet = exchange(request, attempt);
            const double elapsed = std::chrono::duration<double, std::milli>(
                                       std::chrono::steady_clock::now() - attempt_started)
                                       .count();
            {
                std::lock_guard lock(health_mutex_);
                auto& state = health_[candidate->id];
                state.consecutive_failures = 0;
                state.retry_after = {};
                state.latency_ms =
                    state.latency_ms ? (*state.latency_ms * 0.8 + elapsed * 0.2) : elapsed;
            }
            return {std::move(packet), candidate};
        } catch (const Error& error) {
            last_code = error.code;
            last_message = error.what();
            unsigned failures = 0;
            {
                std::lock_guard lock(health_mutex_);
                auto& state = health_[candidate->id];
                failures = ++state.consecutive_failures;
                if (failures >= 2) {
                    const auto shift = std::min(failures - 2, 3u);
                    state.retry_after =
                        std::chrono::steady_clock::now() + std::chrono::seconds(30u << shift);
                }
            }
            if (logger_.enabled(Level::verbose))
                logger_.write(Level::verbose,
                              "UPSTREAM_FAILOVER",
                              "server=" + candidate->name + " failure=" + last_code +
                                  " consecutive=" + std::to_string(failures));
        }
    }
    throw Error(last_code, "Fallback group exhausted: " + last_message);
}
std::pair<Packet, uint32_t>
Router::exchange_cached(const Packet& request, const Server& primary, bool configured) const {
    if (request.size() < 2)
        throw Error("DNS_MALFORMED", "DNS request is too short");
    std::string key;
    key.reserve(request.size() + 96);
    key += configured ? "configured:" : "original:";
    key += std::to_string(configured ? primary.id : static_cast<uint32_t>(primary.protocol));
    key += '|';
    if (!configured)
        key += primary.ip + '|' + std::to_string(primary.port) + '|';
    key.append(2, '\0');
    key.append(reinterpret_cast<const char*>(request.data() + 2), request.size() - 2);
    const uint16_t transaction_id = static_cast<uint16_t>((request[0] << 8) | request[1]);
    std::shared_ptr<Pending> pending;
    bool leader = false;
    {
        std::unique_lock lock(cache_mutex_);
        const auto now = std::chrono::steady_clock::now();
        for (auto entry = cache_.begin(); entry != cache_.end();)
            entry = entry->second.expires <= now ? cache_.erase(entry) : std::next(entry);
        if (const auto found = cache_.find(key); found != cache_.end()) {
            const auto elapsed = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::seconds>(now - found->second.stored)
                    .count());
            if (logger_.enabled(Level::debug))
                logger_.write(Level::debug, "DNS_CACHE_HIT", "server=" + primary.name);
            return {age_dns_response(found->second.packet, transaction_id, elapsed),
                    found->second.used_server_id};
        }
        const auto found = pending_.find(key);
        if (found != pending_.end())
            pending = found->second;
        else {
            pending = std::make_shared<Pending>();
            pending_.emplace(key, pending);
            leader = true;
        }
        if (!leader) {
            if (logger_.enabled(Level::debug))
                logger_.write(Level::debug, "DNS_COALESCED", "server=" + primary.name);
            pending->changed.wait(lock, [&] { return pending->done; });
            if (!pending->error_code.empty())
                throw Error(pending->error_code, pending->error_message);
            return {age_dns_response(pending->packet, transaction_id, 0), pending->used_server_id};
        }
    }
    try {
        auto exchanged = exchange_group(request, primary);
        const auto parsed = parse_response(exchanged.first, parse_question(request));
        const uint32_t used_id = configured ? exchanged.second->id : 0;
        {
            std::lock_guard lock(cache_mutex_);
            const auto now = std::chrono::steady_clock::now();
            if (parsed.cacheable) {
                if (cache_.size() >= 4096) {
                    const auto oldest = std::min_element(
                        cache_.begin(), cache_.end(), [](const auto& left, const auto& right) {
                            return left.second.expires < right.second.expires;
                        });
                    if (oldest != cache_.end())
                        cache_.erase(oldest);
                }
                const auto ttl = std::min<uint32_t>(parsed.cache_ttl, 86400);
                cache_[key] = {exchanged.first, now, now + std::chrono::seconds(ttl), used_id};
            }
            pending->packet = exchanged.first;
            pending->used_server_id = used_id;
            pending->done = true;
            pending_.erase(key);
        }
        pending->changed.notify_all();
        return {std::move(exchanged.first), used_id};
    } catch (const Error& error) {
        {
            std::lock_guard lock(cache_mutex_);
            pending->error_code = error.code;
            pending->error_message = error.what();
            pending->done = true;
            pending_.erase(key);
        }
        pending->changed.notify_all();
        throw;
    } catch (const std::exception& error) {
        {
            std::lock_guard lock(cache_mutex_);
            pending->error_code = "INTERNAL";
            pending->error_message = error.what();
            pending->done = true;
            pending_.erase(key);
        }
        pending->changed.notify_all();
        throw;
    }
}
RouteResult Router::route(const Packet& request, const Server& original) const {
    RouteResult result;
    Question question;
    bool valid_question = false;
    const Rule* matched_rule = nullptr;
    const Server* selected_server = nullptr;
    auto exchange_started = std::chrono::steady_clock::time_point{};
    try {
        question = parse_question(request);
        if (question.flags & 0x8000)
            throw Error("DNS_MALFORMED", "Cannot route a reply as a query");
        valid_question = true;
        const auto& rule = match_rule(config_, question.name);
        matched_rule = &rule;
        result.rule_id = rule.id;
        result.server_id = rule.server_id;
        result.action = rule.action;
        if (!rule.interface_id.empty() || rule.dnssec_validate || rule.dnssec_reject_unsigned)
            throw Error("NOT_IMPLEMENTED",
                        "Selected rule requires interface binding or local DNSSEC validation");
        if (rule.action == Action::bypass) {
            if (logger_.enabled(Level::normal))
                logger_.write(
                    Level::normal, "DNS_ROUTE", route_log_message(question, rule, &original));
            result.disposition = Disposition::forward_original;
            result.packet = request;
            return result;
        }
        if (rule.action == Action::block) {
            if (logger_.enabled(Level::normal))
                logger_.write(
                    Level::normal, "DNS_ROUTE", route_log_message(question, rule, nullptr));
            if (rule.block_mode == BlockMode::silent_drop) {
                result.disposition = Disposition::silent_drop;
                return result;
            }
            result.packet = make_block_response(request, rule.block_mode);
            return result;
        }
        const Server* server = &original;
        if (rule.server_id) {
            const auto it = std::find_if(config_.servers.begin(),
                                         config_.servers.end(),
                                         [&](const Server& s) { return s.id == rule.server_id; });
            if (it == config_.servers.end())
                throw Error("SERVER_REFERENCE", "Missing selected server");
            server = &*it;
        }
        selected_server = server;
        if (logger_.enabled(Level::verbose))
            logger_.write(Level::verbose,
                          "DNS_UPSTREAM",
                          "name=" + question.name + " server=" + server->name +
                              " protocol=" + protocol_name(server->protocol) +
                              " address=" + server->ip + " port=" + std::to_string(server->port));
        exchange_started = std::chrono::steady_clock::now();
        auto exchanged = exchange_cached(request, *server, rule.server_id != 0);
        result.packet = std::move(exchanged.first);
        result.server_id = exchanged.second;
        if (result.server_id) {
            const auto used = std::find_if(
                config_.servers.begin(), config_.servers.end(), [&](const Server& candidate) {
                    return candidate.id == result.server_id;
                });
            if (used != config_.servers.end())
                selected_server = &*used;
        }
        const auto parsed = parse_response(result.packet, question);
        const auto elapsed = std::chrono::duration<double, std::milli>(
                                 std::chrono::steady_clock::now() - exchange_started)
                                 .count();
        if (parsed.rcode) {
            result.error_code = "DNS_RCODE";
            result.message = "Upstream returned RCODE " + std::to_string(parsed.rcode);
            logger_.write(Level::errors_only,
                          result.error_code,
                          route_log_message(question, rule, server, elapsed) +
                              ", error=" + result.message);
        } else {
            if (logger_.enabled(Level::normal))
                logger_.write(
                    Level::normal, "DNS_ROUTE", route_log_message(question, rule, server, elapsed));
            if (logger_.enabled(Level::debug))
                logger_.write(Level::debug,
                              "DNS_REPLY_DETAIL",
                              question.name + " bytes=" + std::to_string(result.packet.size()) +
                                  " addresses=" + std::to_string(parsed.addresses.size()));
        }
    } catch (const Error& error) {
        result.error_code = error.code;
        result.message = error.what();
        if (valid_question && matched_rule) {
            const auto elapsed =
                exchange_started == std::chrono::steady_clock::time_point{}
                    ? std::optional<double>{}
                    : std::optional<double>{std::chrono::duration<double, std::milli>(
                                                std::chrono::steady_clock::now() - exchange_started)
                                                .count()};
            logger_.write(Level::errors_only,
                          error.code,
                          route_log_message(question, *matched_rule, selected_server, elapsed) +
                              ", error=" + error.what());
        } else
            logger_.write(Level::errors_only, error.code, question.name + " " + error.what());
        if (valid_question)
            result.packet = make_error_response(request, 2);
        else
            result.disposition = Disposition::silent_drop;
    } catch (const std::exception& error) {
        result.error_code = "INTERNAL";
        result.message = error.what();
        if (valid_question && matched_rule) {
            const auto elapsed =
                exchange_started == std::chrono::steady_clock::time_point{}
                    ? std::optional<double>{}
                    : std::optional<double>{std::chrono::duration<double, std::milli>(
                                                std::chrono::steady_clock::now() - exchange_started)
                                                .count()};
            logger_.write(Level::errors_only,
                          result.error_code,
                          route_log_message(question, *matched_rule, selected_server, elapsed) +
                              ", error=" + error.what());
        } else
            logger_.write(Level::errors_only, result.error_code, result.message);
        if (valid_question)
            result.packet = make_error_response(request, 2);
        else
            result.disposition = Disposition::silent_drop;
    }
    return result;
}
} // namespace nd
