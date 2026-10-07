#include "log_filter.hpp"
#include "ui_preferences.hpp"
#include <nativedns/dns.hpp>
#include <QRegularExpression>
#include <stdexcept>

struct LogFilter::Node {
    enum class Kind { predicate, conjunction, disjunction, negation } kind = Kind::predicate;
    QString field, value;
    QRegularExpression pattern;
    bool wildcard = false;
    std::shared_ptr<const Node> left, right;
    bool matches(const LogRecord& record) const {
        if (kind == Kind::conjunction)
            return left->matches(record) && right->matches(record);
        if (kind == Kind::disjunction)
            return left->matches(record) || right->matches(record);
        if (kind == Kind::negation)
            return !left->matches(record);
        if (field == "err") {
            if (!record.error)
                return false;
            if (value.isEmpty() || value == "*")
                return true;
            const auto text = record.code + ' ' + record.message;
            return wildcard ? pattern.match(text).hasMatch()
                            : text.contains(value, Qt::CaseInsensitive);
        }
        const auto text = field == "addr"       ? record.address
                          : field == "dns_type" ? record.dnsType
                          : field == "rule"     ? record.rule
                                                : record.action;
        if (text.isEmpty())
            return false;
        return wildcard ? pattern.match(text).hasMatch()
                        : text.compare(value, Qt::CaseInsensitive) == 0;
    }
};

namespace {
class Parser {
public:
    explicit Parser(const QString& expression) : text_(expression) {
    }
    std::shared_ptr<const LogFilter::Node> parse() {
        if (text_.size() > 4096)
            fail("Filter is too long (maximum 4096 characters).");
        skip();
        if (position_ == text_.size())
            return {};
        auto result = disjunction(0);
        skip();
        if (position_ != text_.size())
            fail("Expected && or || between conditions.");
        return result;
    }

private:
    using Node = LogFilter::Node;
    [[noreturn]] void fail(const char* message) const {
        throw std::runtime_error(
            (uiText(message) + ' ' + uiText("At character %1.").arg(position_ + 1))
                .toUtf8()
                .constData());
    }
    void skip() {
        while (position_ < text_.size() && text_[position_].isSpace())
            ++position_;
    }
    bool consume(const QString& token) {
        skip();
        if (text_.mid(position_, token.size()) != token)
            return false;
        position_ += token.size();
        return true;
    }
    std::shared_ptr<const Node>
    combine(Node::Kind kind, std::shared_ptr<const Node> left, std::shared_ptr<const Node> right) {
        if (++nodes_ > 128)
            fail("Too many filter conditions (maximum 128).");
        auto result = std::make_shared<Node>();
        result->kind = kind;
        result->left = std::move(left);
        result->right = std::move(right);
        return result;
    }
    std::shared_ptr<const Node> disjunction(int depth) {
        auto result = conjunction(depth);
        while (consume("||"))
            result = combine(Node::Kind::disjunction, result, conjunction(depth));
        return result;
    }
    std::shared_ptr<const Node> conjunction(int depth) {
        auto result = primary(depth);
        while (consume("&&"))
            result = combine(Node::Kind::conjunction, result, primary(depth));
        return result;
    }
    std::shared_ptr<const Node> primary(int depth) {
        if (depth > 32)
            fail("Filter nesting is too deep (maximum 32).");
        if (consume("!"))
            return combine(Node::Kind::negation, primary(depth + 1), {});
        if (consume("(")) {
            auto result = disjunction(depth + 1);
            if (!consume(")"))
                fail("Expected a closing parenthesis.");
            return result;
        }
        skip();
        const auto start = position_;
        while (position_ < text_.size() && (text_[position_].isLetter() || text_[position_] == '_'))
            ++position_;
        auto result = std::make_shared<Node>();
        result->field = text_.mid(start, position_ - start).toLower();
        if (result->field != "addr" && result->field != "dns_type" && result->field != "rule" &&
            result->field != "err" && result->field != "action")
            fail("Unknown field. Use addr, dns_type, rule, err or action.");
        if (!consume("="))
            fail("Expected = after the field name.");
        if (!consume("\""))
            fail("Put the value in double quotes.");
        bool closed = false;
        while (position_ < text_.size()) {
            auto character = text_[position_++];
            if (character == '"') {
                closed = true;
                break;
            }
            if (character == '\\') {
                if (position_ == text_.size())
                    fail("Incomplete escape sequence.");
                character = text_[position_++];
                if (character != '"' && character != '\\')
                    fail("Only double quotes and backslashes can be escaped.");
            }
            result->value += character;
        }
        if (!closed)
            fail("Expected a closing double quote.");
        if (result->field != "err" && result->value.isEmpty())
            fail("The field value must not be empty.");
        if (result->field == "action" && result->value.compare("process", Qt::CaseInsensitive) &&
            result->value.compare("block", Qt::CaseInsensitive) &&
            result->value.compare("bypass", Qt::CaseInsensitive) && result->value != "*")
            fail("Action must be process, block or bypass.");
        if (result->field == "dns_type") {
            bool numeric = false;
            const auto type = result->value.toUInt(&numeric);
            if (numeric) {
                if (type > 65535)
                    fail("DNS type number must be 0..65535.");
                result->value =
                    QString::fromStdString(nd::dns_type_name(static_cast<uint16_t>(type)));
            }
        }
        if (result->value.contains('*') || result->value.contains('?')) {
            auto pattern = QRegularExpression::escape(result->value);
            pattern.replace("\\*", ".*").replace("\\?", ".");
            if (result->field != "err")
                pattern = "^(?:" + pattern + ")$";
            result->pattern =
                QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption);
            result->wildcard = true;
        }
        if (++nodes_ > 128)
            fail("Too many filter conditions (maximum 128).");
        return result;
    }
    const QString& text_;
    qsizetype position_ = 0;
    int nodes_ = 0;
};
} // namespace

std::optional<LogFilter> LogFilter::compile(const QString& expression, QString& error) {
    error.clear();
    try {
        LogFilter result;
        result.root_ = Parser(expression).parse();
        return result;
    } catch (const std::exception& failure) {
        error = QString::fromUtf8(failure.what());
        return {};
    }
}
bool LogFilter::matches(const LogRecord& record) const {
    return !root_ || root_->matches(record);
}

QList<LogRecord> decodeLogRecords(const QString& payload) {
    QList<LogRecord> result;
    static const QRegularExpression route("^(\\S+) \\[([^\\]]+)\\] - (process|bypass|block) : "
                                          ".*?rule=(.*?)(?:, time=[0-9.]+ ms|, error=|$)");
    for (const auto& line : payload.split('\n', Qt::SkipEmptyParts)) {
        const auto fields = line.split('\t');
        if (fields.size() < 4)
            continue;
        bool sequenceOk = false;
        LogRecord record;
        record.sequence = fields[0].toULongLong(&sequenceOk);
        if (!sequenceOk)
            continue;
        record.error = fields[1] == "0";
        int message = 3;
        if (fields.size() >= 5) {
            bool timeOk = false;
            const auto milliseconds = fields[2].toLongLong(&timeOk);
            if (timeOk) {
                record.timestamp = QDateTime::fromMSecsSinceEpoch(milliseconds);
                message = 4;
            }
        }
        if (!record.timestamp.isValid())
            record.timestamp = QDateTime::currentDateTime();
        record.code = fields[message - 1];
        record.message = fields[message];
        if (message == 4 && fields.size() == 9) {
            record.address = fields[5];
            record.dnsType = fields[6];
            record.rule = fields[7];
            record.action = fields[8];
        } else {
            record.message = fields.mid(message).join('\t');
            const auto match = route.match(record.message);
            if (match.hasMatch()) {
                record.address = match.captured(1);
                record.dnsType = match.captured(2);
                record.action = match.captured(3);
                record.rule = match.captured(4);
            }
        }
        result.push_back(std::move(record));
    }
    return result;
}
