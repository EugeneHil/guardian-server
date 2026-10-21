#include "event.hpp"

#include <cstdint>
#include <utility>

#include "timeutil.hpp"

namespace warden::server {

namespace {

// Shape of a multi-byte UTF-8 sequence: continuation bytes after the lead and the allowed range
// of the first of them (this is what excludes overlong forms, surrogates and > U+10FFFF).
struct Utf8Shape {
  std::size_t continuation;
  unsigned lo;
  unsigned hi;
};

std::optional<Utf8Shape> utf8Shape(unsigned lead) {
  if (lead >= 0xC2U && lead <= 0xDFU) {
    return Utf8Shape{1, 0x80U, 0xBFU};
  }
  if (lead >= 0xE0U && lead <= 0xEFU) {
    return Utf8Shape{2, lead == 0xE0U ? 0xA0U : 0x80U, lead == 0xEDU ? 0x9FU : 0xBFU};
  }
  if (lead >= 0xF0U && lead <= 0xF4U) {
    return Utf8Shape{3, lead == 0xF0U ? 0x90U : 0x80U, lead == 0xF4U ? 0x8FU : 0xBFU};
  }
  return std::nullopt;
}

// Strict UTF-8 (RFC 3629).
bool isValidUtf8(std::string_view text) {
  std::size_t i = 0;
  while (i < text.size()) {
    const auto lead = static_cast<unsigned char>(text[i]);
    if (lead < 0x80U) {
      ++i;
      continue;
    }
    const std::optional<Utf8Shape> shape = utf8Shape(lead);
    if (!shape || i + shape->continuation >= text.size()) {
      return false;
    }
    const unsigned first = static_cast<unsigned char>(text[i + 1]);
    if (first < shape->lo || first > shape->hi) {
      return false;
    }
    for (std::size_t k = 2; k <= shape->continuation; ++k) {
      if ((static_cast<unsigned char>(text[i + k]) & 0xC0U) != 0x80U) {
        return false;
      }
    }
    i += shape->continuation + 1;
  }
  return true;
}

// True if brackets/braces outside of strings nest deeper than kMaxJsonNesting.
bool nestsTooDeep(std::string_view text) {
  std::size_t depth = 0;
  bool inString = false;
  bool escaped = false;
  for (const char c : text) {
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (c == '\\') {
        escaped = true;
      } else if (c == '"') {
        inString = false;
      }
      continue;
    }
    if (c == '"') {
      inString = true;
    } else if (c == '[' || c == '{') {
      if (++depth > kMaxJsonNesting) {
        return true;
      }
    } else if ((c == ']' || c == '}') && depth > 0) {
      --depth;
    }
  }
  return false;
}

using Json = nlohmann::json;

// Parses without exceptions; the caller has already bounded nesting and checked UTF-8.
std::optional<Json> parseJson(std::string_view text) {
  Json value = Json::parse(text.begin(), text.end(), nullptr, /*allow_exceptions=*/false);
  if (value.is_discarded()) {
    return std::nullopt;
  }
  return value;
}

void addError(std::vector<warden::ValidationError>& errors, std::string path, std::string message) {
  errors.push_back({std::move(path), std::move(message)});
}

// Required string field.
bool takeString(const Json& object, const char* key, const std::string& path,
                std::vector<warden::ValidationError>& errors, std::string& out) {
  const auto it = object.find(key);
  if (it == object.end() || !it->is_string()) {
    addError(errors, path, "required string");
    return false;
  }
  if (it->get_ref<const std::string&>().size() > kMaxEventStringBytes) {
    addError(errors, path, "longer than 4096 bytes");
    return false;
  }
  out = it->get<std::string>();
  return true;
}

// Optional string field: absent or null is fine, anything else must be a short string.
void takeOptionalString(const Json& object, const char* key, const std::string& path,
                        std::vector<warden::ValidationError>& errors, std::string& out) {
  const auto it = object.find(key);
  if (it == object.end() || it->is_null()) {
    return;
  }
  takeString(object, key, path, errors, out);
}

void takeProcess(const Json& value, const std::string& path, bool pathRequired,
                 std::vector<warden::ValidationError>& errors, ProcessRef& out) {
  if (!value.is_object()) {
    // Report the required field so the client learns which key is missing.
    addError(errors, path + ".path", "required string");
    return;
  }
  if (pathRequired) {
    takeString(value, "path", path + ".path", errors, out.path);
  } else {
    takeOptionalString(value, "path", path + ".path", errors, out.path);
  }
  takeOptionalString(value, "signingId", path + ".signingId", errors, out.signingId);
  takeOptionalString(value, "teamId", path + ".teamId", errors, out.teamId);
}

void takeEvent(const Json& value, const std::string& path,
               std::vector<warden::ValidationError>& errors, Event& out) {
  if (!value.is_object()) {
    addError(errors, path, "must be an object");
    return;
  }
  if (takeString(value, "ts", path + ".ts", errors, out.ts) && !parseUtc(out.ts).has_value()) {
    addError(errors, path + ".ts", "must be an ISO-8601 UTC timestamp");
  }
  const auto process = value.find("process");
  if (process == value.end()) {
    addError(errors, path + ".process.path", "required string");
  } else {
    takeProcess(*process, path + ".process", true, errors, out.process);
  }
  const auto responsible = value.find("responsible");
  if (responsible != value.end() && !responsible->is_null()) {
    ProcessRef ref;
    takeProcess(*responsible, path + ".responsible", false, errors, ref);
    out.responsible = std::move(ref);
  }
  takeString(value, "file", path + ".file", errors, out.file);
  if (takeString(value, "decision", path + ".decision", errors, out.decision) &&
      out.decision != "deny" && out.decision != "allow") {
    addError(errors, path + ".decision", R"(must be "deny" or "allow")");
  }
  takeOptionalString(value, "ruleId", path + ".ruleId", errors, out.ruleId);
}

// Shared guard in front of every parse of untrusted or on-disk text.
std::optional<Json> parseGuarded(std::string_view text,
                                 std::vector<warden::ValidationError>& errors) {
  if (!isValidUtf8(text)) {
    addError(errors, "$", "invalid UTF-8");
    return std::nullopt;
  }
  if (nestsTooDeep(text)) {
    addError(errors, "$", "nested too deeply");
    return std::nullopt;
  }
  std::optional<Json> parsed = parseJson(text);
  if (!parsed) {
    addError(errors, "$", "invalid JSON");
  }
  return parsed;
}

Json processToJson(const ProcessRef& p) {
  return Json{{"path", p.path}, {"signingId", p.signingId}, {"teamId", p.teamId}};
}

}  // namespace

EventBatchResult parseEventBatch(std::string_view json) {
  EventBatchResult result;
  const std::optional<Json> root = parseGuarded(json, result.errors);
  if (!root) {
    return result;
  }
  if (!root->is_array()) {
    addError(result.errors, "$", "must be an array");
    return result;
  }
  if (root->empty()) {
    addError(result.errors, "$", "must not be empty");
    return result;
  }
  if (root->size() > kMaxEventsPerBatch) {
    addError(result.errors, "$", "more than 500 items");
    return result;
  }
  result.events.reserve(root->size());
  for (std::size_t i = 0; i < root->size(); ++i) {
    Event event;
    takeEvent((*root)[i], "[" + std::to_string(i) + "]", result.errors, event);
    result.events.push_back(std::move(event));
  }
  if (!result.errors.empty()) {
    result.events.clear();
  }
  return result;
}

std::optional<StoredEvent> parseStoredEvent(std::string_view line) {
  std::vector<warden::ValidationError> errors;
  const std::optional<Json> root = parseGuarded(line, errors);
  if (!root || !root->is_object()) {
    return std::nullopt;
  }
  StoredEvent stored;
  takeEvent(*root, "$", errors, stored.event);
  takeString(*root, "agentId", "$.agentId", errors, stored.agentId);
  takeString(*root, "receivedAt", "$.receivedAt", errors, stored.receivedAt);
  if (!errors.empty()) {
    return std::nullopt;
  }
  return stored;
}

nlohmann::json toJson(const StoredEvent& event) {
  Json out = Json::object();
  out["ts"] = event.event.ts;
  out["process"] = processToJson(event.event.process);
  out["responsible"] =
      event.event.responsible ? processToJson(*event.event.responsible) : Json(nullptr);
  out["file"] = event.event.file;
  out["decision"] = event.event.decision;
  out["ruleId"] = event.event.ruleId;
  out["agentId"] = event.agentId;
  out["receivedAt"] = event.receivedAt;
  return out;
}

}  // namespace warden::server
