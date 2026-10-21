#pragma once

#include <cstddef>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "warden/policy.hpp"

namespace warden::server {

struct ProcessRef {
  std::string path;
  std::string signingId;
  std::string teamId;
};

struct Event {
  std::string ts;
  ProcessRef process;
  std::optional<ProcessRef> responsible;
  std::string file;
  std::string decision;  // "deny" or "allow"
  std::string ruleId;
};

struct StoredEvent {
  Event event;
  std::string agentId;
  std::string receivedAt;
};

// `events` is valid if and only if `errors` is empty.
struct EventBatchResult {
  std::vector<Event> events;
  std::vector<warden::ValidationError> errors;
};

constexpr std::size_t kMaxEventsPerBatch = 500;
constexpr std::size_t kMaxEventStringBytes = 4096;
constexpr std::size_t kMaxJsonNesting = 64;

// Parses and validates an agent event batch. Never throws and never puts parser internals into
// the error messages. Input nested deeper than kMaxJsonNesting or containing invalid UTF-8 is
// rejected before it reaches the JSON parser.
EventBatchResult parseEventBatch(std::string_view json);

// Reads back one line written by the event store; nullopt if it is not a well-formed record.
std::optional<StoredEvent> parseStoredEvent(std::string_view line);

nlohmann::json toJson(const StoredEvent& event);

}  // namespace warden::server
