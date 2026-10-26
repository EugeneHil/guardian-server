#include "policy_service.hpp"

#include <algorithm>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <utility>

#include "fs_util.hpp"

namespace guardian::server {

namespace {
constexpr std::size_t kMaxPolicyBytes = 1048576;  // 1 MiB

// The published version is always assigned by the server, so a draft that omits "version"
// is acceptable; every other error is reported as is. Parser messages for malformed JSON carry
// nlohmann text (byte offsets, token text), so they are replaced by a fixed message.
std::vector<guardian::ValidationError> validate(std::string_view text) {
  std::vector<guardian::ValidationError> errors = guardian::parsePolicy(text).errors;
  // Coupled to guardian-core's literal {"version", "missing"} error.
  errors.erase(std::remove_if(errors.begin(), errors.end(),
                              [](const guardian::ValidationError& e) {
                                return e.path == "version" && e.message == "missing";
                              }),
               errors.end());
  for (guardian::ValidationError& error : errors) {
    if (error.path == "$" && error.message.rfind("invalid JSON", 0) == 0) {
      error.message = "invalid JSON";
    }
  }
  return errors;
}

ValidationReport report(std::vector<guardian::ValidationError> errors) {
  ValidationReport out;
  out.valid = errors.empty();
  out.errors = std::move(errors);
  return out;
}
}  // namespace

PolicyService::PolicyService(PolicyStore& store) : store_(store) {}

PolicyDoc PolicyService::active() const { return store_.active(); }

std::optional<std::string> PolicyService::draft() const { return store_.draft(); }

ValidationReport PolicyService::saveDraft(std::string_view text) {
  if (text.size() > kMaxPolicyBytes) {
    return report({{"$", "policy larger than 1 MiB"}});
  }
  const std::scoped_lock lock(mutex_);
  store_.saveDraft(text);
  return report(validate(text));
}

ValidationReport PolicyService::validateDraft() const {
  const std::scoped_lock lock(mutex_);
  const std::optional<std::string> text = store_.draft();
  if (!text.has_value()) {
    return report({{"$", "no draft"}});
  }
  return report(validate(*text));
}

PublishResult PolicyService::publish() {
  const std::scoped_lock lock(mutex_);
  PublishResult result;
  const std::optional<std::string> text = store_.draft();
  if (!text.has_value()) {
    result.failure = PublishResult::Failure::NoDraft;
    return result;
  }
  std::vector<guardian::ValidationError> errors = validate(*text);
  if (!errors.empty()) {
    result.failure = PublishResult::Failure::Invalid;
    result.errors = std::move(errors);
    return result;
  }

  const std::int64_t next = store_.active().version + 1;
  nlohmann::json doc = nlohmann::json::parse(*text, nullptr, /*allow_exceptions=*/false);
  if (!doc.is_object()) {
    throw StorageError("validated draft is not a JSON object");
  }
  doc["version"] = next;
  std::string json = doc.dump(2) + "\n";

  const guardian::ParseResult reparsed = guardian::parsePolicy(json);
  if (!reparsed.policy.has_value() || reparsed.policy->version != next) {
    throw StorageError("published policy failed re-validation");
  }

  PolicyDoc published{next, std::move(json)};
  store_.commit(published);
  store_.clearDraft();
  result.published = std::move(published);
  return result;
}

}  // namespace guardian::server
