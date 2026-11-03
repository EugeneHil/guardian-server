#pragma once

#include <cstdint>
#include <guardian/policy_parser.hpp>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "policy_store.hpp"

namespace guardian::server {

struct ValidationReport {
  bool valid = false;
  std::vector<guardian::ValidationError> errors;
};

struct PublishResult {
  enum class Failure : std::uint8_t { None, NoDraft, Invalid };
  Failure failure = Failure::None;
  std::optional<PolicyDoc> published;
  std::vector<guardian::ValidationError> errors;
};

class PolicyService {
 public:
  explicit PolicyService(PolicyStore& store);

  [[nodiscard]] PolicyDoc active() const;
  [[nodiscard]] std::optional<std::string> draft() const;
  // Saves the text verbatim even when invalid; text over 1 MiB is not saved.
  ValidationReport saveDraft(std::string_view text);
  [[nodiscard]] ValidationReport validateDraft() const;
  // Publishes the draft as version active().version + 1 (any version in the draft is ignored).
  // Throws StorageError on storage failure.
  PublishResult publish();

 private:
  PolicyStore& store_;
  mutable std::mutex mutex_;
};

}  // namespace guardian::server
