#pragma once

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace warden::server {

struct PolicyDoc {
  std::int64_t version = 0;
  std::string json;
};

class PolicyStore {
 public:
  virtual ~PolicyStore() = default;

  // The active policy; never empty. Throws StorageError if it cannot be read.
  [[nodiscard]] virtual PolicyDoc active() const = 0;
  [[nodiscard]] virtual std::optional<std::string> draft() const = 0;
  // Stores the text verbatim (it may be invalid).
  virtual void saveDraft(std::string_view text) = 0;
  virtual void clearDraft() = 0;
  // doc.version must be active().version + 1, else StorageError.
  virtual void commit(const PolicyDoc& doc) = 0;
};

// Layout under <dataDir>/policies: v<N>.json, `active` (decimal N + "\n"), draft.json.
// commit writes v<N>.json first and then flips the pointer, so a crash in between leaves the
// previous version active.
class FilePolicyStore final : public PolicyStore {
 public:
  // Bootstraps an empty v1 when no pointer exists. Throws StorageError on a corrupt pointer
  // or a missing/unreadable version file.
  explicit FilePolicyStore(const std::filesystem::path& dataDir);

  [[nodiscard]] PolicyDoc active() const override;
  [[nodiscard]] std::optional<std::string> draft() const override;
  void saveDraft(std::string_view text) override;
  void clearDraft() override;
  void commit(const PolicyDoc& doc) override;

 private:
  [[nodiscard]] bool hasLaterVersions() const;
  [[nodiscard]] std::filesystem::path versionFile(std::int64_t version) const;

  std::filesystem::path dir_;
  PolicyDoc active_;
  mutable std::mutex mutex_;
};

}  // namespace warden::server
