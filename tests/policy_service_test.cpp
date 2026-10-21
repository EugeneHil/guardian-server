#include "policy_service.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "policy_store.hpp"
#include "warden/policy_parser.hpp"

using namespace warden::server;
namespace fs = std::filesystem;

namespace {
class TempDir {
 public:
  TempDir() {
    path_ =
        fs::temp_directory_path() / ("warden_policy_svc_test_" + std::to_string(counter_++) + "_" +
                                     std::to_string(reinterpret_cast<std::uintptr_t>(this)));
    fs::create_directories(path_);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  [[nodiscard]] const fs::path& path() const { return path_; }

 private:
  static inline int counter_ = 0;
  fs::path path_;
};

std::string draftJson(const std::string& versionField = R"("version":5,)") {
  return R"({"schemaVersion":1,)" + versionField +
         R"("rules":[{"id":"r","targets":["**/secret.txt"],"action":"deny","processes":[{"teamId":"X"}]}]})";
}

std::vector<std::string> described(const ValidationReport& report) {
  std::vector<std::string> out;
  for (const auto& error : report.errors) {
    out.push_back(warden::describe(error));
  }
  return out;
}

struct Fixture {
  TempDir dir;
  FilePolicyStore store{dir.path()};
  PolicyService service{store};
};
}  // namespace

TEST(PolicyService, SaveDraftReportsAllErrorsWithJsonPaths) {
  Fixture f;
  const std::string text =
      R"({"schemaVersion":1,"version":1,"rules":[{"id":"r","targets":["**/x"],"action":"deny","processes":[{"teamId":"X"},{"path":"/x"},{}]}]})";
  const ValidationReport report = f.service.saveDraft(text);
  EXPECT_FALSE(report.valid);
  EXPECT_EQ(described(report), std::vector<std::string>{"rules[0].processes[2]: empty matcher"});
}

TEST(PolicyService, SaveDraftKeepsInvalidTextAndGarbage) {
  Fixture f;
  EXPECT_FALSE(f.service.saveDraft("not json at all {{{").valid);
  EXPECT_EQ(f.service.draft(), std::optional<std::string>("not json at all {{{"));
  EXPECT_TRUE(f.service.saveDraft(draftJson()).valid);
  EXPECT_EQ(f.service.draft(), std::optional<std::string>(draftJson()));
}

TEST(PolicyService, OversizeDraftIsRejected) {
  Fixture f;
  const std::string big(1024 * 1024 + 1, ' ');
  const ValidationReport report = f.service.saveDraft(big);
  EXPECT_FALSE(report.valid);
  EXPECT_EQ(described(report), std::vector<std::string>{"$: policy larger than 1 MiB"});
  EXPECT_FALSE(f.service.draft().has_value());
}

TEST(PolicyService, ValidateDraftWithoutDraft) {
  Fixture f;
  const ValidationReport report = f.service.validateDraft();
  EXPECT_FALSE(report.valid);
  EXPECT_EQ(described(report), std::vector<std::string>{"$: no draft"});
}

TEST(PolicyService, PublishInvalidDraftChangesNothing) {
  Fixture f;
  f.service.saveDraft("garbage");
  const PublishResult result = f.service.publish();
  EXPECT_EQ(result.failure, PublishResult::Failure::Invalid);
  EXPECT_FALSE(result.published.has_value());
  EXPECT_FALSE(result.errors.empty());
  EXPECT_EQ(f.service.active().version, 1);
  EXPECT_EQ(f.service.draft(), std::optional<std::string>("garbage"));
}

TEST(PolicyService, PublishWithoutDraftIsNoDraft) {
  Fixture f;
  const PublishResult result = f.service.publish();
  EXPECT_EQ(result.failure, PublishResult::Failure::NoDraft);
  EXPECT_FALSE(result.published.has_value());
  EXPECT_EQ(f.service.active().version, 1);
}

TEST(PolicyService, ForcesVersionToNextNumber) {
  for (const char* field : {R"("version":99,)", ""}) {
    Fixture f;
    f.service.saveDraft(draftJson(field));
    const PublishResult result = f.service.publish();
    ASSERT_EQ(result.failure, PublishResult::Failure::None);
    ASSERT_TRUE(result.published.has_value());
    EXPECT_EQ(result.published->version, 2);
    EXPECT_NE(result.published->json.find(R"("version": 2)"), std::string::npos);
    EXPECT_EQ(f.service.active().version, 2);
  }
}

TEST(PolicyService, PublishClearsDraftAndServesNewActive) {
  Fixture f;
  f.service.saveDraft(draftJson());
  const PublishResult result = f.service.publish();
  ASSERT_TRUE(result.published.has_value());
  EXPECT_FALSE(f.service.draft().has_value());
  EXPECT_EQ(f.service.active().json, result.published->json);
  EXPECT_EQ(f.service.active().version, 2);
}

TEST(PolicyService, SecondPublishIsV3) {
  Fixture f;
  f.service.saveDraft(draftJson());
  f.service.publish();
  f.service.saveDraft(draftJson());
  const PublishResult result = f.service.publish();
  ASSERT_TRUE(result.published.has_value());
  EXPECT_EQ(result.published->version, 3);
}

TEST(PolicyService, PublishedJsonRoundTripsThroughParsePolicy) {
  Fixture f;
  f.service.saveDraft(draftJson());
  const PublishResult result = f.service.publish();
  ASSERT_TRUE(result.published.has_value());
  const warden::ParseResult parsed = warden::parsePolicy(result.published->json);
  ASSERT_TRUE(parsed.ok());
  EXPECT_EQ(parsed.policy->version, 2);
  EXPECT_EQ(result.published->json.back(), '\n');
}

TEST(PolicyService, ConcurrentPublishesAreConsecutive) {
  Fixture f;
  std::vector<PublishResult> results(2);
  std::vector<std::thread> threads;
  for (std::size_t i = 0; i < results.size(); ++i) {
    threads.emplace_back([&f, &results, i] {
      f.service.saveDraft(draftJson());
      results[i] = f.service.publish();
    });
  }
  for (auto& t : threads) {
    t.join();
  }
  std::vector<std::int64_t> versions;
  for (const auto& r : results) {
    if (r.published.has_value()) {
      versions.push_back(r.published->version);
    } else {
      EXPECT_EQ(r.failure, PublishResult::Failure::NoDraft);
    }
  }
  std::sort(versions.begin(), versions.end());
  ASSERT_FALSE(versions.empty());
  for (std::size_t i = 0; i < versions.size(); ++i) {
    EXPECT_EQ(versions[i], static_cast<std::int64_t>(i) + 2);
  }
  EXPECT_EQ(f.service.active().version, static_cast<std::int64_t>(versions.size()) + 1);
}

TEST(PolicyService, DuplicateJsonKeysInDraftAreRejected) {
  Fixture f;
  const std::string text = R"({"schemaVersion":1,"version":1,"version":2,"rules":[]})";
  EXPECT_FALSE(f.service.saveDraft(text).valid);
  const PublishResult result = f.service.publish();
  EXPECT_EQ(result.failure, PublishResult::Failure::Invalid);
  EXPECT_EQ(f.service.active().version, 1);
}

TEST(PolicyService, MalformedJsonReportsFixedMessageWithoutParserText) {
  Fixture f;
  const std::vector<std::string> inputs = {"{\"rules\": [", "\x01\x02\xff garbage", ""};
  for (const std::string& input : inputs) {
    const ValidationReport saved = f.service.saveDraft(input);
    EXPECT_FALSE(saved.valid);
    ASSERT_EQ(saved.errors.size(), 1U);
    EXPECT_EQ(saved.errors[0].path, "$");
    EXPECT_EQ(saved.errors[0].message, "invalid JSON");
    const ValidationReport validated = f.service.validateDraft();
    ASSERT_EQ(validated.errors.size(), 1U);
    EXPECT_EQ(validated.errors[0].message, "invalid JSON");
    const PublishResult published = f.service.publish();
    EXPECT_EQ(published.failure, PublishResult::Failure::Invalid);
    ASSERT_EQ(published.errors.size(), 1U);
    EXPECT_EQ(published.errors[0].path, "$");
    EXPECT_EQ(published.errors[0].message, "invalid JSON");
  }
}

TEST(PolicyService, NonObjectRootIsRejected) {
  Fixture f;
  EXPECT_FALSE(f.service.saveDraft("[]").valid);
  EXPECT_EQ(f.service.publish().failure, PublishResult::Failure::Invalid);
  EXPECT_EQ(f.service.active().version, 1);
}

TEST(PolicyService, MissingVersionAndRulesReportsOnlyRules) {
  Fixture f;
  const ValidationReport report = f.service.saveDraft(R"({"schemaVersion":1})");
  EXPECT_FALSE(report.valid);
  EXPECT_EQ(described(report), std::vector<std::string>{"rules: missing"});
}

TEST(PolicyService, BadVersionValuesStayInvalid) {
  Fixture f;
  EXPECT_FALSE(f.service.saveDraft(draftJson(R"("version":"x",)")).valid);
  EXPECT_FALSE(f.service.saveDraft(draftJson(R"("version":-1,)")).valid);
  EXPECT_EQ(f.service.publish().failure, PublishResult::Failure::Invalid);
}
