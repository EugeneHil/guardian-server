#include <gtest/gtest.h>
#include <openssl/opensslv.h>

#include <nlohmann/json.hpp>
#include <regex>
#include <string>

#include "version.hpp"
#include "warden/policy_parser.hpp"

TEST(Smoke, VersionIsSemver) {
    const std::string version{warden::server::serverVersion()};
    EXPECT_TRUE(std::regex_match(version, std::regex{R"(\d+\.\d+\.\d+)"}));
    EXPECT_EQ(version, "0.1.0");
}

TEST(Smoke, LinksWardenCoreAndRejectsGarbagePolicy) {
    const auto result = warden::parsePolicy("not json");
    EXPECT_FALSE(result.ok());
    EXPECT_FALSE(result.errors.empty());
}

TEST(Smoke, LinksNlohmannAndOpenSsl) {
    EXPECT_EQ(nlohmann::json::parse("[1]").size(), 1U);
    EXPECT_GE(OPENSSL_VERSION_MAJOR, 3);
}
