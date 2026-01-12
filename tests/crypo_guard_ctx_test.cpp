#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <fstream>
#include <sstream>
#include <string>

//=== Tests for encryption ===
TEST(CryptoGuard_Tests, EncryptExceptionInput)
{
    // A non-existent path to force an exception
    std::fstream ifs("::");
    std::stringstream oss{};

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(ifs, oss, "1234"), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, EncryptExceptionOutput)
{
    // A non-existent path to force an exception
    std::stringstream iss{};
    std::fstream oss("::");

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(iss, oss, "1234"), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, EncryptEmptyFile)
{
    std::stringstream iss("");
    std::stringstream oss{};

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_NO_THROW(ctx.EncryptFile(iss, oss, "0123456789"));
}

TEST(CryptoGuard_Tests, EncryptStability)
{
    using namespace std::string_literals;
    
    std::string s = "This is a test string for "
        "checking the API stability of the EncryptFile function"s;
    
    CryptoGuard::CryptoGuardCtx ctx;
    std::string s_encrypted;
    {
        std::stringstream iss(s);
        std::stringstream oss{};
        ctx.EncryptFile(iss, oss, "0123456789");
        s_encrypted = oss.str();
    }

    for (size_t i = 0; i < 10; ++i)
    {
        std::stringstream iss(s);
        std::stringstream oss{};
        ctx.EncryptFile(iss, oss, "0123456789");
        EXPECT_EQ(oss.str(), s_encrypted);
    }
}

//=== Tests for decryption ===
TEST(CryptoGuard_Tests, DecryptExceptionInput)
{
    // A non-existent path to force an exception
    std::fstream ifs("::");
    std::stringstream oss{};

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(ifs, oss, "1234"), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, DecryptExceptionOutput)
{
    // A non-existent path to force an exception
    std::stringstream iss{};
    std::fstream oss("::");

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(iss, oss, "1234"), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, DecryptEmptyFile)
{
    // An empty string cannot be decrypted
    std::stringstream iss("");
    std::stringstream oss{};

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(iss, oss, "1234"), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, DecryptStability)
{
    using namespace std::string_literals;
    
    std::string s = "This is a test string for "
        "checking the API stability of the DecryptFile function"s;

    CryptoGuard::CryptoGuardCtx ctx;
    std::string s_encrypted;
    {
        std::stringstream iss(s);
        std::stringstream oss{};

        ctx.EncryptFile(iss, oss, "0123456789");
        s_encrypted = oss.str();
    }

    for (size_t i = 0; i < 10; ++i)
    {
        std::stringstream iss(s_encrypted);
        std::stringstream oss{};

        ctx.DecryptFile(iss, oss, "0123456789");
        EXPECT_EQ(oss.str(), s);
    }
}

//=== Composite tests ===
TEST(CryptoGuard_Tests, EncryptDecryptComposite)
{
    std::string s = "This is a test string";
    std::string password = "isbvisvjnsivbnv";

    std::stringstream iss(s); // in
    std::stringstream mss; // middle
    std::stringstream oss; // out

    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(iss, mss, password);
    ctx.DecryptFile(mss, oss, password);

    EXPECT_EQ(s, oss.str());
}

TEST(CryptoGuard_Tests, SameStream)
{
    std::stringstream iss("");

    CryptoGuard::CryptoGuardCtx ctx;

    ASSERT_THROW(ctx.EncryptFile(iss, iss, "password"), 
        std::logic_error);
    ASSERT_THROW(ctx.DecryptFile(iss, iss, "password"), 
        std::logic_error);
}

//=== Tests for checksum calculations ===
TEST(CryptoGuard_Tests, ChecksumCalculationException)
{
    // A non-existent path to force an exception
    std::fstream ifs("::");

    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.CalculateChecksum(ifs), 
        std::runtime_error);
}

TEST(CryptoGuard_Tests, ChecksumCalculation)
{
    using namespace std::string_literals;

    std::stringstream iss("This is a test string"s);

    CryptoGuard::CryptoGuardCtx ctx;

    EXPECT_EQ(ctx.CalculateChecksum(iss), 
        "717ac506950da0cc"
        "b6404cdd5e7591f7"
        "2018a20cbca27c8a"
        "423e9c9e5626ac61"s);
    
    iss = std::stringstream("This is another test string"s);
    EXPECT_EQ(ctx.CalculateChecksum(iss), 
        "e3786ae2f5f45065"
        "e224983439d81c5e"
        "bcaa9dcd4d37a0ee"
        "da99e53c12544cd3"s);
    
    iss = std::stringstream("This is yet another test string"s);
    EXPECT_EQ(ctx.CalculateChecksum(iss), 
        "ee8e26616612760e"
        "853ad17703c6c977"
        "fd3958bc088269e5"
        "95fb4d280c5c74ba"s);
}

TEST(CryptoGuard_Tests, ChecksumStability)
{
    using namespace std::string_literals;
    
    std::string s = "This is a test string for "
        "checking the API stability of the CalculateCheckSum function"s;

    CryptoGuard::CryptoGuardCtx ctx;
    std::string sha256;
    {
        std::stringstream iss(s);
        sha256 = ctx.CalculateChecksum(iss);
    }

    for (size_t i = 0; i < 10; ++i)
    {
        std::stringstream iss(s);
        EXPECT_EQ(ctx.CalculateChecksum(iss), 
            sha256);
    }
}