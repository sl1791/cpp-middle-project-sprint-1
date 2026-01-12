#include "cmd_options.h"
#include <gtest/gtest.h>

TEST(Settings_Tests, MissingCommand)
{
    int argc = 3;
    const char* argv[argc] = {"Reserved for the working directory", 
        "abcd", "abcd"};
    
    CryptoGuard::ProgramOptions options;
    ASSERT_THROW(options.Parse(argc, (char**)argv), 
        std::logic_error);
}

TEST(Settings_Tests, MissingInput)
{
    int argc = 7;
    const char* argv_e[argc] = {"Reserved for the working directory", 
        "--command", "encrypt", 
        // "--input", "File name",
        "--output", "File name", 
        "--password", "password"};
    {
        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(argc, (char**)argv_e), 
            std::logic_error);
    }

    const char* argv_d[argc] = {"Reserved for the working directory", 
        "--command", "decrypt", 
        // "--input", "File name",
        "--output", "File name", 
        "--password", "password"};
    {
        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(argc, (char**)argv_d), 
            std::logic_error);
    }

    const char* argv_cs[argc] = {"Reserved for the working directory", 
        "--command", "encrypt", 
        // "--input", "File name",
        "--output", "File name", 
        "--password", "password"};
    {
        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(argc, (char**)argv_cs), 
            std::logic_error);
    }
}

TEST(Settings_Tests, MissingOutput)
{
    int argc = 7;
    const char* argv_e[argc] = {"Reserved for the working directory", 
        "--command", "encrypt", 
        "--input", "File name",
        // "--output", "File name", 
        "--password", "password"};
    {
        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(argc, (char**)argv_e), 
            std::logic_error);
    }

    const char* argv_d[argc] = {"Reserved for the working directory", 
        "--command", "decrypt", 
        "--input", "File name",
        // "--output", "File name", 
        "--password", "password"};
    {
        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(argc, (char**)argv_d), 
            std::logic_error);
    }

    const char* argv_cs[argc] = {"Reserved for the working directory", 
        "--command", "checksum", 
        "--input", "File name",
        // "--output", "File name", 
        "--password", "password"};
    {
        CryptoGuard::ProgramOptions options;
        ASSERT_NO_THROW(options.Parse(argc, (char**)argv_cs));
    }
}

TEST(Settings_Tests, MissingPassword)
{
    int argc = 7;
    const char* argv_e[argc] = {"Reserved for the working directory", 
        "--command", "encrypt", 
        "--input", "File name",
        "--output", "File name"};
    {
        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(argc, (char**)argv_e), 
            std::logic_error);
    }

    const char* argv_d[argc] = {"Reserved for the working directory", 
        "--command", "decrypt", 
        "--input", "File name",
        "--output", "File name"};
    {
        CryptoGuard::ProgramOptions options;
        ASSERT_THROW(options.Parse(argc, (char**)argv_d), 
            std::logic_error);
    }

    const char* argv_cs[argc] = {"Reserved for the working directory", 
        "--command", "checksum", 
        "--input", "File name",
        "--output", "File name"};
    {
        CryptoGuard::ProgramOptions options;
        ASSERT_NO_THROW(options.Parse(argc, (char**)argv_cs));
    }
}

TEST(Settings_Tests, HelpIgnoreAllElse)
{
    int argc = 3;
    const char* argv[argc] = {"Reserved for the working directory", 
        "--help", "abcd"};
    
    std::ostringstream oss{};
    CryptoGuard::ProgramOptions options;
    ASSERT_NO_THROW(options.Parse(argc, (char**)argv, oss));
}

TEST(Settings_Tests, CommandMapping)
{
    using CommandType = CryptoGuard::ProgramOptions::COMMAND_TYPE;

    int argc = 9;
    const char* argv_e[argc] = {"Reserved for the working directory", 
        "--command", "encrypt", 
        "--input", "File name",
        "--output", "File name", 
        "--password", "password"};
    {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, (char**)argv_e);
        EXPECT_EQ(options.GetCommand(), 
            CommandType::ENCRYPT);
    }

    const char* argv_d[argc] = {"Reserved for the working directory", 
        "--command", "decrypt", 
        "--input", "File name",
        "--output", "File name", 
        "--password", "password"};
    {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, (char**)argv_d);
        EXPECT_EQ(options.GetCommand(), 
            CommandType::DECRYPT);
    }

    const char* argv_cs[argc] = {"Reserved for the working directory", 
        "--command", "checksum", 
        "--input", "File name",
        "--output", "File name", 
        "--password", "password"};
    {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, (char**)argv_cs);
        EXPECT_EQ(options.GetCommand(), 
            CommandType::CHECKSUM);
    }
}