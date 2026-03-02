//
// Created by Miralius on 3/2/26.
//

#include <gtest/gtest.h>
#include "cmd_options.h"

TEST(ProgramOptions, ParseEncryptCommand) {
    CryptoGuard::ProgramOptions options;
    std::vector args = {"program", "--command", "encrypt",
                     "--input", "input.txt",
                     "--output", "encrypted.txt",
                     "--password", "1234"};

    ASSERT_NO_THROW(options.Parse(args.size(), const_cast<char**>(args.data())));

    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "encrypted.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

// Тест 2: Успешный парсинг команды decrypt
TEST(ProgramOptions, ParseDecryptCommand) {
    CryptoGuard::ProgramOptions options;
    std::vector args = {"program", "--command", "decrypt",
                     "--input", "encrypted.txt",
                     "--output", "decrypted.txt",
                     "--password", "1234"};

    ASSERT_NO_THROW(options.Parse(args.size(), const_cast<char**>(args.data())));

    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "encrypted.txt");
    EXPECT_EQ(options.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(options.GetPassword(), "1234");
}

// Тест 3: Успешный парсинг команды checksum (без пароля)
TEST(ProgramOptions, ParseChecksumCommand) {
    CryptoGuard::ProgramOptions options;
    std::vector args = {"program", "--command", "checksum",
                     "--input", "input.txt"};

    ASSERT_NO_THROW(options.Parse(args.size(), const_cast<char**>(args.data())));

    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}

// Тест 4: Ошибка при неизвестной команде
TEST(ProgramOptions, ThrowsOnUnknownCommand) {
    CryptoGuard::ProgramOptions options;
    std::vector args = {"program", "--command", "invalid_command",
                     "--input", "file.txt",
                     "--output", "out.txt"};

    EXPECT_THROW(options.Parse(args.size(), const_cast<char**>(args.data())), std::runtime_error);
}

// Тест 5: Парсинг с параметрами в произвольном порядке
TEST(ProgramOptions, ParseOptionsInAnyOrder) {
    CryptoGuard::ProgramOptions options;
    std::vector args({"program",
                     "--password", "pass123",
                     "--output", "encrypted.txt",
                     "--command", "encrypt",
                     "--input", "source.txt"});

    ASSERT_NO_THROW(options.Parse(args.size(), const_cast<char**>(args.data())));

    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "source.txt");
    EXPECT_EQ(options.GetOutputFile(), "encrypted.txt");
    EXPECT_EQ(options.GetPassword(), "pass123");
}

// Тест 6: Опция help не вызывает исключений
TEST(ProgramOptions, HelpOptionDoesNotThrow) {
    CryptoGuard::ProgramOptions options;
    std::vector args({"program", "--help"});

    EXPECT_NO_THROW(options.Parse(args.size(), const_cast<char**>(args.data())));
}

// Тест 7: Парсинг путей с пробелами
TEST(ProgramOptions, ParsePathsWithSpaces) {
    CryptoGuard::ProgramOptions options;
    std::vector args({"program", "--command", "checksum",
                     "--input", "/path/to/my file.txt"});

    ASSERT_NO_THROW(options.Parse(args.size(), const_cast<char**>(args.data())));

    EXPECT_EQ(options.GetInputFile(), "/path/to/my file.txt");
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_TRUE(options.GetPassword().empty());
}
