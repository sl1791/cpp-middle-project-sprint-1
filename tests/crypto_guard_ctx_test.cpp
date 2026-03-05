#include <gtest/gtest.h>
#include <sstream>
#include "crypto_guard_ctx.h"

namespace {

using CryptoGuard::CryptoGuardCtx;

TEST(CryptoGuardCtxTest, EncryptEmptyStream) {
    CryptoGuardCtx ctx;
    std::stringstream inStream("");
    std::stringstream outStream;
    std::string password = "test_password";

    ASSERT_NO_THROW(ctx.EncryptFile(inStream, outStream, password));
    
    // Даже пустой поток при шифровании AES-256 с паддингом должен дать какой-то вывод (16 байт)
    EXPECT_FALSE(outStream.str().empty());
}

TEST(CryptoGuardCtxTest, EncryptNormalString) {
    CryptoGuardCtx ctx;
    std::string plaintext = "Hello OpenSSL crypto world!";
    std::stringstream inStream(plaintext);
    std::stringstream outStream;
    std::string password = "strong_password";

    ASSERT_NO_THROW(ctx.EncryptFile(inStream, outStream, password));

    std::string ciphertext = outStream.str();
    EXPECT_FALSE(ciphertext.empty());
    EXPECT_NE(ciphertext, plaintext);
}

TEST(CryptoGuardCtxTest, EncryptThrowsOnBadStream) {
    CryptoGuardCtx ctx;
    std::stringstream inStream;
    inStream.setstate(std::ios::failbit);
    std::stringstream outStream;
    std::string password = "password";

    // Согласно реализации в src/crypto_guard_ctx.cpp, если !inStream.good(), выбрасывается runtime_error
    ASSERT_THROW(ctx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, DecryptNormalString) {
    CryptoGuardCtx ctx;
    std::string plaintext = "Hello OpenSSL crypto world!";
    std::string password = "very_very_strong_password";

    std::stringstream inStream(plaintext);
    std::stringstream cipherStream;
    ASSERT_NO_THROW(ctx.EncryptFile(inStream, cipherStream, password));

    std::stringstream outStream;
    ASSERT_NO_THROW(ctx.DecryptFile(cipherStream, outStream, password));

    EXPECT_EQ(outStream.str(), plaintext);
}

TEST(CryptoGuardCtxTest, DecryptEmptyStream) {
    CryptoGuardCtx ctx;
    std::string password = "test_password";

    std::stringstream inStream("");
    std::stringstream cipherStream;
    ASSERT_NO_THROW(ctx.EncryptFile(inStream, cipherStream, password));

    std::stringstream outStream;
    ASSERT_NO_THROW(ctx.DecryptFile(cipherStream, outStream, password));

    EXPECT_TRUE(outStream.str().empty());
}

TEST(CryptoGuardCtxTest, DecryptThrowsOnBadPassword) {
    CryptoGuardCtx ctx;
    std::string plaintext = "Hello OpenSSL crypto world!";
    std::string correctPassword = "correct_password";
    std::string wrongPassword = "wrong_password";

    std::stringstream inStream(plaintext);
    std::stringstream cipherStream;
    ASSERT_NO_THROW(ctx.EncryptFile(inStream, cipherStream, correctPassword));

    std::stringstream outStream;
    // При дешифровании с неправильным паролем EVP_CipherFinal_ex должен вернуть ошибку
    ASSERT_THROW(ctx.DecryptFile(cipherStream, outStream, wrongPassword), std::runtime_error);
}

} // namespace
