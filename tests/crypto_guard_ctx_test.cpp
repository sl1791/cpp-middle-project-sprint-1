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

TEST(CryptoGuardCtxTest, CalculateChecksumNormalString) {
    CryptoGuardCtx ctx;
    std::string text = "Hello OpenSSL crypto world!";
    std::stringstream inStream(text);

    // echo -n "Hello OpenSSL crypto world!" | sha256sum
    std::string expected = "abec80fdd708340513c54b7c6522cd3c9318a5decce7305e48fb1b51da6a4899";
    std::string actual;
    ASSERT_NO_THROW(actual = ctx.CalculateChecksum(inStream));
    EXPECT_EQ(actual, expected);
}

TEST(CryptoGuardCtxTest, CalculateChecksumEmptyStream) {
    CryptoGuardCtx ctx;
    std::stringstream inStream("");

    // echo -n "" | sha256sum
    std::string expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    std::string actual;
    ASSERT_NO_THROW(actual = ctx.CalculateChecksum(inStream));
    EXPECT_EQ(actual, expected);
}

TEST(CryptoGuardCtxTest, CalculateChecksumThrowsOnBadStream) {
    CryptoGuardCtx ctx;
    std::stringstream inStream;
    inStream.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.CalculateChecksum(inStream), std::runtime_error);
}

TEST(CryptoGuardCtxTest, CalculateChecksumBeforeAndAfterEncryptDecrypt) {
    CryptoGuardCtx ctx;
    std::string text = "Hello OpenSSL crypto world!";
    std::stringstream inStream(text);

    // echo -n "Hello OpenSSL crypto world!" | sha256sum
    // >> abec80fdd708340513c54b7c6522cd3c9318a5decce7305e48fb1b51da6a4899
    std::string before;
    ASSERT_NO_THROW(before = ctx.CalculateChecksum(inStream));

    // Теперь сравним с хэшэм после шифрования/дешифрования того же текста
    std::string password = "very_very_strong_password";

    std::stringstream inStream2(text);
    std::stringstream cipherStream;
    ASSERT_NO_THROW(ctx.EncryptFile(inStream2, cipherStream, password));

    std::stringstream outStream;
    ASSERT_NO_THROW(ctx.DecryptFile(cipherStream, outStream, password));

    std::string after;
    ASSERT_NO_THROW(after = ctx.CalculateChecksum(outStream));

    EXPECT_EQ(before, after);
}

} // namespace
