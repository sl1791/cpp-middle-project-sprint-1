#include "crypto_guard_ctx.h"

#include <array>
#include <vector>
#include <iostream>
#include <openssl/evp.h>
#include <print>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::PImpl {
    using Unique_ptr_EVP_CIPHER_CTX = std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX* ptr) { EVP_CIPHER_CTX_free(ptr); })>;
public:
    PImpl() {
        std::string input = "01234567890123456789";

        OpenSSL_add_all_algorithms();

        auto params = CreateChiperParamsFromPassword("12341234");
        params.encrypt = 1;
        ctx_ = Unique_ptr_EVP_CIPHER_CTX(EVP_CIPHER_CTX_new());

        outBuf_.resize(16 + EVP_MAX_BLOCK_LENGTH);

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx_.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        std::vector<unsigned char> inBuf(16);

        // Обрабатываем первые N символов
        std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        EVP_CipherUpdate(ctx_.get(), outBuf_.data(), &outLen_, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen_; ++i) {
            output_.push_back(outBuf_[i]);
        }

        // Обрабатываем оставшиеся символы
        std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        EVP_CipherUpdate(ctx_.get(), outBuf_.data(), &outLen_, inBuf.data(), static_cast<int>(input.size() - 16));
        for (int i = 0; i < outLen_; ++i) {
            output_.push_back(outBuf_[i]);
        }
    }
    ~PImpl() {
        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx_.get(), outBuf_.data(), &outLen_);
        for (int i = 0; i < outLen_; ++i) {
            output_.push_back(outBuf_[i]);
        }
        std::print("String encoded successfully. Result: '{}'\n\n", output_);
        EVP_cleanup();
    }

    PImpl(const PImpl &) = delete;
    PImpl &operator=(const PImpl &) = delete;
    PImpl(PImpl &&) = delete;
    PImpl &operator=(PImpl &&) = delete;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        // 1. Проверка состояния потоков
        if (!inStream.good()) {
            throw std::runtime_error("Input stream is in bad state");
        }
        if (!outStream.good()) {
            throw std::runtime_error("Output stream is in bad state");
        }
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    Unique_ptr_EVP_CIPHER_CTX ctx_;
    std::vector<unsigned char> outBuf_;
    int outLen_;
    std::string output_;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<PImpl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;
CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
