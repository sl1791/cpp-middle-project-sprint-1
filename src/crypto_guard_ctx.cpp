#include "crypto_guard_ctx.h"

#include <array>
#include <iomanip>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <print>
#include <sstream>
#include <vector>

namespace {
std::string getOpenSSLErrorMessage(std::string_view prefix) {
    std::array<char, 256> buf{};
    const unsigned long err = ERR_get_error();
    ERR_error_string_n(err, buf.data(), sizeof(buf));
    return std::format("{}: {} (OpenSSL error: {})", prefix, buf, err);
}
}  // namespace

namespace CryptoGuard {
struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt{};                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key{};  // Encryption key
    std::array<unsigned char, IV_SIZE> iv{};    // Initialization vector
};

class CryptoGuardCtx::PImpl {
    using Unique_ptr_EVP_CIPHER_CTX =
        std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ptr) { EVP_CIPHER_CTX_free(ptr); })>;

    using Unique_ptr_EVP_MD_CTX = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *ptr) { EVP_MD_CTX_free(ptr); })>;

public:
    PImpl() : ctx_(Unique_ptr_EVP_CIPHER_CTX(EVP_CIPHER_CTX_new())), mdctx_(Unique_ptr_EVP_MD_CTX(EVP_MD_CTX_new())) {
        if (!ctx_ || !mdctx_) {
            throw std::runtime_error(getOpenSSLErrorMessage(
                "CryptoGuardCtx::PImpl::PImpl: не удалось инициализировать контексты Cipher и/или MD"));
        }
    }

    ~PImpl() = default;

    PImpl(const PImpl &) = delete;

    PImpl &operator=(const PImpl &) = delete;

    PImpl(PImpl &&) = delete;

    PImpl &operator=(PImpl &&) = delete;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        performCrypto(inStream, outStream, password, true);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        performCrypto(inStream, outStream, password, false);
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream.good()) {
            throw std::runtime_error("CryptoGuardCtx::PImpl::CalculateChecksum: Входной поток не в валидном состоянии");
        }

        const auto md = std::unique_ptr<const EVP_MD, decltype([](auto ptr) {})>(EVP_sha256());
        if (!md) {
            throw std::runtime_error("CryptoGuardCtx::PImpl::CalculateChecksum: вызов EVP_sha256 закончился неудачей");
        }

        if (EVP_DigestInit_ex(mdctx_.get(), md.get(), nullptr) != 1) {
            throw std::runtime_error(getOpenSSLErrorMessage(
                "CryptoGuardCtx::PImpl::CalculateChecksum: вызов EVP_DigestInit_ex закончился неудачей"));
        }

        constexpr std::size_t kChunkSize = 64 * 1024;
        std::vector<unsigned char> buffer(kChunkSize);

        while (true) {
            inStream.read(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));

            if (const auto bytesRead = inStream.gcount(); bytesRead > 0) {
                if (EVP_DigestUpdate(mdctx_.get(), buffer.data(), static_cast<size_t>(bytesRead)) != 1) {
                    throw std::runtime_error(getOpenSSLErrorMessage(
                        "CryptoGuardCtx::PImpl::CalculateChecksum: вызов EVP_DigestUpdate закончился неудачей"));
                }
            }

            if (inStream.eof()) {
                break;
            }

            if (!inStream.good()) {
                throw std::runtime_error("CryptoGuardCtx::PImpl::CalculateChecksum: Входной поток оказался не в "
                                         "валидном состоянии при чтении очередного блока данных");
            }
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> md_value{};
        unsigned int md_len = 0;

        if (EVP_DigestFinal_ex(mdctx_.get(), md_value.data(), &md_len) != 1) {
            throw std::runtime_error(getOpenSSLErrorMessage(
                "CryptoGuardCtx::PImpl::CalculateChecksum: вызов EVP_DigestFinal_ex закончился неудачей"));
        }

        std::stringstream ss;
        for (unsigned int i = 0; i < md_len; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(md_value[i]);
        }

        return ss.str();
    }

private:
    void performCrypto(std::iostream &inStream, std::iostream &outStream, std::string_view password, bool encrypt) {
        const std::string opName = encrypt ? "EncryptFile" : "DecryptFile";
        if (!inStream.good()) {
            throw std::runtime_error("CryptoGuardCtx::PImpl::" + opName + ": Входной поток не в валидном состоянии");
        }
        if (!outStream.good()) {
            throw std::runtime_error("CryptoGuardCtx::PImpl::" + opName + ": Выходной поток не в валидном состоянии");
        }
        auto [cipher, encFlag, key, iv] = createCipherParamsFromPassword(password);
        encFlag = encrypt ? 1 : 0;

        if (EVP_CipherInit_ex(ctx_.get(), cipher, nullptr, key.data(), iv.data(), encFlag) != 1) {
            throw std::runtime_error(getOpenSSLErrorMessage("CryptoGuardCtx::PImpl::" + opName +
                                                            ": вызов EVP_CipherInit_ex закончился неудачей"));
        }

        constexpr std::size_t kChunkSize = 64 * 1024;
        std::vector<unsigned char> inBuf(kChunkSize);
        std::vector<unsigned char> outBuf(kChunkSize + EVP_MAX_BLOCK_LENGTH);

        while (true) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), static_cast<std::streamsize>(inBuf.size()));

            if (const auto bytesRead = inStream.gcount(); bytesRead > 0) {
                int outLen = 0;
                if (EVP_CipherUpdate(ctx_.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead)) !=
                    1) {
                    throw std::runtime_error(getOpenSSLErrorMessage("CryptoGuardCtx::PImpl::" + opName +
                                                                    ": вызов EVP_CipherUpdate закончился неудачей"));
                }

                outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
                if (!outStream.good()) {
                    throw std::runtime_error("CryptoGuardCtx::PImpl::" + opName +
                                             ": Выходной поток оказался не в валидном "
                                             "состоянии при записи блока данных");
                }
            }

            if (inStream.eof()) {
                break;
            }
            if (!inStream.good()) {
                throw std::runtime_error("CryptoGuardCtx::PImpl::" + opName +
                                         ": Входной поток оказался не в валидном "
                                         "состоянии при очередном чтении блока данных из файла");
            }
        }

        int finalLen = 0;
        if (EVP_CipherFinal_ex(ctx_.get(), outBuf.data(), &finalLen) != 1) {
            throw std::runtime_error(getOpenSSLErrorMessage("CryptoGuardCtx::PImpl::" + opName +
                                                            ": вызов EVP_CipherFinal_ex закончился неудачей"));
        }

        outStream.write(reinterpret_cast<const char *>(outBuf.data()), finalLen);
        if (!outStream.good()) {
            throw std::runtime_error("CryptoGuardCtx::PImpl::" + opName +
                                     ": Выходной поток оказался не в валидном "
                                     "состоянии при записи финального блока данных");
        }
    }

    static AesCipherParams createCipherParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        const int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                          reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                          params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{getOpenSSLErrorMessage("Failed to create a key from password")};
        }

        return params;
    }

    const Unique_ptr_EVP_CIPHER_CTX ctx_;
    const Unique_ptr_EVP_MD_CTX mdctx_;
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
