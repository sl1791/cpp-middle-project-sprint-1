#include "crypto_guard_ctx.h"

#include <memory>

namespace CryptoGuard {

class CryptoGuardCtx::PImpl {
public:
    PImpl() = default;
    ~PImpl() = default;

    PImpl(const PImpl &) = delete;
    PImpl &operator=(const PImpl &) = delete;
    PImpl(PImpl &&) = delete;
    PImpl &operator=(PImpl &&) = delete;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(nullptr) {}
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
