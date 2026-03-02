#include "crypto_guard_ctx.h"

#include <memory>

namespace CryptoGuard {

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(nullptr) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;
CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

}  // namespace CryptoGuard
