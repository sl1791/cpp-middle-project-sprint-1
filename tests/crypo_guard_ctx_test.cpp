#include <gtest/gtest.h>
#include <crypto_guard_ctx.h>
#include <print>
#include <fstream>

static const char textForEncription[] = "this is an example of text for encryption";
static const char password[] = "sinecura";
const char encryptedText[] = {
    "E\x9A\xCD\0\x88\x7F\xE1\x87\"\x91 \x14t1\xAF~[sIs_\xE7\xDF\xC5\xEC\xCF"
    "bG\xB2\xCE\xEBr\xE3#\xA9"
    "2\xAD\xF5\xB0\xEA\x87}#\xDDX\x7F\v\xD8"
};
const char encryptedEmptyText[] = {
    "O\x12j\xC8H\xF\x85zpk\xCC^\x9E\xA7" 
    "F\x87"
};

const char encryptedTextNoPwd[] = {
    "\xBETI\x11\xB5\xE1\xAF-\x89\xB3\x11y\x1A\xC8\xDC\xAA+y"
    "\xC7\xFE$E\xBB\a\xFA\x19\xB6\b\xC4}\x1\xA0\xC4\t\xFC\xE3\xCEo"
    "\xF7\xE7\xB7)\t\xF0\xAE\xAET="        
};

///////////////////////////////////////////////////////////////////////////////////////////////
TEST(CryptoGuardCtx, Encrypt) 
{ 
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream input;
    input << textForEncription;
    std::stringstream output;
    cryptoCtx.EncryptFile(input, output, password);
    std::string res(encryptedText, sizeof(encryptedText)-1);  
    EXPECT_EQ(output.str(), res); 
}

TEST(CryptoGuardCtx, EncryptEmptyInput) 
{ 
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream input;
    std::stringstream output;
    cryptoCtx.EncryptFile(input, output, password);
    std::string res(encryptedEmptyText, sizeof(encryptedEmptyText)-1);  
    EXPECT_EQ(output.str(), res); 
}

TEST(CryptoGuardCtx, EncryptEmptyPwd) 
{ 
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream input;
    input << textForEncription;
    std::stringstream output;
    cryptoCtx.EncryptFile(input, output, "");
    std::string res(encryptedTextNoPwd, sizeof(encryptedTextNoPwd)-1);  
    EXPECT_EQ(output.str(), res); 
}

TEST(CryptoGuardCtx, EncryptAssert) 
{ 
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream input;
    input << "this is an example of text for encryption";
    const char* pwd = "sinecura";
    std::stringstream output;
    output.setstate(std::ios_base::failbit);
    ASSERT_THROW(cryptoCtx.EncryptFile(input, output, pwd), std::runtime_error);
}
