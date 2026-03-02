#include "cmd_options.h"

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
        ("help", "показать все поддерживаемые команды")
        ("command", boost::program_options::value<std::string>(), "команда encrypt, decrypt или checksum")
        ("input", boost::program_options::value<std::string>(), "путь до входного файла")
        ("output", boost::program_options::value<std::string>(), "путь до файла, где будет сохранен результат")
        ("password", boost::program_options::value<std::string>(), "пароль для шифрования и дешифрова")
    ;
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {}

}  // namespace CryptoGuard
