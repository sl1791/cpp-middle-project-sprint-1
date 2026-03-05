#include "cmd_options.h"

#include <iostream>

namespace CryptoGuard {
namespace po = boost::program_options;
ProgramOptions::ProgramOptions() : command_(), desc_("Allowed options") {
    desc_.add_options()("help", "показать все поддерживаемые команды")("command", po::value<std::string>(),
                                                                       "команда encrypt, decrypt или checksum")(
        "input", po::value<std::string>(), "путь до входного файла")("output", po::value<std::string>(),
                                                                     "путь до файла, где будет сохранен результат")(
        "password", po::value<std::string>(), "пароль для шифрования и дешифрования");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map commandMap;
    po::store(parse_command_line(argc, argv, desc_), commandMap);
    po::notify(commandMap);

    // Обработка --help
    if (commandMap.contains("help")) {
        std::cout << desc_ << std::endl;
        std::exit(0);
    }

    // Проверка и обработка --command
    if (commandMap.contains("command")) {
        const auto &command = commandMap["command"].as<std::string>();
        if (auto it = commandMapping_.find(command); it != commandMapping_.end()) {
            command_ = it->second;
        } else {
            throw std::runtime_error("Неизвестная команда: " + command +
                                     ". Допустимые значения: encrypt, decrypt, checksum");
        }
    }

    // Проверка и обработка --input
    if (commandMap.contains("input")) {
        inputFile_ = commandMap["input"].as<std::string>();
    }

    // Проверка и обработка --output
    if (commandMap.contains("output")) {
        outputFile_ = commandMap["output"].as<std::string>();
    }

    // Проверка и обработка --password
    if (commandMap.contains("password")) {
        password_ = commandMap["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard
