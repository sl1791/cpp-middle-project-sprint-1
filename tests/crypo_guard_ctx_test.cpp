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

static const char longText[] = 
"Мои курсы"
"Подарок за друга"
""
"Задание"
"Ревью"
"Финальный проект модуля — разработка криптографического приложения"
"Поздравляем, вы изучили тему «Управление памятью и ресурсами». Чтобы проверить полученные знания на практике, предлагаем вам выполнить проектную работу, в процессе которой вам предстоит:"
"Разработать и протестировать:"
"библиотеку CryptoGuard на основе OpenSSL;"
"приложение, которое с помощью этой библиотеки выполняет основные криптографические операции: шифрование, дешифрование и подсчёт контрольной суммы."
"Разобраться с библиотекой Boost.ProgramOptions для обработки аргументов командной строки."
"Покрыть тестами каждую из функций библиотеки CryptoGuard с помощью фреймворка GTest."
"Прежде чем разрабатывать библиотеку CryptoGuard, познакомьтесь с основами шифрования. Эти знания пригодятся вам и в дальнейшем, ведь криптографические алгоритмы применяются повсеместно: для защиты данных в HTTPS и VPN, для хеширования паролей, в банковских транзакциях и шифровании файлов."
"Ссылки на необходимые материалы вы найдёте в плане реализации проекта."
"План реализации проекта CryptoGuard"
"Подготовьтесь к работе:"
"Откройте шаблон проекта CryptoGuard."
"Выполните инструкции в разделе «Начало работы»."
"Соберите проект и запустите приложение по шагам в разделе «Сборка проекта и запуск тестов»."
"Разработайте класс ProgramOptions:"
"Изучите документацию о классе boost::program_options по ссылкам:"
"https://www.boost.org/doc/libs/1_63_0/doc/html/program_options.html;"
"https://www.boost.org/doc/libs/1_63_0/doc/html/program_options/tutorial.html."
"Реализуйте конструктор, который настроит парсер командной строки с помощью boost::program_options для следующих опций:"
"help — список доступных опций;"
"command — команда encrypt, decrypt или checksum;"
"input — путь до входного файла;"
"output — путь до файла, в котором будет сохранён результат;"
"password — пароль для шифрования и дешифрования."
"Добавьте обработку перечисленных опций с соответствующими параметрами (например, входные и выходные данные для шифрования файла) и их проверку."
"Реализуйте маппинг строковых команд на enum COMMAND_TYPE."
"Добавьте вызов метода Parse(), который в случае ошибки будет выводить сообщение об ошибке, а при выборе help — список доступных опций."
"Протестируйте класс ProgramOptions:"
"В папку tests добавьте файл cmd_options_test.cpp, а в группе ProgramOptions (TEST(ProgramOptions, TestName)) реализуйте не меньше шести различных тестов."
"Проверьте, правильно ли класс ProgramOptions обрабатывает параметры командной строки."
"Разработайте класс CryptoGuardCtx с использованием PImpl:"
"Проанализируйте файл crypto_guard_ctx.h и примените идиому PImpl, скрыв реализацию интерфейса (cами функции пока оставьте пустыми)."
"Реализуйте класс CryptoGuardCtx::PImpl."
"Замените использование сырого указателя PImpl* на современное решение, которое вы изучили в этом модуле."
"Напишите правильную реализацию всех специальных методов класса CryptoGuardCtx в соответствии с идиомой PImpl."
"Переместите реализацию API (интерфейсных функций программы) в cpp-файл."
"Разработайте структуру класса CryptoGuardCtx::PImpl:"
"Переместите структуру AesCipherParams в cpp-файл."
"Переместите функцию CreateChiperParamsFromPassword внутрь реализации CryptoGuardCtx::PImpl."
"В соответствии с идиомой PImpl создайте в классе CryptoGuardCtx::PImpl API-функции, аналогичные имеющимся в классе CryptoGuardCtx, но не реализовывайте их."
"В конструктор и деструктор класса поместите функции инициализации EVP из main."
"Изучите тему шифрования:"
"Прочтите статью о разнице между кодированием и шифрованием в журнале Яндекс Практикума."
"Прочтите статью о симметричном шифровании."
"Прочтите статью об асимметричном шифровании."
"Реализуйте метод Encrypt:"
"Добавьте проверку состояния входного и выходного потоков перед шифрованием."
"Создайте криптографический контекст с помощью умных указателей и пользовательского «удалителя»."
"Реализуйте шифрование аналогично примеру с функцией main и примерам с функцией do_crypt."
"В процессе работы с OpenSSL-функцией Update реализуйте проверку состояния входных и выходных потоков."
"C помощью GTest реализуйте как минимум три теста для проверки функции Encrypt, используя std::stringstream вместо файлов. Хотя бы одна из функций должна использовать ASSERT_THROW."
"Реализуйте метод Decrypt:"
"Реализуйте метод Decrypt аналогично методу Encrypt."
"С помощью GTest реализуйте как минимум три теста для проверки функции Decrypt, используя std::stringstream вместо файлов. Хотя бы одна из функций должна использовать ASSERT_THROW."
"Разработайте метод CalculateChecksum:"
"Прочтите в журнале Яндекс Практикума статью о том, что такое контрольная сумма (checksum)."
"Прочтите на Хабре статью об алгоритмах безопасного хеширования SHA6."
"Инициализируйте хеш-контекст с алгоритмом SHA-256 с помощью EVP_MD_CTX, умных указателей и пользовательского «удалителя»."
"Реализуйте подсчёт контрольной суммы аналогично примеру с функцией main."
"В процессе работы с OpenSSL-функцией Update реализуйте проверку состояния входных и выходных потоков."
"Преобразуйте результат хеширования в шестнадцатеричную строку c помощью std::stringstream и std::hex."
"С помощью GTest реализуйте как минимум два теста для проверки функции CalculateChecksum, используя std::stringstream вместо файлов."
"Улучшите обработку ошибок:"
"Добавьте детальную обработку ошибок OpenSSL с помощью ERR_get_error()."
"Реализуйте обработку ошибок с помощью информативных исключений типа std::runtime_error."
"Обеспечьте корректное освобождение ресурсов OpenSSL в любых сценариях."
"Финализируйте работу:"
"Протестируйте каждый метод на корректность шифрования/дешифрования."
"Проверьте вычисление контрольной суммы до шифрования и после шифрования+дешифрования."
"Убедитесь в правильной обработке пограничных случаев и ошибочных сценариев."
"Требования к результатам работы для студента"
"Общие требования к проекту"
"Должно быть создано криптографическое приложение для шифрования, дешифрования и подсчёта контрольной суммы файлов."
"В разработке должны применяться современные возможности C++, изученные идиомы, практики организации кода, библиотеки OpenSSL, Boost и GTest."
"Система должна надёжно и безопасно работать с файлами."
"Ключевые функциональные требования"
"В системе должны быть реализованы:"
"Возможность шифрования файлов с помощью пароля."
"Возможность дешифрования ранее зашифрованных файлов."
"Подсчёт контрольной суммы файлов с помощью SHA-256."
"Обработка различных сценариев использования через командную строку."
"Технические требования"
"В системе должны применяться:"
"Идиома PImpl для инкапсуляции реализации."
"Корректная обработка ошибок и исключительных ситуаций."
"Unit-тесты для проверки функциональности."
"Умные указатели для управления памятью."
"Чек-лист"
"Обязательные требования"
"Реализация обработки командной строки"
"Использована библиотека Boost.ProgramOptions."
"Поддержаны все требуемые аргументы: help, command, input, output, password."
"Криптографическая функциональность"
"Реализован метод шифрования файлов."
"Реализован метод дешифрования файлов."
"Реализован метод подсчёта контрольной суммы."
"Применён алгоритм SHA-256 для подсчёта контрольной суммы."
"Обработка ошибок и безопасность"
"Корректная обработка ошибок открытия/закрытия файлов."
"Корректное освобождение ресурсов OpenSSL."
"Защита от некорректного ввода данных."
"Архитектура и код"
"Применена идиома PImpl в любой форме."
"Использованы умные указатели."
"Отсутствуют утечки памяти."
"Тестирование"
"Написан хотя бы один из шести unit-тестов для обработчика командной строки."
"Написано хотя бы три unit-теста — по одному на каждый криптографических метод."
"Тесты для криптографических методов работают с std::stringstream, а не с файлами."
"Тесты покрывают основные сценарии использования."
"Опциональные требования"
"Реализация обработки командной строки"
"Всевозможные комбинации аргументов командной строки обрабатываются корректно."
"Обработка ошибок и безопасность"
"Использование информативных исключений."
"Архитектура и код"
"Применена идиома PImpl и propagate_const<std::unique_ptr>."
"Код соответствует современным стандартам C++"
"Тестирование"
"Написано не меньше шести unit-тестов для обработчика командной строки."
"Написано не меньше семи unit-тестов для криптографических методов."
"Тесты покрывают основные сценарии использования."
"Есть тесты на проверку выбрасывания исключений."
"Сдача работы на ревью"
"После выполнения проекта вам необходимо будет сдать работу на ревью. Ниже подробная инструкция о том, как это сделать."
"GitHub"
"Сделайте ваш репозиторий с проектом на GitHub публичным. В репозитории должна отображаться вся история коммитов в Git."
"Создайте Pull Request в вашем репозитории из ветки development в ветку main."
"Платформа"
"Чтобы отправить Pull Request на ревью:"
"Кликните на вкладку «Ревью». Там вы увидите форму для отправки ссылки."
"Форма для отправки"
"Вставьте ссылку на ваш Pull Request (PR)."
"PR"
"Нажмите «Отправить». Работа отправится на проверку."
"Кнопка «Отправить»"
"Примерно через час начнёт отображаться время отправки."
"Время отправки"
"Когда ревьюер приступит к проверке, это отобразится в интерфейсе формы."
"Интерфейс формы"
"Если у ревьюера будут замечания по коду, он оставит комментарии и отправит код на доработку."
"Есть замечания"
"Вы можете задавать вопросы в чате когорты — скорее всего, ответы будут полезны и другим студентам. "
"После того как вы исправите код с учётом комментариев ревьюера, не забудьте закоммитить изменения. Новый коммит появится в Pull Request, и вы сможете отправить работу на повторную проверку."
"Внимание! Для повторного ревью нужно снова отправить ссылку на PR через эту форму. Только так ревьюер узнает, что вы закоммитили изменения. Иначе он не увидит вашу работу в списке ожидающих проверки."
"Если комментариев у ревьюера больше нет, работа будет засчитана, а спринт пройден. Это отобразится в интерфейсе Практикума."
"Работа засчитана"
""
"Сдать работу"
"Вперёд";

static const char textForEncriptionChecksum[] = "1fbb970d3fe44662473572a0f91bf5a8c11832de0c0893064ea69a7a9fbdf9ec";
static const char longTextChecksum[] = "d3185e137ecb37911918d81144348cd892ca717f0f2eb32d4b266ef4416ea754";

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

TEST(CryptoGuardCtx, Decrypt) 
{ 
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream input;
    input << std::string(encryptedText, sizeof(encryptedText)-1);  
    std::stringstream output;
    cryptoCtx.DecryptFile(input, output, password);
    std::string res(textForEncription, sizeof(textForEncription)-1);  
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

TEST(CryptoGuardCtx, DecryptEmptyInput) 
{ 
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream input;
    input << std::string (encryptedEmptyText, sizeof(encryptedEmptyText)-1);
    std::stringstream output;
    cryptoCtx.DecryptFile(input, output, password);
    EXPECT_EQ(output.str(), ""); 
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

TEST(CryptoGuardCtx, DecryptEmptyPwd) 
{ 
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream input;
    input << std::string(encryptedTextNoPwd, sizeof(encryptedTextNoPwd)-1);
    std::stringstream output;
    cryptoCtx.DecryptFile(input, output, "");
    EXPECT_EQ(output.str(), textForEncription); 
}

TEST(CryptoGuardCtx, EncryptAssert) 
{ 
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream input;
    input << textForEncription;
    std::stringstream output;
    output.setstate(std::ios_base::failbit);
    ASSERT_THROW(cryptoCtx.EncryptFile(input, output, password), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptAssert) 
{ 
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream input;
    input << std::string(encryptedText, sizeof(encryptedText)-1);  
    std::stringstream output;
    output.setstate(std::ios_base::failbit);
    ASSERT_THROW(cryptoCtx.DecryptFile(input, output, password), std::runtime_error);
}

TEST(CryptoGuardCtx, CalculateChecksum)
{ 
    std::stringstream input;
    input << textForEncription;  
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_EQ(textForEncriptionChecksum, cryptoCtx.CalculateChecksum(input));
}

TEST(CryptoGuardCtx, CmpChecksum)
{
    std::stringstream input2;
    input2 << textForEncription << "!";

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::string newChecksum = cryptoCtx.CalculateChecksum(input2);
    EXPECT_EQ(64, newChecksum.size());
    EXPECT_NE(textForEncriptionChecksum, newChecksum);
    std::string substr(textForEncriptionChecksum, textForEncriptionChecksum + 3);
    EXPECT_NE(substr, newChecksum.substr(0, 3));
}

TEST(CryptoGuardCtx, CalculateLongChecksum)
{ 
    std::stringstream input;
    input << longText;
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_EQ(longTextChecksum, cryptoCtx.CalculateChecksum(input));
}

TEST(CryptoGuardCtx, CmpLongChecksum)
{
    std::stringstream input2;
    input2 << longText << "!";

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::string newChecksum = cryptoCtx.CalculateChecksum(input2);
    EXPECT_EQ(64, newChecksum.size());
    EXPECT_NE(longTextChecksum, newChecksum);
    std::string substr(longTextChecksum, longTextChecksum + 3);
    EXPECT_NE(substr, newChecksum.substr(0, 3));
}