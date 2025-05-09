#include <sstream>
#include <algorithm>
#include "web.hpp"

inline void closeWeb(URLSession session)
{
    session.CloseSession();
}

inline std::vector<std::string> splitLines(const std::string& data)
{
    std::vector<std::string> lines;
    std::istringstream stream(data);
    std::string line;
    while (std::getline(stream, line))
    {
        lines.push_back(line);
    }

    return lines;
}

inline std::vector<std::string> extractLines(const std::vector<std::string>& lines, const std::string& word)
{
    std::vector<std::string> results;
    for (const auto& line : lines)
    {
        size_t pos = line.find(word);
        if (pos != std::string::npos)
            results.push_back(line.substr(pos + word.length()));

    }
    return results;
}

uintptr_t getAddress(URLSession session, const std::string& addrName, int url)
{
    std::string uRL = xorstr_("https://raw.githubusercontent.com/a2x/cs2-dumper/refs/heads/main/output");

    if (url == 1)
        uRL += xorstr_("/offsets.hpp");
    else if (url == 2)
        uRL += xorstr_("/client_dll.hpp");

    if (!session.OpenSession())
        std::cout << xorstr_("Failed to open session.") << std::endl;

    if (!session.OpenURL(uRL))
        std::cout << xorstr_("Failed to open URL.") << std::endl;

    std::vector<std::string> lines = splitLines(session.ReadContent());
    std::vector<std::string> results = extractLines(lines, addrName);

    for (const auto& result : results) {
        std::string str1 = ReplaceAll(result, "=", "");
        str1 = ReplaceAll(str1, ";", "");

        uintptr_t value = static_cast<uintptr_t>(std::stoull(str1, nullptr, 16));
        return value;
    }

    return 0;
}