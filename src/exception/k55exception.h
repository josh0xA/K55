/* Copyright (C) 2021 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

#include <exception>

namespace exception {
    /**
    * @brief K55Exception Class
    * Used to throw exceptions rather than std::cerr
    */

    class K55Exception : public std::exception {
    public:
      K55Exception(const char* const message) : __errmessage__{message} {};

      const char* what() const noexcept { return __errmessage__; }
    private:
      const char* __errmessage__;
    };

}
