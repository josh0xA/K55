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

int main(void) {
  Kernel kn;
  Injector inj;
  Utility utl;

  long proc_id;

  std::cout << "---------------------------------------------------\n";
  if (!kn.retrieve_system_kernel_information()) {
    std::cerr << "Cannot Return Kernel Information\n";
    return K55_STANDARD_ERROR_CODE;
  }
  std::cout << "---------------------------------------------------\n";
  // Error handling already heavily implemented within proc_inject(long)
  if (proc_id = utl.get_process_id_by_name("k55_test_process")) {
    inj.proc_inject(proc_id);
  }


}
