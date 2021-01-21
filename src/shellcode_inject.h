/* Copyright (C) 2021 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

#include "config.h"

#define KERNEL_VERSION_SPACE 16
#define PROCESS_ID_MAX_STRING_LENGTH 64

// SCI - "Shell-code injection"
namespace SCI {

  typedef struct extension {
    long address;
    char* permissions;
  } extension, *pextension;

  typedef struct ptruths {
    bool r_xp = false;
    bool non_rxp = false;

  } ptruths;

  class Kernel {
  public:
    /*
    Gathers machine architecture from a C uname() call
    @param - null
    @return char*
    */
    char* retrieve_machine_architecture();
    /*
    Gathers kernel information from a utsbuffer
    @param - null
    @return bool
    */
    bool retrieve_system_kernel_information();

  private:
    struct utsname utsbuffer;
    long version_buffer[KERNEL_VERSION_SPACE];
    int v_counter = 0;

  protected:
    cfg::_K55_STATE_BOUND default_status;
  }; // class Kernel

  template <typename _k55_type>
  class Process : protected Kernel {
  public:
    /*
    Return the maxium possible process ID number for either x86 or
      x86_64
    @param - proc:default - true
    @return k55_process
    */
    k55_process return_maximum_process_id(_k55_type proc);
    /*
    Retrieves code exec flags from the file map: looking for r-xp
    @param - process_line (char*)
    @return char*
    */
    _k55_type* return_file_permissions(_k55_type* process_line);

  private:
    std::ifstream process_id_file;

    long max_process_id;

    std::string line;

    int process_space_a = -1;
    int process_space_b = -1;


  }; // class Process

  template <typename _k55_type>
  class Parser : protected Kernel {
  public:
    /*
    Gathers memory address of the code execution flag/perm
    @param - line (char*)
    @return long
    */
    long retrieve_memory_address(_k55_type* line);
    /*
    Parse the /proc/ID/maps directory of the process
    @param - target_process_identifier (long)
    @return long
    */
    _k55_type parse_process_id_maps(_k55_type target_process_identifier);

  private:
    int addr_last_occurance_line_index = -1;

    std::string addr_line, maps_f_name_path;

    std::size_t name_length_file, maps_line_length;

    _k55_type* maps_line = NULL;
    // TODO: Implement std::ifstream with std::getline rather than, C-style getline
    FILE* maps_file;

  }; // class Parser

  class Injector : protected Kernel {
  public:
    /*
    Injects __shellcode__ (the payload) into targets address space
    @param - target_process_identifier (long)
    @return bool
    */
    bool proc_inject(long target_process_identifier);
  private:
    struct user_regs_struct old_regs, regs;

    std::size_t payload_shell_size;

    uint64_t* final_payload;


  }; // class Injector

} // namespace SCI
