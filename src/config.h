/* Copyright (C) 2021 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

#pragma once

#ifndef CONFIG_H
#define CONFIG_H

#include "include.h"

#define K55_STANDARD_SUCCESS_CODE 0
#define K55_STANDARD_ERROR_CODE -1

#define K55_MAX_STRING_LEN 2048

#define K55_MIN_ARGUMENT_COUNT 2

#define SET_DEBUG_VALUE(s_val, k_val) ((s_val) = (k_val))

#define X86_64_MAX_PROCESS_ID_VALUE 4194304
#define X86_MAX_PROCESS_ID_VALUE 32768

typedef char* n_buffer;
typedef long k55_process;
typedef short k55_short_process;
typedef DIR *k55_system_dir;

inline bool k55_success_on_return_value(bool s_value) {
  /*
   For univeral conditional use if true
   @param bool, value to test
   @return bool
  */
  return (s_value == true);
}

inline bool k55_error_on_return_value(bool s_value) {
  /*
    For universal conditional use if false
    @param bool, value to test
    @return bool
  */
  return (s_value == false);
}

typedef enum _K55_STATE_BOUND
{
  n_invalid_var_any = -1,

  n_success_state,

  __n_get_proc_id_fatal__,

  __n_process_non_existent__,

  __n_read_directory_fatal__,

  __n_value_parse_fatal__,

  __n_get_line_permissions_fatal__,

  __n_heap_alloc_fatal__,

  __n_snprintf_fatal__,

  __n_file_map_parser_fatal__,

  __n_get_addr_fatal__,

  __n_ptrace_attach_fatal__,

  __n_ptrace_poketext_fatal__,

  __n_copy_memory_fatal__,

  __n_get_registers_fatal__,

  __n_set_registers_fatal__,

  __n_ptrace_cont_syscall_fatal__,

} K55_STATE_BOUND, *P_K55_STATE_BOUND;


#endif
