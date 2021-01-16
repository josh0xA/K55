/* Copyright (C) 2021 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

#pragma once

#ifndef UTILITY_H
#define UTILITY_H

#include "config.h"

namespace UTL {
  class Utility {

  private:
    k55_process process_id;
    k55_process casual_id;

    k55_system_dir process_directory;
    std::string command_path, command_line;

    struct dirent* dir_p;
    struct stat sts;

  public:
    /*
    Retrieves process id from name of program
    @param - process_name (std::string)
    @return k55_process
    */
    k55_process get_process_id_by_name(const std::string& process_name);

    /*
    Gathers machine architecture from a C uname() call
    @param - target_id (k55_process)
    @return bool
    */
    bool is_process_id_alive(k55_process target_id);


    k55_process proc_id;

  protected:
    _K55_STATE_BOUND default_status;


  }; // class Utility

  class User {
  public:
    bool root_privileges();
  };

} // namespace UTL

#endif
