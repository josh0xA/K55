/* Copyright (C) 2021 Josh Schiavone - All Rights Reserved
 * You may use, distribute and modify this code under the
 * terms of the MIT license, which unfortunately won't be
 * written for another century.
 *
 * You should have received a copy of the MIT license with
 * this file. If not, visit : https://opensource.org/licenses/MIT
 */

 #include "utility.h"

 bool UTL::User::root_privileges() {
   if (getuid()) { return false; }
   else { return true; }
 }

 k55_process UTL::Utility::get_process_id_by_name(const std::string& process_name)
 {
   default_status = cfg::n_invalid_var_any;

   process_directory = opendir("/proc");
   process_id = K55_STANDARD_ERROR_CODE;

   if (process_directory != NULL) {

     while (process_id < 0 && (dir_p = readdir(process_directory))) {
       casual_id = std::atoi(dir_p->d_name);

       if (casual_id > K55_STANDARD_SUCCESS_CODE) {
         command_path = std::string("/proc/") + dir_p->d_name + "/cmdline";
         std::ifstream command_file(command_path.c_str());
         std::getline(command_file, command_line);

         if (cfg::k55_error_on_return_value(command_line.empty())) {
           std::size_t position = command_line.find('\0');

           if (position != std::string::npos)
             command_line = command_line.substr(0, position);
           // Only remove the path
           position = command_line.rfind('/');
           if (position != std::string::npos)
             command_line = command_line.substr(position + 1);

           if (process_name == command_line)
             process_id = casual_id;
         }

       }
     }
   } else {
     SET_DEBUG_VALUE(default_status, cfg::__n_get_proc_id_fatal__);
     return default_status;
   }
   if (closedir(process_directory)) { throw std::runtime_error(std::strerror(errno)); }
   return process_id;
}

bool UTL::Utility::is_process_id_alive(k55_process target_id) {
  default_status = cfg::n_invalid_var_any;
  std::string formatter = std::string("/proc/") + std::to_string(target_id);
  if (formatter.find('-') != std::string::npos) {
    if (stat(formatter.c_str(), &sts) == K55_STANDARD_ERROR_CODE && errno == ENOENT)
      SET_DEBUG_VALUE(default_status, cfg::__n_process_non_existent__);
      return false;
  }
  return true;
}
