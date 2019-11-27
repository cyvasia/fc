/* (c) 2016, 2017 DECENT Services. For details refers to LICENSE.txt */
/*
* Copyright (c) 2015 Cryptonomex, Inc., and contributors.
*
* The MIT License
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/

#include <fc/monitoring.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/io/json.hpp>

#include <algorithm>
#include <fstream>

namespace monitoring {

   std::set<monitoring_counters_base*> monitoring_counters_base::registered_instances;
   std::mutex monitoring_counters_base::registered_instances_mutex;
   std::thread* monitoring_counters_base::_monitoring_thread = nullptr;
   bool monitoring_counters_base::_end_thread = false;
   std::condition_variable monitoring_counters_base::cv;
   std::mutex  monitoring_counters_base::wait_mutex;
   std::vector<counter_item> monitoring_counters_base::_initializing_cache;
   bool monitoring_counters_base::_cache_is_loaded = false;
   std::vector<counter_item> monitoring_counters_base::_pending_save;

   static fc::path monitoring_path;

   void set_data_dir(const fc::path &data_dir)
   {
      monitoring_path = data_dir / "monitoring";
      fc::create_directories(monitoring_path);
      monitoring_path = monitoring_path / "counters.json";
   }

   void monitoring::monitoring_counters_base::save_to_disk(const std::vector<counter_item>& counters)
   {
      std::fstream fs;
      fs.open(monitoring_path.string().c_str(), std::fstream::out);
      if (fs.is_open()) {

         fc::variant tmp;
         fc::to_variant(counters, tmp);
         std::string s = fc::json::to_string(tmp);

         fs.write(s.c_str(), s.size());
      }
   }

   void monitoring::monitoring_counters_base::read_from_disk(std::vector<counter_item>& counters)
   {
      std::fstream fs;
      fs.open(monitoring_path.string().c_str(), std::fstream::in);
      if (fs.is_open()) {

         std::string s;
         fs.seekg(0, std::ios::end);
         s.reserve(fs.tellg());
         fs.seekg(0, std::ios::beg);

         s.assign((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());

         fc::variant tmp = fc::json::from_string(s);
         fc::from_variant(tmp, counters);
      }
   }

   void monitoring_counters_base::store_counters()
   {
      try {
         std::vector<counter_item> result;
         std::for_each(registered_instances.begin(), registered_instances.end(), [&](const monitoring_counters_base* this_ptr) {
            const std::vector<std::string> names;

            this_ptr->get_local_counters(names, result, true);
         });

         if (_pending_save.size()) {
            result.insert(result.end(), _pending_save.begin(), _pending_save.end());
            _pending_save.clear();
         }

         save_to_disk(result);
      }
      catch (...) {
         // not clean if to handle this exceptions
      }
   }

   // We know path to data_dir after command line parameters are processed but some class instances can exists at that moment
   // so we need explicitly to initialize them
   void monitoring_counters_base::initialize_existing_instances()
   {
      std::set<monitoring_counters_base*>::iterator existing_iter;
      std::lock_guard<std::mutex> lock(monitoring_counters_base::registered_instances_mutex);
      std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();

      for (existing_iter = registered_instances.begin(); existing_iter != registered_instances.end(); ++existing_iter)
      {
         if ((*existing_iter)->_counters_initialized == false) {
            monitoring::counter_item* it = (*existing_iter)->get_first_counter();

            for (int i = 0; i < (*existing_iter)->get_counters_size(); i++) {
               if (it->persistent) {
                  std::vector<monitoring::counter_item>::iterator iter;
                  for (iter = _initializing_cache.begin(); iter != _initializing_cache.end(); ++iter) {
                     if ((*iter).name == it->name) {
                        (*it) = (*iter);
                        break;
                     }
                  }
               }
               else {
                  it->last_reset = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
               }

               it++;
            }
            (*existing_iter)->_counters_initialized = true;
         }
      }
   }

   void monitoring_counters_base::monitoring_thread_function()
   {
      read_from_disk(_initializing_cache);
      _cache_is_loaded = true;
      initialize_existing_instances();
      while (true) {
         std::unique_lock<std::mutex> lck(wait_mutex);
         if (cv.wait_for(lck, std::chrono::milliseconds(1000), [] {return _end_thread == true; }) == true)
            break;

         std::lock_guard<std::mutex> lock(monitoring_counters_base::registered_instances_mutex);
         store_counters();
      }
   }

   std::thread& monitoring_counters_base::start_monitoring_thread()
   {
      _monitoring_thread = new std::thread(monitoring_thread_function);
      return *_monitoring_thread;
   }

   void monitoring_counters_base::stop_monitoring_thread()
   {
      if (!_monitoring_thread)
         return;

      std::unique_lock<std::mutex> lck(wait_mutex);
      monitoring_counters_base::_end_thread = true;
      lck.unlock();
      cv.notify_one();

      _monitoring_thread->join();
   }

   void monitoring_counters_base::register_instance()
   {
      monitoring_counters_base::registered_instances.insert(this);
   }

   void monitoring_counters_base::unregister_instance()
   {
      std::set<monitoring_counters_base*>::iterator it = registered_instances.find(this);
      if (it != registered_instances.end())
         registered_instances.erase(it);
   }

   void monitoring_counters_base::reset_counters(const std::vector<std::string>& names)
   {
      std::lock_guard<std::mutex> lock(monitoring_counters_base::registered_instances_mutex);
      std::set<monitoring_counters_base*>::iterator it;
      std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();
       uint32_t seconds = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();

      for (it = registered_instances.begin(); it != registered_instances.end(); ++it)
      {
         (*it)->reset_local_counters(seconds, names);
      }
   }

   void monitoring_counters_base::reset_local_counters_internal(uint32_t seconds, counter_item* first_counter, int size, counter_item_dependency* first_dep, int dep_size, const std::vector<std::string>& names)
   {
      monitoring::counter_item* it = (monitoring::counter_item*)first_counter;
      if (names.size() == 0) {

         for (int i = 0; i < size; i++) {
            if (it->persistent) {
               it->last_reset = seconds;
               it->value = 0LL;

               monitoring::counter_item_dependency* itd = first_dep;
               
               for (int j = 0; j < dep_size; j++) {
                  if (itd->name == it->name) {
                     monitoring::counter_item* it_dep_on = (monitoring::counter_item*)first_counter;
                     for (int k = 0; k < size; k++) {
                        if (itd->depends_on_name == it_dep_on->name) {
                           it->value = it_dep_on->value;
                           break;
                        }
                        it_dep_on++;
                     }
                     break;
                  }
                  itd++;
               }
            } // if(it->persistent)
            it++;
         }
      }
      else
      {
         for (int i = 0; i < size; i++) {

            std::string val(it->name);
            std::vector<std::string>::const_iterator iter = std::find(names.begin(), names.end(), val);
            if (iter != names.end()) {
               if (it->persistent) {
                  it->last_reset = seconds;
                  it->value = 0LL;

                  monitoring::counter_item_dependency* itd = first_dep;

                  for (int j = 0; j < dep_size; j++) {
                     if (itd->name == it->name) {
                        monitoring::counter_item* it_dep_on = (monitoring::counter_item*)first_counter;
                        for (int k = 0; k < size; k++) {
                           if (itd->depends_on_name == it_dep_on->name) {
                              it->value = it_dep_on->value;
                              break;
                           }
                           it_dep_on++;
                        }
                        break;
                     }
                     itd++;
                  }
               } // if(it->persistent)
            }
            it++;
         }
      }
   }

   void monitoring_counters_base::get_counters(const std::vector<std::string>& names, std::vector<counter_item>& result)
   {
      std::lock_guard<std::mutex> lock(monitoring_counters_base::registered_instances_mutex);
      std::set<monitoring_counters_base*>::iterator it;
      for (it = registered_instances.begin(); it != registered_instances.end(); ++it)
      {
         (*it)->get_local_counters(names, result, false);
      }
   }

   void monitoring_counters_base::get_local_counters_internal(const counter_item* first_counter, int size, const std::vector<std::string>& names, bool only_persistent, std::vector<monitoring::counter_item>& result) const
   {
      const monitoring::counter_item* it = (monitoring::counter_item*)first_counter;
      if (names.size() == 0) {
         for (int i = 0; i < size; i++) {
            if(!only_persistent || (only_persistent && it->persistent == true))
               result.push_back(*it);
            it++;
         }
      }
      else {
         for (int i = 0; i < size; i++) {
            std::string val(it->name);
            std::vector<std::string>::const_iterator iter = std::find(names.begin(), names.end(), val);
            if (iter != names.end()) {
               if (!only_persistent || (only_persistent && it->persistent == true))
                  result.push_back(*it);
            }
            it++;
         }
      }
   }

   bool monitoring_counters_base::load_local_counters_internal(counter_item* first_counter, int size)
   {
      monitoring::counter_item* it = (monitoring::counter_item*)first_counter;
      std::chrono::system_clock::time_point tp = std::chrono::system_clock::now();

      if (_cache_is_loaded == false)
         return false;

      for (int i = 0; i < size; i++) {
         if (it->persistent) {
            std::vector<monitoring::counter_item>::iterator iter;
            for (iter = _initializing_cache.begin(); iter != _initializing_cache.end(); ++iter) {
               if ((*iter).name == it->name) {
                  (*it) = (*iter);
                  break;
               }
            }
         }
         else {
            it->last_reset = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
         }
         it++;
      }
      return true;
   }

   void monitoring_counters_base::save_local_counters_internal(counter_item* first_counter, int size)
   {
      monitoring::counter_item* it = (monitoring::counter_item*)first_counter;

      for (int i = 0; i < size; i++) {
         if (it->persistent) 
            _pending_save.push_back(*it);
         it++;
      }
   }
}
