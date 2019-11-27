#include <fc/network/http/websocket.hpp>

#ifndef WIN32 
// websocket++ currently does not build correctly with permessage deflate enabled
// since chrome does not work with websocketpp's implementation of permessage-deflate
// yet, I'm just disabling it on windows instead of trying to fix the build error.
# define ENABLE_WEBSOCKET_PERMESSAGE_DEFLATE
#endif

#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>
#include <websocketpp/config/asio_client.hpp>
#ifdef ENABLE_WEBSOCKET_PERMESSAGE_DEFLATE
# include <websocketpp/extensions/permessage_deflate/enabled.hpp>
#endif
#include <websocketpp/client.hpp>
#include <websocketpp/logger/stub.hpp>

#include <fc/monitoring.hpp>
#include <fc/optional.hpp>
#include <fc/variant.hpp>
#include <fc/thread/scoped_lock.hpp>
#include <fc/thread/spin_lock.hpp>
#include <fc/thread/thread.hpp>
#include <fc/asio.hpp>

#include <thread>
#if defined ( _MSC_VER )
#include <atomic>
#endif

#ifdef DEFAULT_LOGGER
# undef DEFAULT_LOGGER
#endif
#define DEFAULT_LOGGER "rpc"


namespace {


    class shutdown_locker {
    public:
        class shutdown_preventing_task {
        public:
            explicit shutdown_preventing_task(shutdown_locker& locker)
                : _acquired(false)
                , _users(locker._users)
            {
            }

            // this is rather maybe_lock()
            void lock() {
                FC_ASSERT( !_acquired );

                while(true) {
                    int curr = _users.load();

                    if (curr < 0) {
                        // lock could not be acquired at all: shutting down
                        // additional manual check is required in the outer code
                        _acquired = false;
                        return;
                    }

                    if (_users.compare_exchange_weak(curr, curr + 1)) {
                        _acquired = true;
                        return;
                    }

                    if (curr < 0) {
                        // lock could not be acquired at all: shutting down
                        // additional manual check is required in the outer code
                        _acquired = false;
                        return;
                    }

                    std::this_thread::yield();
                }
            }

            void unlock() {
                if (_acquired) {
                    while(true) {
                        int curr = _users.load();

                        FC_ASSERT( curr > 0 );

                        if (_users.compare_exchange_weak(curr, curr - 1)) {
                            _acquired = false;
                            return;
                        }

                        FC_ASSERT( curr > 0 );

                        std::this_thread::yield();
                    }
                }
            }

        private:
            bool _acquired;
            std::atomic<int>& _users;
        };

        class shutdown_task {
        public:
            explicit shutdown_task(shutdown_locker& locker)
                : _acquired(false)
                , _users(locker._users)
            {
            }

            void lock() {
                FC_ASSERT( !_acquired );

                while(true) {
                    int curr = 0;

                    if (_users.compare_exchange_weak(curr, curr - 1)) {
                        FC_ASSERT( _users == -1 );

                        _acquired = true;
                        return;
                    }

                    FC_ASSERT( _users > 0 );

                    std::this_thread::yield();
                }
            }

            void unlock() {
                FC_ASSERT( _acquired );
                FC_ASSERT( _users == -1 );

                // keep _users == -1
                // new users are not allowed after successful shutdown
                // multiple shutdowns will cause assertions
                _acquired = false;
            }

        private:
            bool _acquired;
            std::atomic<int>& _users;
        };

    public:
        shutdown_locker()
            : _users(0)
        {
        }

        bool is_shutting_down() const {
            return _users < 0;
        }

    private:
        friend class shutdown_preventing_task;
        friend class shutdown_task;

        std::atomic<int> _users;
    };


    typedef fc::scoped_lock<shutdown_locker::shutdown_preventing_task> shutdown_preventing_task_scoped_maybe_lock;
    typedef fc::scoped_lock<shutdown_locker::shutdown_task> shutdown_task_scoped_lock;


}


namespace fc { namespace http {

   namespace detail {
      struct asio_with_stub_log : public websocketpp::config::asio {
          typedef asio_with_stub_log type;
          typedef asio base;

          //// All boilerplate copying the base class's config, except as noted
          typedef base::concurrency_type concurrency_type;

          typedef base::request_type request_type;
          typedef base::response_type response_type;

          typedef base::message_type message_type;
          typedef base::con_msg_manager_type con_msg_manager_type;
          typedef base::endpoint_msg_manager_type endpoint_msg_manager_type;

          /// Custom Logging policies, use do-nothing log::stub instead of log::basic
          typedef websocketpp::log::stub elog_type;
          typedef websocketpp::log::stub alog_type;

          typedef base::rng_type rng_type;

          struct transport_config : public base::transport_config {
              typedef type::concurrency_type concurrency_type;
              typedef type::alog_type alog_type;
              typedef type::elog_type elog_type;
              typedef type::request_type request_type;
              typedef type::response_type response_type;
              typedef websocketpp::transport::asio::basic_socket::endpoint
                  socket_type;
          };

          typedef websocketpp::transport::asio::endpoint<transport_config>
              transport_type;

          // override default value of 5 sec timeout
          static const long timeout_open_handshake = 0;
      };

#ifdef ENABLE_WEBSOCKET_PERMESSAGE_DEFLATE
      struct asio_with_stub_log_and_deflate : public websocketpp::config::asio {
          typedef asio_with_stub_log_and_deflate type;
          typedef asio base;

          //// All boilerplate copying the base class's config, except as noted
          typedef base::concurrency_type concurrency_type;

          typedef base::request_type request_type;
          typedef base::response_type response_type;

          typedef base::message_type message_type;
          typedef base::con_msg_manager_type con_msg_manager_type;
          typedef base::endpoint_msg_manager_type endpoint_msg_manager_type;

          /// Custom Logging policies, use do-nothing log::stub instead of log::basic
          typedef websocketpp::log::stub elog_type;
          typedef websocketpp::log::stub alog_type;

          typedef base::rng_type rng_type;

          struct transport_config : public base::transport_config {
              typedef type::concurrency_type concurrency_type;
              typedef type::alog_type alog_type;
              typedef type::elog_type elog_type;
              typedef type::request_type request_type;
              typedef type::response_type response_type;
              typedef websocketpp::transport::asio::basic_socket::endpoint
                  socket_type;
          };

          typedef websocketpp::transport::asio::endpoint<transport_config>
              transport_type;

          /// enable the permessage_compress extension
          struct permessage_deflate_config {};
          typedef websocketpp::extensions::permessage_deflate::enabled
              <permessage_deflate_config> permessage_deflate_type;

          // override default value of 5 sec timeout
          static const long timeout_open_handshake = 0;
      };
#endif

      struct asio_tls_stub_log : public websocketpp::config::asio_tls {
          typedef asio_tls_stub_log type;
          typedef asio_tls base;

          //// All boilerplate copying the base class's config, except as noted
          typedef base::concurrency_type concurrency_type;

          typedef base::request_type request_type;
          typedef base::response_type response_type;

          typedef base::message_type message_type;
          typedef base::con_msg_manager_type con_msg_manager_type;
          typedef base::endpoint_msg_manager_type endpoint_msg_manager_type;

          /// Custom Logging policies, use do-nothing log::stub instead of log::basic
          typedef websocketpp::log::stub elog_type;
          typedef websocketpp::log::stub alog_type;

          typedef base::rng_type rng_type;

          struct transport_config : public base::transport_config {
              typedef type::concurrency_type concurrency_type;
              typedef type::alog_type alog_type;
              typedef type::elog_type elog_type;
              typedef type::request_type request_type;
              typedef type::response_type response_type;
              typedef websocketpp::transport::asio::tls_socket::endpoint socket_type;
          };

          typedef websocketpp::transport::asio::endpoint<transport_config>
              transport_type;
      };

#ifdef ENABLE_WEBSOCKET_PERMESSAGE_DEFLATE
      struct asio_tls_stub_log_and_deflate : public websocketpp::config::asio_tls {
          typedef asio_tls_stub_log_and_deflate type;
          typedef asio_tls base;

          //// All boilerplate copying the base class's config, except as noted
          typedef base::concurrency_type concurrency_type;

          typedef base::request_type request_type;
          typedef base::response_type response_type;

          typedef base::message_type message_type;
          typedef base::con_msg_manager_type con_msg_manager_type;
          typedef base::endpoint_msg_manager_type endpoint_msg_manager_type;

          /// Custom Logging policies, use do-nothing log::stub instead of log::basic
          typedef websocketpp::log::stub elog_type;
          typedef websocketpp::log::stub alog_type;

          typedef base::rng_type rng_type;

          struct transport_config : public base::transport_config {
              typedef type::concurrency_type concurrency_type;
              typedef type::alog_type alog_type;
              typedef type::elog_type elog_type;
              typedef type::request_type request_type;
              typedef type::response_type response_type;
              typedef websocketpp::transport::asio::tls_socket::endpoint socket_type;
          };

          typedef websocketpp::transport::asio::endpoint<transport_config>
              transport_type;

          /// enable the permessage_compress extension
          struct permessage_deflate_config {};
          typedef websocketpp::extensions::permessage_deflate::enabled
              <permessage_deflate_config> permessage_deflate_type;
      };
#endif

      using websocketpp::connection_hdl;

      template<typename T>
      class websocket_connection_impl : public websocket_connection
      {
         public:
            websocket_connection_impl( T con )
            :_ws_connection(con){
            }

            ~websocket_connection_impl()
            {
            }

            virtual void send_message( const std::string& message )override
            {
               idump((message));
               //std::cerr<<"send: "<<message<<"\n";
               auto ec = _ws_connection->send( message );
               FC_ASSERT( !ec, "websocket send failed: ${msg}", ("msg",ec.message() ) );
            }
            virtual void close( int64_t code, const std::string& reason  )override
            {
               _ws_connection->close(code,reason);
            }

            T _ws_connection;
      };


      typedef websocketpp::lib::shared_ptr<boost::asio::ssl::context> context_ptr;
      
      MONITORING_COUNTERS_BEGIN(abstract_websocket_server_monitoring_helper)
      MONITORING_DEFINE_TRANSIENT_COUNTER(connections_rpc_active)
      MONITORING_DEFINE_COUNTER(connections_rpc_active_max)
      MONITORING_DEFINE_TRANSIENT_COUNTER(connections_http_active)
      MONITORING_DEFINE_COUNTER(connections_http_active_max)
      MONITORING_COUNTERS_DEPENDENCIES
      MONITORING_COUNTER_DEPENDENCY(connections_http_active_max, connections_http_active)
      MONITORING_COUNTER_DEPENDENCY(connections_rpc_active_max, connections_rpc_active)
      MONITORING_COUNTERS_END
      
      
      class abstract_websocket_server_monitoring_helper PUBLIC_DERIVATION_FROM_ONLY_MONITORING_CLASS(abstract_websocket_server_monitoring_helper)
      {
      public:
      };

      class abstract_websocket_server
      {
         public:
            abstract_websocket_server()
            {
               if(_counters_refcount == 0) // we dont need synchronization because there are only two instances of this class constructed/destructed in sequence
                  _counters_helper = std::unique_ptr<abstract_websocket_server_monitoring_helper>(new abstract_websocket_server_monitoring_helper());
               _counters_refcount++;
               FC_ASSERT(_counters_helper);
            }
            virtual ~abstract_websocket_server() 
            {
               if (_counters_refcount == 1)
                  _counters_helper.reset();
               _counters_refcount--;
            }

            virtual void on_connection( const on_connection_handler& handler) = 0;
            virtual void listen( uint16_t port ) = 0;
            virtual void listen( const fc::ip::endpoint& ep ) = 0;
            virtual void start_accept() = 0;

            virtual void add_headers(const fc::string& name, const fc::string& value) = 0;
            static std::unique_ptr<abstract_websocket_server_monitoring_helper> _counters_helper;
      private:
            static int _counters_refcount;
      };
     

      std::unique_ptr<abstract_websocket_server_monitoring_helper> abstract_websocket_server::_counters_helper = nullptr;
      int abstract_websocket_server::_counters_refcount = 0;

      

      template <typename config>
      class websocket_server_impl : public abstract_websocket_server 
      {
          void tick(std::shared_ptr<boost::asio::deadline_timer> timer, connection_hdl hdl, std::shared_ptr<shutdown_locker> shutdown_locker, boost::system::error_code const &ec)
          {
              if(shutdown_locker->is_shutting_down( ))
                  return;

              websocketpp::lib::error_code wse;
              if(ec)
              {
                  _server.close(hdl, websocketpp::close::status::internal_endpoint_error, "", wse);
                  return;
              }

              _server.ping(hdl, "", wse);

              if(wse)
              {
                  _server.close(hdl, websocketpp::close::status::force_tcp_drop, "", wse);
                  return;
              }
              timer->expires_from_now(boost::posix_time::seconds(257));
              timer->async_wait(boost::bind(&websocket_server_impl::tick, this, timer, hdl, shutdown_locker, boost::placeholders::_1));
          }

         public:
            websocket_server_impl()
               : _shutdown_locker( new shutdown_locker() )
               , _server_thread( fc::thread::current() )
            {
               auto shutdown_locker_wraith = _shutdown_locker;

               _server.clear_access_channels( websocketpp::log::alevel::all );
               _server.init_asio(&fc::asio::default_io_service());
               _server.set_reuse_addr(true);

               _server.set_open_handler( [&, shutdown_locker_wraith]( connection_hdl hdl ){
                    _server_thread.async( [&, shutdown_locker_wraith](){
                       shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                       const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                       if (shutdown_locker_wraith->is_shutting_down()) return;

                       websocket_connection_ptr new_con = std::make_shared<websocket_connection_impl<typename websocketpp::server<config>::connection_ptr>>( _server.get_con_from_hdl(hdl) );

                       auto timer = std::make_shared<boost::asio::deadline_timer>(fc::asio::default_io_service( ));
                       timer->expires_from_now(boost::posix_time::seconds(257));
                       timer->async_wait(boost::bind(&websocket_server_impl::tick, this, timer, hdl, shutdown_locker_wraith, boost::placeholders::_1));

                       _on_connection( _connections[hdl] = new_con, new_con->is_tls );
                       _counters_helper->MONITORING_COUNTER_VALUE(connections_rpc_active)++;
                       
                       if (_counters_helper->MONITORING_COUNTER_VALUE(connections_rpc_active_max) < _counters_helper->MONITORING_COUNTER_VALUE(connections_rpc_active))
                          _counters_helper->MONITORING_COUNTER_VALUE(connections_rpc_active_max) = _counters_helper->MONITORING_COUNTER_VALUE(connections_rpc_active);
                          
                    }).wait();
               });

               _server.set_message_handler( [&, shutdown_locker_wraith]( connection_hdl hdl, typename websocketpp::server<config>::message_ptr msg ){
                    _server_thread.async( [&, shutdown_locker_wraith](){
                       shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                       const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                       if (shutdown_locker_wraith->is_shutting_down()) return;

                       auto current_con = _connections.find(hdl);
                       assert( current_con != _connections.end() );
                       //wdump(("server")(msg->get_payload()));
                       //std::cerr<<"recv: "<<msg->get_payload()<<"\n";
                       auto payload = msg->get_payload();
                       std::shared_ptr<websocket_connection> con = current_con->second;
                       ++_pending_messages;
                       auto f = fc::async([this, con, payload, shutdown_locker_wraith](){
                           shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                           const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                           if (shutdown_locker_wraith->is_shutting_down()) return;

                           if( _pending_messages )
                               --_pending_messages;
                           con->on_message( payload );
                       });
                       if( _pending_messages > 100 ) 
                         f.wait();
                    }).wait();
               });

               _server.set_http_handler( [&, shutdown_locker_wraith]( connection_hdl hdl ){
                    _server_thread.async( [&, shutdown_locker_wraith](){
                       shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                       const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                       if (shutdown_locker_wraith->is_shutting_down()) return;

                       auto current_con = std::make_shared<websocket_connection_impl<typename websocketpp::server<config>::connection_ptr>>( _server.get_con_from_hdl(hdl) );                 
                       _on_connection( current_con, current_con->is_tls );
                      _counters_helper->MONITORING_COUNTER_VALUE(connections_http_active)++;
                      if (_counters_helper->MONITORING_COUNTER_VALUE(connections_http_active_max) < _counters_helper->MONITORING_COUNTER_VALUE(connections_http_active))
                          _counters_helper->MONITORING_COUNTER_VALUE(connections_http_active_max) = _counters_helper->MONITORING_COUNTER_VALUE(connections_http_active);

                       auto con = _server.get_con_from_hdl(hdl);
                       con->defer_http_response();
                       std::string request_body = con->get_request_body();
                       //wdump(("server")(request_body));

                       fc::async([&, current_con, request_body, con, shutdown_locker_wraith] {
                          shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                          const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                          if (shutdown_locker_wraith->is_shutting_down()) return;

                          std::string response = current_con->on_http(request_body);
                          con->set_body( response );
                          con->set_status( websocketpp::http::status_code::ok );

                          if (!this->_additional_headers.empty()) {
                             for(const auto& item : this->_additional_headers) {
                                con->append_header(item.first, item.second);
                             }
                          }

//                          con->append_header("Access-Control-Allow-Origin", "*");
                          con->send_http_response();
                          current_con->closed();
                          _counters_helper->MONITORING_COUNTER_VALUE(connections_http_active)--;
                       }, "call on_http");
                    }).wait();
               });

               _server.set_close_handler( [&, shutdown_locker_wraith]( connection_hdl hdl ){
                    shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                    const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                    if (shutdown_locker_wraith->is_shutting_down()) return;

                    _server_thread.async( [&, shutdown_locker_wraith](){
                       shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                       const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                       if (shutdown_locker_wraith->is_shutting_down()) return;

                       if( _connections.find(hdl) != _connections.end() )
                       {
                          _connections[hdl]->closed();
                          _connections.erase( hdl );
                          _counters_helper->MONITORING_COUNTER_VALUE(connections_rpc_active)--;
                       }
                       else
                       {
                            wlog( "unknown connection closed" );
                       }
                       if( _connections.empty() && _closed )
                           _closed->set_value();
                    }).wait();
               });

               _server.set_fail_handler( [&, shutdown_locker_wraith]( connection_hdl hdl ){
                    shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                    const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                    if (shutdown_locker_wraith->is_shutting_down()) return;

                    if( _server.is_listening() )
                    {
                       _server_thread.async( [&, shutdown_locker_wraith](){
                          shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                          const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                          if (shutdown_locker_wraith->is_shutting_down()) return;

                          if( _connections.find(hdl) != _connections.end() )
                          {
                             _connections[hdl]->closed();
                             _connections.erase( hdl );
                             _counters_helper->MONITORING_COUNTER_VALUE(connections_rpc_active)--;
                          }
                          else
                          {
                            wlog( "unknown connection failed" );
                          }
                          if( _connections.empty() && _closed )
                              _closed->set_value();
                       }).wait();
                    }
               });

               _server.set_pong_timeout_handler([&, shutdown_locker_wraith](connection_hdl hdl, std::string) {
                   if (shutdown_locker_wraith->is_shutting_down()) return;
                   websocketpp::lib::error_code wse;
                   _server.close(hdl, websocketpp::close::status::force_tcp_drop, "pong timeout", wse);
               });
            }

            ~websocket_server_impl()
            {
               if( _server.is_listening() )
                   _server.stop_listening();

               if( _connections.size() )
                   _closed = fc::promise<void>::ptr( new fc::promise<void>() );

               auto cpy_con = _connections;
               for( auto item : cpy_con )
                   _server.close( item.first, 0, "server exit" );

               if( _closed )
                   _closed->wait();

                shutdown_locker::shutdown_task st(*_shutdown_locker);
                const shutdown_task_scoped_lock lock(st);
            }

            void on_connection( const on_connection_handler& handler ) override
            {
               _on_connection = handler;
            }

            void listen( uint16_t port ) override
            {
               _server.listen(port);
            }

            void listen( const fc::ip::endpoint& ep ) override
            {
               _server.listen( boost::asio::ip::tcp::endpoint( boost::asio::ip::address_v4(uint32_t(ep.get_address())),ep.port()) );
            }

            void start_accept() override
            {
               _server.start_accept();
            }

            void add_headers(const fc::string& name, const fc::string& value) override
            {
                _additional_headers.insert( { name, value } );
            }

            typedef std::map<connection_hdl, websocket_connection_ptr,std::owner_less<connection_hdl> > con_map;

            std::shared_ptr<shutdown_locker>   _shutdown_locker;
            con_map                            _connections;
            fc::thread&                        _server_thread;
            websocketpp::server<config>        _server;
            on_connection_handler              _on_connection;
            fc::promise<void>::ptr             _closed;
            uint32_t                           _pending_messages = 0;
            std::map<fc::string, fc::string>   _additional_headers;
      };
     
      template <typename config>
      class websocket_tls_server_impl : public websocket_server_impl<config> 
      {
         public:
            websocket_tls_server_impl( const string& server_cert_key_file,
                                       const string& server_cert_chain_file,
                                       const string& ssl_password )
            {
               this->_server.set_tls_init_handler( [=]( websocketpp::connection_hdl hdl ) -> context_ptr {
                     context_ptr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv1);
                     try {
                        ctx->set_options(boost::asio::ssl::context::default_workarounds |
                        boost::asio::ssl::context::no_sslv2 |
                        boost::asio::ssl::context::no_sslv3 |
                        boost::asio::ssl::context::single_dh_use);
                        ctx->set_password_callback([=](std::size_t max_length, boost::asio::ssl::context::password_purpose){ return ssl_password;});
                        ctx->use_private_key_file(server_cert_key_file, boost::asio::ssl::context::pem);
                        ctx->use_certificate_chain_file(server_cert_chain_file);
                     } catch (std::exception& e) {
                        std::cout << e.what() << std::endl;
                     }
                     return ctx;
               });
            }
      };



      typedef websocketpp::client<asio_with_stub_log> websocket_client_type;
      typedef websocketpp::client<asio_tls_stub_log> websocket_tls_client_type;

      typedef websocket_client_type::connection_ptr  websocket_client_connection_type;
      typedef websocket_tls_client_type::connection_ptr  websocket_tls_client_connection_type;

      class websocket_client_impl
      {
         public:
            typedef websocket_client_type::message_ptr message_ptr;

            websocket_client_impl()
               : _shutdown_locker( new shutdown_locker() )
               , _client_thread( fc::thread::current() )
            {
                auto shutdown_locker_wraith = _shutdown_locker;

                _client.clear_access_channels( websocketpp::log::alevel::all );
                _client.set_message_handler( [&, shutdown_locker_wraith]( connection_hdl hdl, message_ptr msg ){
                   shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                   const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                   if (shutdown_locker_wraith->is_shutting_down()) return;

                   _client_thread.async( [&, shutdown_locker_wraith](){
                        shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                        const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                        if (shutdown_locker_wraith->is_shutting_down()) return;

                        wdump((msg->get_payload()));
                        //std::cerr<<"recv: "<<msg->get_payload()<<"\n";
                        auto received = msg->get_payload();
                        fc::async( [=](){
                           shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                           const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                           if (shutdown_locker_wraith->is_shutting_down()) return;

                           if( _connection )
                               _connection->on_message(received);
                        });
                   }).wait();
                });
                _client.set_close_handler( [=]( connection_hdl hdl ){
                   shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                   const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                   if (shutdown_locker_wraith->is_shutting_down()) return;

                   _client_thread.async( [&, shutdown_locker_wraith](){
                       shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                       const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                       if (shutdown_locker_wraith->is_shutting_down()) return;

                       if( _connection ){
                           _connection->closed();
                           _connection.reset();
                       }
                   } ).wait();
                   if( _closed )
                       _closed->set_value();
                });
                _client.set_fail_handler( [=]( connection_hdl hdl ){
                   shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                   const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                   if (shutdown_locker_wraith->is_shutting_down()) return;

                   auto con = _client.get_con_from_hdl(hdl);
                   auto message = con->get_ec().message();
                   if( _connection )
                       _client_thread.async( [&, shutdown_locker_wraith](){
                           shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                           const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                           if (shutdown_locker_wraith->is_shutting_down()) return;

                           if( _connection )
                               _connection->closed();
                           _connection.reset();
                       } ).wait();
                   if( _connected && !_connected->ready() )
                       _connected->set_exception( exception_ptr( new FC_EXCEPTION( exception, "${message}", ("message",message)) ) );
                   if( _closed )
                       _closed->set_value();
                });

                _client.init_asio( &fc::asio::default_io_service() );
            }
            ~websocket_client_impl()
            {
               if( _connection )
               {
                  _connection->close(0, "client closed");
                  _connection.reset();
                  if( _closed )
                      _closed->wait();
               }

               shutdown_locker::shutdown_task st(*_shutdown_locker);
               const shutdown_task_scoped_lock lock(st);
            }

            std::shared_ptr<shutdown_locker>   _shutdown_locker;
            fc::promise<void>::ptr             _connected;
            fc::promise<void>::ptr             _closed;
            fc::thread&                        _client_thread;
            websocket_client_type              _client;
            websocket_connection_ptr           _connection;
      };



      class websocket_tls_client_impl
      {
         public:
            typedef websocket_tls_client_type::message_ptr message_ptr;

            websocket_tls_client_impl()
               : _shutdown_locker( new shutdown_locker() )
               , _client_thread( fc::thread::current() )
            {
                auto shutdown_locker_wraith = _shutdown_locker;

                _client.clear_access_channels( websocketpp::log::alevel::all );
                _client.set_message_handler( [&, shutdown_locker_wraith]( connection_hdl hdl, message_ptr msg ){
                   _client_thread.async( [&, shutdown_locker_wraith](){
                       shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                       const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                       if (shutdown_locker_wraith->is_shutting_down()) return;

                       wdump((msg->get_payload()));
                       _connection->on_message( msg->get_payload() );
                   }).wait();
                });

                _client.set_close_handler( [=]( connection_hdl hdl ){
                   shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                   const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                   if (shutdown_locker_wraith->is_shutting_down()) return;

                   if( _connection )
                   {
                      try {
                         _client_thread.async( [&, shutdown_locker_wraith](){
                                 shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                                 const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                                 if (shutdown_locker_wraith->is_shutting_down()) return;

                                 wlog(". ${p}", ("p",uint64_t(_connection.get())));
                                 if( !_closed && _connection )
                                     _connection->closed();
                                 _connection.reset();
                         } ).wait();
                      } catch ( const fc::exception& e )
                      {
                          if( _closed )
                              _closed->set_exception( e.dynamic_copy_exception() );
                      }
                      if( _closed )
                          _closed->set_value();
                   }
                });

                _client.set_fail_handler( [=]( connection_hdl hdl ){
                   shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                   const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                   if (shutdown_locker_wraith->is_shutting_down()) return;

                   elog( "." );
                   auto con = _client.get_con_from_hdl(hdl);
                   auto message = con->get_ec().message();
                   if( _connection )
                       _client_thread.async( [&, shutdown_locker_wraith](){
                           shutdown_locker::shutdown_preventing_task spt(*shutdown_locker_wraith);
                           const shutdown_preventing_task_scoped_maybe_lock lock(spt);
                           if (shutdown_locker_wraith->is_shutting_down()) return;

                           if( _connection )
                               _connection->closed();
                           _connection.reset();
                       } ).wait();
                   if( _connected && !_connected->ready() )
                       _connected->set_exception( exception_ptr( new FC_EXCEPTION( exception, "${message}", ("message",message)) ) );
                   if( _closed )
                       _closed->set_value();
                });

                _client.set_tls_init_handler( [=](websocketpp::connection_hdl) {
                   context_ptr ctx = websocketpp::lib::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv1);
                   try {
                      ctx->set_options(boost::asio::ssl::context::default_workarounds |
                      boost::asio::ssl::context::no_sslv2 |
                      boost::asio::ssl::context::no_sslv3 |
                      boost::asio::ssl::context::single_dh_use);
                   } catch (std::exception& e) {
                      edump((e.what()));
                      std::cout << e.what() << std::endl;
                   }
                   return ctx;
                });

                _client.init_asio( &fc::asio::default_io_service() );
            }
            ~websocket_tls_client_impl()
            {
               if( _connection )
               {
                  wlog(".");
                  _connection->close(0, "client closed");
                  if( _closed )
                      _closed->wait();
               }

               shutdown_locker::shutdown_task st(*_shutdown_locker);
               const shutdown_task_scoped_lock lock(st);
            }

            std::shared_ptr<shutdown_locker>   _shutdown_locker;
            fc::promise<void>::ptr             _connected;
            fc::promise<void>::ptr             _closed;
            fc::thread&                        _client_thread;
            websocket_tls_client_type          _client;
            websocket_connection_ptr           _connection;
      };


   } // namespace detail

   websocket_server::websocket_server(bool enable_permessage_deflate /* = true */) :
      my( 
#ifdef ENABLE_WEBSOCKET_PERMESSAGE_DEFLATE
          enable_permessage_deflate ? 
            (detail::abstract_websocket_server*)new detail::websocket_server_impl<detail::asio_with_stub_log_and_deflate> : 
#endif
            (detail::abstract_websocket_server*)new detail::websocket_server_impl<detail::asio_with_stub_log> ) 
   {
#ifndef ENABLE_WEBSOCKET_PERMESSAGE_DEFLATE
     if (enable_permessage_deflate)
       elog("Websocket permessage-deflate requested but not enabled during compile");
#endif
   }
   websocket_server::~websocket_server(){}

   void websocket_server::on_connection( const on_connection_handler& handler )
   {
      my->on_connection(handler);
   }

   void websocket_server::listen( uint16_t port )
   {
      my->listen(port);
   }
   void websocket_server::listen( const fc::ip::endpoint& ep )
   {
      my->listen(ep);
   }

   void websocket_server::start_accept() {
      my->start_accept();
   }

   void websocket_server::add_headers(const fc::string& name, const fc::string& value) {
      my->add_headers(name, value);
   }

   websocket_tls_server::websocket_tls_server(const std::string& server_cert_key_file,
                                              const std::string& server_cert_chain_file,
                                              const string& ssl_password,
                                              bool enable_permessage_deflate /* = true */) :
      my(
#ifdef ENABLE_WEBSOCKET_PERMESSAGE_DEFLATE
          enable_permessage_deflate ?
            (detail::abstract_websocket_server*)new detail::websocket_tls_server_impl<detail::asio_tls_stub_log_and_deflate>(server_cert_key_file,
                                                                                                                             server_cert_chain_file,
                                                                                                                             ssl_password) :
#endif
            (detail::abstract_websocket_server*)new detail::websocket_tls_server_impl<detail::asio_tls_stub_log>(server_cert_key_file,
                                                                                                                 server_cert_chain_file,
                                                                                                                 ssl_password) )
   {
#ifndef ENABLE_WEBSOCKET_PERMESSAGE_DEFLATE
     if (enable_permessage_deflate)
       elog("Websocket permessage-deflate requested but not enabled during compile");
#endif
   }
   websocket_tls_server::~websocket_tls_server(){}

   void websocket_tls_server::on_connection( const on_connection_handler& handler )
   {
      my->on_connection(handler);
   }

   void websocket_tls_server::listen( uint16_t port )
   {
      my->listen(port);
   }
   void websocket_tls_server::listen( const fc::ip::endpoint& ep )
   {
      my->listen(ep);
   }

   void websocket_tls_server::start_accept() 
   {
      my->start_accept();
   }

   void websocket_tls_server::add_headers(const fc::string& name, const fc::string& value) {
      my->add_headers(name, value);
   }

   websocket_client::websocket_client():my( new detail::websocket_client_impl() ),smy(new detail::websocket_tls_client_impl()) {}
   websocket_client::~websocket_client(){ }

   websocket_connection_ptr websocket_client::connect( const std::string& uri )
   { try {
       if( uri.substr(0,4) == "wss:" )
          return secure_connect(uri);
       FC_ASSERT( uri.substr(0,3) == "ws:" );

       // wlog( "connecting to ${uri}", ("uri",uri));
       websocketpp::lib::error_code ec;

       my->_connected = fc::promise<void>::ptr( new fc::promise<void>("websocket::connect") );

       my->_client.set_open_handler( [=]( websocketpp::connection_hdl hdl ){
          auto con =  my->_client.get_con_from_hdl(hdl);
          my->_connection = std::make_shared<detail::websocket_connection_impl<detail::websocket_client_connection_type>>( con );
          my->_closed = fc::promise<void>::ptr( new fc::promise<void>("websocket::closed") );
          if( my->_connected )
              my->_connected->set_value();
       });

       auto con = my->_client.get_connection( uri, ec );

       if( ec ) FC_ASSERT( !ec, "error: ${e}", ("e",ec.message()) );

       my->_client.connect(con);
       if( my->_connected )
           my->_connected->wait();
       return my->_connection;
   } FC_CAPTURE_AND_RETHROW( (uri) ) }

   websocket_connection_ptr websocket_client::secure_connect( const std::string& uri )
   { try {
       if( uri.substr(0,3) == "ws:" )
          return connect(uri);
       FC_ASSERT( uri.substr(0,4) == "wss:" );
       // wlog( "connecting to ${uri}", ("uri",uri));
       websocketpp::lib::error_code ec;

       smy->_connected = fc::promise<void>::ptr( new fc::promise<void>("websocket::connect") );

       smy->_client.set_open_handler( [=]( websocketpp::connection_hdl hdl ){
          auto con =  smy->_client.get_con_from_hdl(hdl);
          smy->_connection = std::make_shared<detail::websocket_connection_impl<detail::websocket_tls_client_connection_type>>( con );
          smy->_closed = fc::promise<void>::ptr( new fc::promise<void>("websocket::closed") );
          if( smy->_connected )
              smy->_connected->set_value();
       });

       auto con = smy->_client.get_connection( uri, ec );
       if( ec )
          FC_ASSERT( !ec, "error: ${e}", ("e",ec.message()) );
       smy->_client.connect(con);
       if( smy->_connected )
           smy->_connected->wait();
       return smy->_connection;
   } FC_CAPTURE_AND_RETHROW( (uri) ) }

   websocket_connection_ptr websocket_tls_client::connect( const std::string& uri )
   { try {
       // wlog( "connecting to ${uri}", ("uri",uri));
       websocketpp::lib::error_code ec;

       my->_connected = fc::promise<void>::ptr( new fc::promise<void>("websocket::connect") );

       my->_client.set_open_handler( [=]( websocketpp::connection_hdl hdl ){
          auto con =  my->_client.get_con_from_hdl(hdl);
          my->_connection = std::make_shared<detail::websocket_connection_impl<detail::websocket_tls_client_connection_type>>( con );
          my->_closed = fc::promise<void>::ptr( new fc::promise<void>("websocket::closed") );
          if( my->_connected )
              my->_connected->set_value();
       });

       auto con = my->_client.get_connection( uri, ec );
       if( ec )
       {
          FC_ASSERT( !ec, "error: ${e}", ("e",ec.message()) );
       }
       my->_client.connect(con);
       if( my->_connected )
           my->_connected->wait();
       return my->_connection;
   } FC_CAPTURE_AND_RETHROW( (uri) ) }

} } // fc::http
