#include <fc/rpc/cli.hpp>
#include <fc/thread/thread.hpp>

#include <iostream>
#include <fstream>

#ifndef _WIN32
#include <unistd.h>
#include <termios.h>
#else
#include <Windows.h>
#endif

#ifdef HAVE_READLINE
# include <readline/readline.h>
# include <readline/history.h>
// I don't know exactly what version of readline we need.  I know the 4.2 version that ships on some macs is
// missing some functions we require.  We're developing against 6.3, but probably anything in the 6.x
// series is fine
# if RL_VERSION_MAJOR < 6
#  ifdef _MSC_VER
#   pragma message("You have an old version of readline installed that might not support some of the features we need")
#   pragma message("Readline support will not be compiled in")
#  else
#   warning "You have an old version of readline installed that might not support some of the features we need"
#   warning "Readline support will not be compiled in"
#  endif
#  undef HAVE_READLINE
# endif
# ifdef WIN32
#  include <io.h>
# endif
#endif

namespace fc { namespace rpc {

static std::vector<std::string>& cli_commands()
{
   static std::vector<std::string>* cmds = new std::vector<std::string>();
   return *cmds;
}

cli::~cli()
{
   if( _run_complete.valid() )
   {
      stop();
   }
}

variant cli::send_call( api_id_type api_id, string method_name, variants args /* = variants() */ )
{
   FC_ASSERT(false);
}

variant cli::send_callback( uint64_t callback_id, variants args /* = variants() */ )
{
   FC_ASSERT(false);
}

void cli::send_notice( uint64_t callback_id, variants args /* = variants() */ )
{
   FC_ASSERT(false);
}

void cli::start()
{
   cli_commands() = get_method_names(0);
   _run_complete = fc::async( [&](){ run(); } );
}

void cli::stop()
{
   _run_complete.cancel();
   _run_complete.wait();
}

void cli::wait()
{
   _run_complete.wait();
}

void cli::format_result( const string& method, std::function<string(variant,const variants&)> formatter)
{
   _result_formatters[method] = formatter;
}

void cli::set_prompt( const string& prompt )
{
   _prompt = prompt;
}

void cli::set_command_file( const string& command_file )
{
    non_interactive = true;

    std::ifstream cf_in(command_file);
    std::string current_line;

    if (! cf_in.good())
    {
        std::cout << "File not found or an I/O error.\n";
        return;
    }

    while (std::getline(cf_in, current_line))
    {
        if (current_line.size() > 0)
        {
            commands.emplace_back(current_line);
        }
    }
}

void cli::run()
{
   unsigned int current_line_index = 0;
   while( !_run_complete.canceled() )
   {
      try
      {
         std::string line;
         if (non_interactive)
         {
             if (current_line_index >= commands.size())
                 break;
             line = commands[current_line_index++];
         }
         else
         {
             try
             {
                 get_line( _prompt.c_str(), line, true );
             }
             catch ( const fc::eof_exception& e )
             {
                break;
             }
         }
         if (line == "quit" || line == "exit")
            break;

         if (line == "unlock" || line == "set_password")
         {
#ifndef _WIN32
            struct termios _old, _new;
            int input_file_desc = fileno(
#ifdef HAVE_READLINE
                     rl_instream != NULL ? rl_instream :
#endif
                     stdin);
            /* Turn echoing off and fail if we can’t. */
            if (tcgetattr(input_file_desc, &_old) != 0)
                FC_THROW("Can't get terminal attributes");
            _new = _old;
            _new.c_lflag &= ~ECHO;
            if (tcsetattr(input_file_desc, TCSAFLUSH, &_new) != 0)
                FC_THROW("Can't set terminal attributes");
#else
            DWORD mode = 0;
            GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
            mode &= ~ENABLE_ECHO_INPUT;
             
            DWORD bytesWritten = 0;
            INPUT_RECORD ir[4];
            memset(&ir, 0, sizeof(ir));

            ir[0].EventType = KEY_EVENT;
            ir[0].Event.KeyEvent.bKeyDown = TRUE;
            ir[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
            ir[0].Event.KeyEvent.uChar.AsciiChar = 13;
            ir[0].Event.KeyEvent.wRepeatCount = 1;

            ir[1].EventType = KEY_EVENT;
            ir[1].Event.KeyEvent.bKeyDown = FALSE;
            ir[1].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
            ir[1].Event.KeyEvent.uChar.AsciiChar = 13;
            ir[1].Event.KeyEvent.wRepeatCount = 1;
            
            BOOL res = SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);
            res = WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), ir, 2, &bytesWritten);
            bytesWritten = 0;

            fc::string redudant_line;
            fc::getline(fc::cin, redudant_line);        

#endif

            try
            {
                std::string passwd;
                get_line( "Password: ", passwd, false );
                std::cout << "\n";
                if (!passwd.empty())
                    line.append(1, ' ').append(passwd);
            }
            catch ( const fc::eof_exception& e )
            {
                break;
            }

#ifndef _WIN32
            /* Restore terminal. */
            if (tcsetattr(input_file_desc, TCSAFLUSH, &_old) != 0)
                FC_THROW("Can't revert terminal attributes");
#else
            GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode);
            mode |= ENABLE_ECHO_INPUT;
            res = SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), mode);

            bytesWritten = 0;           
            memset(&ir, 0, sizeof(ir));

            ir[0].EventType = KEY_EVENT;
            ir[0].Event.KeyEvent.bKeyDown = TRUE;
            ir[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
            ir[0].Event.KeyEvent.uChar.AsciiChar = 13;
            ir[0].Event.KeyEvent.wRepeatCount = 1;

            ir[1].EventType = KEY_EVENT;
            ir[1].Event.KeyEvent.bKeyDown = FALSE;
            ir[1].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
            ir[1].Event.KeyEvent.uChar.AsciiChar = 13;
            ir[1].Event.KeyEvent.wRepeatCount = 1;

            res = WriteConsoleInput(GetStdHandle(STD_INPUT_HANDLE), ir, 2, &bytesWritten);
            fc::getline(fc::cin, redudant_line);
#endif
         }

         fc::variants args = fc::json::variants_from_string(line + char(EOF));
         if( args.size() == 0 )
            continue;

         const string& method = args[0].get_string();

         auto result = receive_call( 0, method, variants( args.begin()+1,args.end() ) );
         auto itr = _result_formatters.find( method );
         if( itr == _result_formatters.end() )
         {
            std::cout << fc::json::to_pretty_string( result ) << "\n";
         }
         else
            std::cout << itr->second( result, args ) << "\n";
      }
      catch ( const fc::exception& e )
      {
         std::cout << e.to_detail_string() << "\n";
      }
   }
}


char * dupstr (const char* s) {
   char *r;

   r = (char*) malloc ((strlen (s) + 1));
   strcpy (r, s);
   return (r);
}

char* my_generator(const char* text, int state)
{
   static int list_index, len;
   const char *name;

   if (!state) {
      list_index = 0;
      len = strlen (text);
   }

   auto& cmd = cli_commands();

   while( list_index < cmd.size() ) 
   {
      name = cmd[list_index].c_str();
      list_index++;

      if (strncmp (name, text, len) == 0)
         return (dupstr(name));
   }

   /* If no names matched, then return NULL. */
   return ((char *)NULL);
}


static char** cli_completion( const char * text , int start, int end)
{
   char **matches;
   matches = (char **)NULL;

#ifdef HAVE_READLINE
   if (start == 0)
      matches = rl_completion_matches ((char*)text, &my_generator);
   else
      rl_bind_key('\t',rl_abort);
#endif

   return (matches);
}


void cli::get_line( const fc::string& prompt, fc::string& line, bool allow_history) const
{
   // getting file descriptor for C++ streams is near impossible
   // so we just assume it's the same as the C stream...
#ifdef HAVE_READLINE
#ifndef WIN32   
   if( isatty( fileno( stdin ) ) )
#else
   // it's implied by
   // https://msdn.microsoft.com/en-us/library/f4s0ddew.aspx
   // that this is the proper way to do this on Windows, but I have
   // no access to a Windows compiler and thus,
   // no idea if this actually works
   if( _isatty( _fileno( stdin ) ) )
#endif
   {
      rl_attempted_completion_function = cli_completion;

      static fc::thread getline_thread("getline");
      getline_thread.async( [&](){
         char* line_read = nullptr;
         std::cout.flush(); //readline doesn't use cin, so we must manually flush _out
         line_read = readline(prompt.c_str());
         if( line_read == nullptr )
            FC_THROW_EXCEPTION( fc::eof_exception, "" );
         rl_bind_key( '\t', rl_complete );
         if( allow_history && *line_read )
            add_history(line_read);
         line = line_read;
         free(line_read);
      }).wait();
   }
   else
#endif
   {
      std::cout << prompt;
      // sync_call( cin_thread, [&](){ std::getline( *input_stream, line ); }, "getline");
      fc::getline(fc::cin, line);
   }
}

} } // namespace fc::rpc
