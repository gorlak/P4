# include <array>
# include "p4script53_redefines.h"

# ifndef OS_NT
// Avoid link warnings on tmpnam().
#define LUA_USE_POSIX
# endif

// Disable the stand-alone interpreter.
# define MAKE_LIB

#define SOL_CXX17_FEATURES 1
#define SOL_NO_COMPAT 1
// This causes an anonymous namespace error when luaconf.h is set to static.
#define SOL_CHECK_ARGUMENTS 1
#define SOL_USING_CXX_LUA 1
// TODO:  This is turned off so debug mode has the same output as
//        release - but does it hide stuff we might otherwise miss?
#define SOL_PRINT_ERRORS 0
// Isolate this copy of sol2 so it doesn't conflict with anything else.
#define sol p4sol53

# if defined(OS_NT) && defined(_MSC_VER)
#pragma warning( push )  
// Bogus?
// warning C4335: Mac file format detected: please convert the source file
//                to either DOS or UNIX format
#pragma warning( disable : 4335 )  
# endif
#include "sol2.hpp"
# ifdef OS_NT
#pragma warning( pop )
# endif

inline static sol::state *cast_sol_State( void* l )
{
	return static_cast< sol::state* >( l );
}
