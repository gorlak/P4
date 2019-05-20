Implementation notes for Scripting support in the API
-----------------------------------------------------

The script-related classes are designed to support multiple different
scripting implementations - either separate languages, or multiple
versions of a single language.

Implementation details are hidden from callers with a combination of
the C++ PIMPL idiom (so header includes don't leak symbols - see
p4script.h), symbol redefinition (keeping the language runtime symbols
unique, preventing clash with customer programs and other versions of
the runtime - see p4script53_redefines.h) and using a single
compilation unit.  There are alternative approaches such as using
anonymous namespaces (to force internal linkage) or linker tools to
hide/rename symbols (e.g. using objcopy).  There are issues with
putting headers or libraries into separate namespaces, so that's not
recommended.  Note that luaconf.h has some provisions for controling
visibility as well.

Note that there are no references to Lua datatypes or signatures in
p4script.h so as not to require any of that for API users.  Functions
taking Lua datatypes as arguments use void* and casts.

Testing for symbol clash can be done by copying the existing script
implementation file and its symbol redefinition header into new files and
giving them new names - when building with the new files in LTO mode, you
would expect to see conflicts there it there are any.  One can also take
the library and link it to a sample program that uses the un-prefixed
versions of the 3rd-party code.

Lua itself is C code, but is compiled here as C++ so as to support
exceptions (which Sol can throw when something goes wrong - e.g. a
script returns the wrong datatype to a C++ function).  Lua compiled
as C uses longjmp when an error happens, and that isn't compatible
with exceptions or the stack unwinding necessary to call any bound C++
classes' destructors.

A consequence of Lua being built as C++ is that any native libraries
extending Lua (e.g. LuaSQLite) must be built as C++ so they can link
properly.  Lua-extending native libraries can however call down into
C, so that direction does not require any special consideration (e.g.
the LuaSQLite case where LuaSQLite needs to be C++ to talk with our
C++ copy of Lua, but itself then talks with the C-built SQLite.)

The 'lua-5.3' subdirectory omits the patch level since they're assumed
to be minor changes, not introducing incompatibilities.

The 'sol2' library provides a variety of mechanisms for bridging the
Lua/C++ gap.

  http://sol2.readthedocs.io/

The P4API classes are generally bound to Lua via C++ subclasses via
shared function pointers that Lua code can assign to.

There are some edits to the Lua source in support of various properties
we need (e.g. not doing blocking operations that we can't interrupt when
enforcing Max* limits).  Changes are:

  - the os.execute() edit in loslib.c.
