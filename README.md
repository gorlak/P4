# Perforce Open Source Command Line and API

This is the source code for the Perforce command line and API. See LICENSE
for all licensing information.


## Dependencies
Outside of a C/C++ compiler you will need Jam (Just Another Make), a build system
written by Christopher Seiwald. A source bundle can be found here: 

    https://swarm.workshop.perforce.com/files/guest/perforce_software/jam/jam-2.6.zip

Starting with the 2017.1 release, the P4API must be linked against OpenSSL (preferably the latest 1.0.2 patch). More details about how to obtain or build OpenSSL and now to build p4 against OpenSSL are included below.
    
## To build the Perforce command line interface
From the root of the p4 source run:

    jam p4

Jam may ask you to specify an OS version if it cannot determine it. For example
on OS X running 'jam p4' will return:

    Set OSVER to 104, 105, or 106 for MACOSX 

To set any options in Jam use the '-s' flag. For the example above you would run:

    jam -sOSVER=106 p4

To build on Cygwin run:

    jam -sOS=CYGWIN

To build on Windows or Linux you will need to disable use of Smartheap:

    jam -sSMARTHEAP=0 p4

Builds will be placed in a directory called 'p4-bin/bin.[OS][OSVER]' at the same level as your p4 directory.


## Building with SSL support
If you wish to build a pre-2017.1 p4 with support for SSL servers you will need to add '-sSSL=yes' to the Jam call (this is now the default).
Jam expect the OpenSSL libraries (libssl.a and libcrypto.a) in a directory named 'p4-bin/lib.[OS][OSVER]' and the OpenSSL headers (in a folder named openssl) in a directory named 'p4-bin/inc.[OS][OSVER]'. The base 'p4-bin' folder is the same directory mentioned above, one level above the p4 source.

### Obtaining OpenSSL
Most Linux distributions provide OpenSSL development packages. If such a package is installed you can use the '-sSSLLIBDIR' and '-sSSLINCDIR' jam arguments to specify the location of libraries and headers. For example (on Ubuntu):

    sudo apt-get install libssl-dev
    jam -sOSVER=26 -sSMARTHEAP=0 -sSSLLIBDIR=/usr/lib/x86_64-linux-gnu/ -sSSLINCDIR=/usr/include/ p4
    
Pre-compiled OpenSSL builds for a number of platforms are available from a number of 3rd-party sources. We make no recommendations regarding these. For more information, please see the OpenSSL binary distribution page:

    https://www.openssl.org/community/binaries.html
    
### Building OpenSSL
OpenSSL builds on a wide range of platforms, with many build options: more than can be sensibly documented here. As such, this will only cover the steps to build the OpenSSL libraries with the same options as we build internally.

First, you'll need to get the latest OpenSSL 1.0.2 release from the OpenSSL downloads page:

    https://www.openssl.org/source/

Once you've confirmed the checksum of the tarball and extracted the OpenSSL source, cd into the openssl-1.0.2* folder. We recommend reading the provided build documentation, so the following sets of commands are only for reference (they are not guaranteed to work if you do not have all of the appropriate OpenSSL dependencies. 

* Linux x86_64:

      make -s -f Makefile.org dclean
      ./Configure no-hw no-gost linux-x86_64 -m64 -Wa,--noexecstack shared -g -fPIC
      make depend build_libs build_apps

* MacOSX 10.6 x86_64 and Darwin 10.0 x86_64:

      export CC=gcc-4.2
      make -s -f Makefile.org dclean
      ./Configure no-hw no-gost darwin64-x86_64-cc shared -g -fPIC -isysroot/Developer/SDKs/MacOSX10.6.sdk -mmacosx-version-min=10.5
      make depend build_libs build_apps
    
* Windows x64 VS12 (Visual Studio 2013 + NASM):

      perl ./Configure no-shared no-hw no-gost VC-WIN64A -Zi 
      cmd.exe /c ms\do_win64a.bat 
      nmake -f ms\nt.mak
    
To build p4 using your OpenSSL build, either copy the libraries and headers into the appropriate default locations under 'p4-bin' as described above, or use the '-sSSLLIBDIR' and '-sSSLINCDIR' jam arguments to specify the location of libraries and headers.
    
## To build the Perforce API
From the root of the p4 source run:

    jam -sPRODUCTION=1 p4api.tar

As with building p4, Jam may ask you to specify an OS version.

