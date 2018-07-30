/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of the Library RCS.  See rcstest.c.
 */

/*
 * rcsgen.h - write a new RCS file, given an RcsArchive structure
 *
 * Classes defines:
 *
 *	RcsGenFile - control block for generating a new RCS file
 *
 * Public methods:
 *
 *	RcsGenFile::Generate() - write out an RcsArchive to a stdio file
 *
 * History:
 *	2-18-97 (seiwald) - translated to C++.
 */

class FileSys;

class RcsGenFile {

    public:
			RcsGenFile() : buf( FileSys::BufferSize() ) {}

	void		Generate( FileSys *wf, RcsArchive *ar, 
				Error *e, int fastformat );

    protected:

	void		GenList( RcsList *strings, int dostring, int dorev );
	void		GenChunk( RcsChunk *chunk, int fastformat );
	void 		GenString( const char *string );

	void		GenAt()		{ wf->Write( "@", 1, e ); }
	void		GenSemi()	{ wf->Write( ";", 1, e ); }
	void		GenSpace()	{ wf->Write( " ", 1, e ); }
	void		GenNum( int n )	
				{ wf->Write( StrNum( n ), e ); GenSpace(); }

	void		GenTxt( RcsText *t ) 
				{ wf->Write( t->text, t->len, e ); }

	void		GenLit( const char *str ) 
				{ wf->Write( str, strlen( str ), e ); }

	void		GenBuf( const char *b, int l ) 
				{ wf->Write( b, l, e ); }

	/* NT LF -> CRLF translation */

# ifdef USE_CRLF
	void		GenNL()		{ wf->Write( "\r\n", 2, e ); }
# else
	void		GenNL()		{ wf->Write( "\n", 1, e ); }
# endif

    protected:
	FileSys		*wf;
	Error		*e;

    private:
	StrFixed	buf;		// for forming @ strings

};

