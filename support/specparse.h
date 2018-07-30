/*
 * Copyright 1995, 1996 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */


enum SpecParseReturn {  
	SR_EOS,
	SR_TAG,
	SR_VALUE,
	SR_COMMENT,
	SR_COMMENT_NL,
	SR_DONEV
};

class SpecParse {
	
    public:

			SpecParse( const char *buffer );

	SpecParseReturn	GetToken( int isTextBlock, StrBuf *value, Error *e );
			
	void		ErrorLine( Error *e );

    private:

	SpecChar	c;
	int		state;
	int		savedBlankLines;
	int		addNewLine;

} ;

