/*
 * Copyright 1995, 2016 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class MapTable;

/*
 * ClientUserColor -- version of output that displays ANSI colors
 */

class ClientUserColor : public ClientUser {

    public:
			ClientUserColor( int forceColors = 0,
			                 int autoLoginPrompt = 1 );
			~ClientUserColor();

	virtual void	HandleError( Error* err );
	virtual void	Message( Error* err );
	virtual void	SetQuiet();

	virtual void	OutputAnsiInfo( char level, const char *data );

    private:
	int		ColorMessage( Error *err, int color, StrBuf &out,
				      int flag );
	void		FmtError( StrBuf &buf, Error *err, int opts,
				  StrDict *tags );
	void		OutputStream( const char *t, int l, FILE *s );
	void		OutputAnsiStream( const char *t, FILE *s );
	void		SetColor( int type, int fg, int bg, FILE *stream );
	void		ResetColor( FILE *stream );
	StrDict		*GetColors();
	int		GetColors( StrDict *tags, MapTable &c );

	StrDict		*colors;
	MapTable	*conditionals;
	int		quiet;
	int		outColor;
	int		errColor;

#ifdef OS_NT
	void		*hConsoleOut;
	void		*hConsoleErr;
	short		oldColors;
#endif
} ;

