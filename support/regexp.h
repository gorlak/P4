/*
 * Definitions etc. for regexp(3) routines.
 *
 * Caveat:  this is V8 regexp(3) [actually, a reimplementation thereof],
 * not the System V one.
 *
 * 11/04/02 (seiwald) - const-ing for string literals
 * 14/02/10 (sknop) - wrapped in a C++ class
 */

#define NSUBEXP  10
typedef struct regexp {
	const char *startp[NSUBEXP];
	const char *endp[NSUBEXP];
	char regstart;		/* Internal use only. */
	char reganch;		/* Internal use only. */
	char *regmust;		/* Internal use only. */
	int regmlen;		/* Internal use only. */
	char program[1];	/* Unwarranted chumminess with compiler. */
} regexp;

/*
 * The first byte of the regexp internal "program" is actually this magic
 * number; the start node begins in the second byte.
 */
#define	MAGIC	0234

class V8Regex
{
public:
    V8Regex();
    ~V8Regex();

public:
    void compile( const char *exp, Error *e );
    int match( const char *str, Error* e);
    const char * matchBegin() const;
    const char * matchEnd() const;
    size_t matchLen() const { return matchEnd() - matchBegin();  }

private:
    // internal methods for compile()
    char *reg( int paren, int *flagp );
    char *regbranch( int *flagp );
    char *regpiece( int *flagp );
    char *regatom( int *flagp );
    char *regnode( int op );
    char *regnext( char *p );
    void regc( int b );
    void reginsert( char op, char *opnd );
    void regtail( char *p, char *val );
    void regoptail( char *p, char *val );

    // internal methods for match()
    int regtry( regexp *prog, const char *str );
    int regmatch( char *prog );
    int regrepeat( char *p );

private:
    regexp * prog;
    Error * error;		// stored for subroutines

    // for compile
    char *regparse;		/* Input-scan pointer. */
    int regnpar;		/* () count. */
    char regdummy;
    char *regcode;		/* Code-emit pointer; &regdummy = don't. */
    long regsize;		/* Code size. */

    // for match
    const char *reginput;	/* String-input pointer. */
    char *regbol;		/* Beginning of input, for ^ check. */
    const char **regstartp;	/* Pointer to startp array. */
    const char **regendp;	/* Ditto for endp. */

};
