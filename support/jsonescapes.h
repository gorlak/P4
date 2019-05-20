/*
 * Given a string and its length, look for and replace
 * any valid JSON escape sequences.
 */
void jsonEscapes( const char *input, int len, StrBuf &out );

/*
 * Given a string, look for and replace JSON invalid characters.
 */
void jsonEscape( const StrPtr *input, StrBuf &out );
