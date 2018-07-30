/*
 * Copyright 2009 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

#include <stdhdrs.h>
#include <strbuf.h>
#include <error.h>
#include <ctype.h> // this might not be portable, or it should be part of stdhdrs.h
#include "regmatch.h"
#include "regexp.h"

// The actual implementation of the regex class is hidden here to avoid pulling
// the implementation class into the public header

class RegexBase {
public:
    RegexBase(RegMatch::regex_flags f) {
	flags = f;
    }

    virtual ~RegexBase() { }

    virtual void compile(const char *p, Error* e)  = 0;

    virtual int matches(const char * line, Error* e) = 0;
    virtual size_t matchBegin() const = 0;
    virtual size_t matchEnd() const = 0;

    const StrBuf& getPattern() const { return pattern; }

protected:
    StrBuf pattern;
    RegMatch::regex_flags flags;
};

static
char *
_stristr(const char *line, const char * pattern)
{
    for (const char * start = line; *start != 0; start++)
    {
	/* find start of pattern in string */
	while ((*start!=0) && (toupper(*start) != toupper(*pattern)))
	    start++;

	if (0 == *start)
	    return 0;

	const char * sptr = start;
	const char * pptr = pattern;

	while (toupper(*sptr) == toupper(*pptr))
	{
	    sptr++;
	    pptr++;

	    /* if end of pattern then pattern was found */

	    if (0 == *pptr)
		return (char *) start;
	}
    }

    return 0;
}


class RegexFixed : public RegexBase 
{
private:
    size_t begin;
    size_t end;

public:
    RegexFixed(RegMatch::regex_flags f) : RegexBase(f) 
    {
	begin = end = 0;
    }

    virtual void compile(const char *p, Error* e) 
    {
	pattern = p;
    }

    virtual int matches(const char * line, Error* e) 
    {
	begin = end = 0;

	const char *m = flags & RegMatch::icase ? 
		_stristr( line, pattern.Text() ) : 
		  strstr( line, pattern.Text() ) ;

	if( m ) 
	{
	    begin = m - line;
	    end = begin + pattern.Length();
	}

	return (flags & RegMatch::inverse) ? m == 0 : m != 0;
    }

    virtual size_t matchBegin() const { return begin; }
    virtual size_t matchEnd() const { return end; }

};

class Regex : public RegexBase {
public:
    Regex(RegMatch::regex_flags f) : RegexBase(f) {
	reg = new V8Regex();
	lastMatchedLine = 0;
    }

    virtual void compile(const char *p, Error *e) {
	pattern = p;

	if( flags & RegMatch::icase) {
	    for (char *s = pattern.Text(); *s != 0; ++s) {
		*s = toupper(*s);
	    }
	}

	reg->compile(pattern.Text(), e);
	lastMatchedLine = 0;
    }

    virtual ~Regex() {
	delete reg;
    }

    virtual int matches(const char * line, Error* e) {
	if( flags & RegMatch::icase ) {
	    StrBuf lineBuf = line;
	    for (char *s = lineBuf.Text(); *s != 0; ++s) {
		*s = toupper(*s);
	    }
	    lastMatchedLine = lineBuf.Text();
	    int result = reg->match( lineBuf.Text(), e );
	    return (flags & RegMatch::inverse) ? !result : result;
	}
	else {
	    lastMatchedLine = line;
	    int result = reg->match( line, e );
	    return (flags & RegMatch::inverse) ? !result : result;
	}
    }

    virtual size_t matchBegin() const {
	if( lastMatchedLine )
	    return reg->matchBegin() - lastMatchedLine;
	return 0;
    }

    virtual size_t matchEnd() const {
	if( lastMatchedLine )
	    return reg->matchEnd() - lastMatchedLine;
	return 0;
    }

private:
    V8Regex * reg;
    const char *lastMatchedLine; // for matchBegin and matchEnd
};

void
RegMatch::alloc()
{
    if( flags & RegMatch::fixed ) {
	impl = new RegexFixed( flags );
    }
    else {
	impl = new Regex( flags );
    }
}

RegMatch::RegMatch(RegMatch::regex_flags f)
{
    flags = f;
    impl = 0;
}

RegMatch::~RegMatch()
{
    delete impl;
}

void
RegMatch::compile(const char *pattern, Error* e)
{
    delete impl;
    alloc();

    impl->compile(pattern, e);
}

int
RegMatch::matches(const char *line, Error* e)
{
    return impl->matches(line, e);
}

size_t
RegMatch::begin() const
{
    if( flags & RegMatch::inverse )
	return 0;

    return impl->matchBegin();
}

size_t
RegMatch::end() const
{
    if( flags & RegMatch::inverse )
	return 0;

    return impl->matchEnd();
}

const StrBuf&
RegMatch::getPattern() const
{
    return impl->getPattern();
}
