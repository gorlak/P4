/*
 * Copyright 2009 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class RegexBase;

class RegMatch {
public:
    typedef enum {
	fixed = 0x01,
	grep = 0x02,
	egrep = 0x04,
	perl = 0x08,
	inverse = 0x10,
	icase = 0x20,
    } regex_flags;
public:
    RegMatch(RegMatch::regex_flags f = RegMatch::grep);
    ~RegMatch();

    void alloc();
    void compile(const char *pattern, Error* e);
    int matches(const char * line, Error* e);
    size_t begin() const;
    size_t end() const;
    size_t len() const { return end() - begin();  }
    regex_flags getFlags() const { return flags; }
    const StrBuf& getPattern() const;

private:
    RegexBase *impl;
    RegMatch::regex_flags flags;
};
