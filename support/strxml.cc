//
// Copyright 2008 Perforce Software.  All rights reserved.
//
// This file is part of Perforce - the FAST SCM System.
//
// StrXml:
//   XML output methods class
//
//    Instructions for using:
//
//    You must call XMLHeader() to generate the header for your XML;
//    Call XMLOutput*() when you get an p4api callback of type Output*()
//        e.g. call XMLOutputStat() when you get an OutputStat() callback;
//    You must call XMLEnd() when you are done.
//
//    StrXml is a child of StrBuf; the XML itself is generated in the
//    implicit StrBuf.  You can use <<, .Clear(), .Set(), etc. to
//    obtain the generated XML or add you own data to the stream.
//
//    See //depot/main/p4-web/Panes/p4wMimeContentPane.cpp for a useage example


// -------------------------------------
// Includes
//

# include <stdhdrs.h>
# include <strbuf.h>
# include <strdict.h>
# include <strops.h>
# include <time.h>
# include <ctype.h>
# include <strxml.h>

#define    NBRPREFIX    "_"

void
StrXml::XMLHeader( const StrPtr *cmd, const StrPtr *args, const StrPtr *port, 
	       const StrPtr *user, const StrPtr *client, int bUnicode )
{
	*this << "<?xml version='1.0' encoding='";

	fUnicode = bUnicode;
	if ( bUnicode )
	    *this << "UTF-8";
	else
	    *this << "ISO-8859-1";

	fP4Cmd.Set(cmd);
	*this << "'?>\n<perforce command=\"" << cmd;
	if ( args->Length() )
	    *this << "\" args=\"" << EscapeHTML(StrRef(args->Text()));

	*this << "\" server=\"" << EscapeHTML(StrRef(port->Text()));
	*this << "\" user=\"" << EscapeHTML(StrRef(user->Text()));
	*this << "\" client=\"" << EscapeHTML(StrRef(client->Text()));

	char time_buffer[255 + 1];
	time_buffer[0] = '\0';
	StrBuf time_format;
	time_format.Append( "%a, %d %b %Y %H:%M:%S %Z" );
	time_t iTime;
	time( &iTime );                
	strftime( time_buffer, sizeof( time_buffer ), time_format.Text(), 
	            localtime( &iTime ) );
	*this << "\" time=\"" << time_buffer << "\">\n";
}

void
StrXml::XMLOutputStat( StrDict * varList )
{
	int i;
	int seenXML = 0;
	StrBuf msg;
	StrRef var, val;

	// Dump out the variables, using the GetVar( x ) interface.
	// Don't display the function (duh), which is only relevant to rpc.

	for( i = 0; varList->GetVar( i, var, val ); i++ )
	{
	    if( var == "func" )
	        continue;

	    if( var == "specdef" )
	    {
	        *this << "<specdef>" << val << "</specdef>\n";
	        continue;
	    }

	    if (!seenXML)
	    {
	        seenXML++;
	        *this << "<" << fP4Cmd << ">\n";
	    }

	    char *p = var.Text();
	    if (*(p + var.Length() - 1) == '0')
	    {
	        i = XMLlist( varList, i );
	        continue;
	    }

	    StrBuf varbuf( var );
	    StrOps::Lower( varbuf );
	    var = varbuf;

	    *this << "<";
	    if (isdigit(*(var.Text())))
	        *this << NBRPREFIX;
	    *this << var;
	    if (val.Length())
	    {
	        if (strchr(val.Text(), '\n') || strchr(val.Text(), '\t') || strstr(val.Text(), "  "))
	            *this << ">\n<![CDATA[" << val << "]]>\n";
	        else
	            *this << ">" << EscapeHTML(val);
	        *this << "</";
	        if (isdigit(*(var.Text())))
	            *this << NBRPREFIX;
	        *this << var << ">\n";
	    }
	    else
	        *this << "/>\n";
	}
	if (seenXML)
	{
	    if (!strcmp(fP4Cmd.Text(), "annotate") && !fExtraTag.Length())
	    {
	        fExtraTag << "fileLines";
	        *this << "<" << fExtraTag << ">\n";
	    }
	    else
	        *this << "</" << fP4Cmd << ">\n";
	}
}

int
StrXml::XMLlist( StrDict * varList, int i, char * remove, char *nextup )
{
	StrRef vary, val;
	StrBuf var;
	char *p;
	varList->GetVar( i, vary, val );

	StrBuf listtag;
	if (isdigit(*(vary.Text())))
	    listtag << NBRPREFIX;
	listtag << vary.Text();

	StrOps::Lower( listtag );

	if (remove)
	{
	    p = strstr(listtag.Text(), remove);
	    if (p)
	    {
	        strcpy(p, p+strlen(remove));
	        listtag.SetLength();
	    }
	}

	p = listtag.Text();
	*(p + listtag.Length() - 1) = '\0';
	listtag.SetLength();

	*this << "<" << listtag << "s>\n";

	StrBuf sameas;
	StrBuf next;
	int nxt = 0;
	do
	{
	    var.Clear();
	    if (isdigit(*(vary.Text())))
	        var << NBRPREFIX;
	    var << vary;

	    StrOps::Lower( var );

	    if (remove)
	    {
	        p = strstr(var.Text(), remove);
	        if (p)
	        {
	            strcpy(p, p+strlen(remove));
	            var.SetLength();
	        }
	    }

	    sameas.Set(var.Text() + listtag.Length());
	    next.Clear();
	    next << listtag << ++nxt;

	    *this << "<" << listtag;
	    if (val.Length())
	        *this << " value=\"" << EscapeHTML(val) << "\"";
	    *this << " id1=\"";
	    if (remove)
	    {
	        StrBuf temp;
	        temp << remove;
	        if ((p = strchr(temp.Text(), ',')) != NULL)
	        {
	            *p = '\0';
	            temp.SetLength();
	        }
	        *this << temp << "\" id2=\"";
	    }
	    *this << sameas << "\">\n";

	    while (    varList->GetVar( ++i, vary, val ) )
	    {
	        var.Clear();
	        if (isdigit(*(vary.Text())))
	            var << NBRPREFIX;
	        var << vary;

	        StrOps::Lower( var );

	        if (remove)
	        {
	            p = strstr(var.Text(), remove);
	            if (p)
	            {
	                strcpy(p, p+strlen(remove));
	                var.SetLength();
	            }
	        }

	        if (!strcmp(next.Text(), var.Text()))
	            break;
	        if (nextup && !strcmp(nextup, var.Text()))
	            break;

	        p = strchr(var.Text(), ',');
	        if (p)
	        {
	            StrBuf rmv;
	            rmv << p - sameas.Length();
	            *(rmv.Text() + sameas.Length() + 1) = '\0';
	            rmv.SetLength();
	            i = XMLlist( varList, i, rmv.Text(), next.Text() );
	            continue;
	        }

	        if (strcmp(var.Text() + var.Length() - sameas.Length(), sameas.Text()))
	            break;

	        *(var.Text() + var.Length() - sameas.Length()) = '\0';
	        var.SetLength();
	        *this << "<" << var;
	        if (val.Length())
	        {
	            *this << ">" << EscapeHTML(val);
	            *this << "</" << var << ">\n";
	        }
	        else
	            *this << "/>\n";
	    }

	    *this << "</" << listtag << ">\n";
	} while (varList->GetVar( i, vary, val ) && !strcmp(next.Text(), var.Text()));

	*this << "</" << listtag << "s>\n";

	return --i;
}

StrBuf& StrXml::EscapeHTML(const StrPtr &s, int isUnicode)
{
	fEscapeBuf.Clear();    // holds output

	//
	// Search for, and escape, <>&'s to &gt; &lt; and &amp;
	int i=0;
	for( const char * p = s.Text(); *p != '\0'; p++, i++ ) {
	    unsigned char first = *p;
	    
	    //
	    // See if we need to escape this character.
	    if( first == '<' ) {
	        fEscapeBuf.Append("&lt;");
	    } else if( first == '>' ) {
	        fEscapeBuf.Append("&gt;");
	    } else if( first == '&' ) {
	        fEscapeBuf.Append("&amp;");
	    } else if( first == '"' ) {
	        fEscapeBuf.Append("&quot;");
	    } else if ( first > 0x7F && !isUnicode ) {
	        //
	        // If it is outside of ascii, just use the numeric
	        // value
	        //
	        fEscapeBuf.Append( "&#" );
	        fEscapeBuf << (unsigned int)first;
	        fEscapeBuf.Append( ";" );
	    } else {
	        fEscapeBuf.Append(p, 1);
	    }
	}

	//
	// We're done.
	return fEscapeBuf;
}


void
StrXml::XMLOutputError( char *data )
{

	*this << "<error>\n<![CDATA[\n" << EscapeHTML(StrRef(data)) << "]]>\n</error>\n";
}

void
StrXml::XMLOutputText( char *data )
{
	*this << "<text>\n<![CDATA[\n" << EscapeHTML(StrRef(data)) << "]]>\n</text>\n";
}

void
StrXml::XMLOutputInfo(char *data, char level)
{
	*this << "<info>\n<![CDATA[\n" << EscapeHTML(StrRef(data)) << "]]>\n</info>\n";
}

void
StrXml::XMLEnd()
{
	if (fExtraTag.Length())
	{
	    *this << "</" << fExtraTag << ">\n";
	    *this << "</" << fP4Cmd << ">\n";
	}
	*this << "</perforce>\n";
}
