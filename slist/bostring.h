

#ifndef bostring_h
#define bostring_h



/*

This defines an API to manipulate safely strings in C.

Strings can be arrays of char, of unsigned char, of (WCHAR), or of wchar_t.
There are mutable strings and immutable strings (initialized from const strings).

The actual representation of strings is configurable per string object.
The following formats are provided:

 - null-terminated <character> []
 - count + <character> []

*/


typedef struct string;
typedef struct mutable_string;


string *  string_from_uint8_string(const uint8 * cstring);
string *  string_from_uint16_string(const uint16 * cstring);
string *  string_from_uint32_string(const uint32 * cstring);

#endif
