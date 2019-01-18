
 /*

This defines an API to manipulate lists of strings in C.

Strings can be arrays of char,  of unsigned char,  of (WCHAR), or of wchar_t.

The actual representation of string list is configurable;
the following formats are provided:

 - null-terminated <character> * []
 - count + <character>  * []
 - Microsoft msz format (unsigned char or WCHAR)
 - empty-string terminated <character> [maxstringlen] []
 - count +  <character> [maxstringlen] []

 */


typedef struct string;
typedef struct string_list;


string *  string_from_c_string_copy(const char * cString);
string *  string_with_c_string(char * cString);
