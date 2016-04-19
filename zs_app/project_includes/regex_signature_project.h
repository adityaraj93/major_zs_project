#ifndef __PROJECT_INCLUDES_REGEX_SIGNATURE_PROJECT
#define __PROJECT_INCLUDES_REGEX SIGNATURE_PROJECT 1

#define TOTAL_SIGNATURES 4

const char signature_names[TOTAL_SIGNATURES][10]={	"HTTP\0",
						 	"ssh\0",
							"ssl\0",
							"ftp\0"};
const char signatures[TOTAL_SIGNATURES][500]={	"http/(0\\.9|1\\.0|1\\.1) [1-5][0-9][0-9]",//  [\\x09-\\x0d -~]*(connection:|content-type:|content-length:|date:)|post [\\x09-\\x0d -~]* http/[01]\\.[019]",
						"^ssh-[12]\\.[0-9]",
						"^(.?.?\\x16\\x03.*\\x16\\x03|.?.?\\x01\\x03\\x01?.*\\x0b)",
						"^220[\\x09-\\x0d -~]*ftp"};

#endif /* project_includes/regex_signature_project.h */
