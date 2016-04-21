#ifndef __PROJECT_INCLUDES_REGEX_SIGNATURE_PROJECT
#define __PROJECT_INCLUDES_REGEX SIGNATURE_PROJECT 1

#define TOTAL_SIGNATURES 7 

const char signature_names[TOTAL_SIGNATURES][10]={	"HTTP\0",
						 	"SSH\0",
							"SSL\0",
							"Filezilla\0",
							"vsFTPd\0",
							"FTP\0",
							"SMTP\0"};
const char signatures[TOTAL_SIGNATURES][500]={	"http/(0\\.9|1\\.0|1\\.1) [1-5][0-9][0-9]",
						"^ssh-[12]\\.[0-9]",
						"^(.?.?\\x16\\x03.*\\x16\\x03|.?.?\\x01\\x03\\x01?.*\\x0b)",
						"^220-FileZilla",
						"^220 \\(vsFTPd",
						"^220[\\x09-\\x0d -~]*ftp",
						"^220[\\x09-\\x0d -~]* (E?SMTP|[Ss]imple [Mm]ail)"};

#endif /* project_includes/regex_signature_project.h */
