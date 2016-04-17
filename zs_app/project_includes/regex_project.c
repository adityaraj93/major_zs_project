#ifndef __PROJECT_INCLUDES_REGEX_PROJECT
#define __PROJECT_INCLUDES_REGEX_PROJECT 1


#include<regex.h>
#include "project.h"
#include "regex_signature_project.h"

#define REGEX_ERROR_MSG_SIZE 0x1000
#define MATCH_ERROR 2

/* 
*  Compiles the regex pattern.
*  Returns 0 if compiled without an error.
*  Returns 1 if any error occured.
*/

int compile_regex(regex_t *regex, const char *regex_expression)
{
	int status;
	if(status=regcomp(regex, regex_expression ,REG_EXTENDED|REG_NEWLINE|REG_ICASE))
	{
		printf("Regex compilation error: %s\n", regex_expression);
		char error_message[REGEX_ERROR_MSG_SIZE];
		regerror (status, regex, error_message, REGEX_ERROR_MSG_SIZE);
        printf ("Regex error compiling '%s': %s\n",
                 regex_expression, error_message);
        return 1;
	}
	return 0;
}
/*
*  Matches the to_match string with the compiled string.
*/
int match_regex(regex_t *regex, const char *to_match)
{
	int match;
	match = regexec(regex, to_match,0,NULL, 0 );
	if (!match)
	{
		return match;
	}
	else if (match == REG_NOMATCH)
	{
		//printf("No match");
		return REG_NOMATCH;
	}
	else
	{
		printf("Error in matching\n");
		return MATCH_ERROR;
	}
}

int control_regex(const char *packet_payload)
{
	regex_t regex;
	int i,match;
	for (i = 0; i < TOTAL_SIGNATURES; i ++)
	{
		if (!compile_regex(&regex, signatures[i]))
		{
			if(!(match=match_regex(&regex, packet_payload))){
				printf("%s-------------------------",signature_names[i]);
				return 1;
			}
			else if (match==REG_NOMATCH)
			{
				printf("Unknown");
				return 0;
			}
			else
			{
				printf("MATCH_ERROR");
				return 0;
			}
		}
	}
}

#endif /* project_includes/regex_project.c */ 
