#ifndef __PROJECT_INCLUDES_REGEX_SIGNATURE_PROJECT
#define __PROJECT_INCLUDES_REGEX SIGNATURE_PROJECT 1

#define TOTAL_SIGNATURES 1 

const char signature_names[TOTAL_SIGNATURES][10]={"HTTP\0"};
const char signatures[TOTAL_SIGNATURES][100]={"HTTP/(0\\.9|1\\.0|1\\.1) [1-5][0-9][0-9]"};

#endif /* project_includes/regex_signature_project.h */
