#include <stdio.h>
#include <string.h>

void vulnerable_function(char *str)
{
    char buffer[10]; // Allocate 10 bytes
    // Dangerous: strcpy does not check if str fits in buffer
    strcpy(buffer, str);
    printf("Buffer content: %s\n", buffer);
}

int main()
{
    // Input is longer than 10 bytes, causing an overflow
    char *large_input = "This string is definitely longer than ten bytes";
    vulnerable_function(large_input);
    return 0;
}
