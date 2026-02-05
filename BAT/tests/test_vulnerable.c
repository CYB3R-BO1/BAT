/*
 * Test cases for BAT vulnerability detection
 * Contains intentional vulnerabilities for testing
 * DO NOT USE IN PRODUCTION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================
 * BUFFER OVERFLOW VULNERABILITIES
 * CWE-787, CWE-120
 * ============================================ */

// Vulnerable: strcpy without bounds checking
void buffer_overflow_strcpy(char *user_input)
{
    char buffer[32];
    strcpy(buffer, user_input); // VULNERABLE: No bounds check
    printf("Copied: %s\n", buffer);
}

// Vulnerable: gets is always dangerous
void buffer_overflow_gets()
{
    char buffer[64];
    printf("Enter name: ");
    gets(buffer); // VULNERABLE: Never use gets
    printf("Hello, %s\n", buffer);
}

// Vulnerable: sprintf without size limit
void buffer_overflow_sprintf(char *name, int age)
{
    char buffer[50];
    sprintf(buffer, "Name: %s, Age: %d", name, age); // VULNERABLE
    printf("%s\n", buffer);
}

// Vulnerable: strcat without checking destination size
void buffer_overflow_strcat(char *suffix)
{
    char greeting[20] = "Hello, ";
    strcat(greeting, suffix); // VULNERABLE: May overflow
    printf("%s\n", greeting);
}

/* ============================================
 * USE-AFTER-FREE VULNERABILITIES
 * CWE-416
 * ============================================ */

// Vulnerable: Using pointer after free
void use_after_free_basic()
{
    char *data = malloc(100);
    strcpy(data, "sensitive data");

    // ... some operations ...

    free(data);

    // VULNERABLE: Use after free
    printf("Data: %s\n", data);
}

// Vulnerable: Double free
void double_free_vuln()
{
    char *ptr = malloc(50);
    strcpy(ptr, "test");

    free(ptr);
    // ... some code ...
    free(ptr); // VULNERABLE: Double free
}

// Vulnerable: UAF in struct
typedef struct
{
    char *name;
    int id;
} User;

void use_after_free_struct()
{
    User *user = malloc(sizeof(User));
    user->name = malloc(50);
    user->id = 123;

    strcpy(user->name, "Alice");

    free(user);

    // VULNERABLE: Accessing freed struct
    printf("User ID: %d\n", user->id);
}

/* ============================================
 * INTEGER OVERFLOW VULNERABILITIES
 * CWE-190
 * ============================================ */

// Vulnerable: Integer overflow in malloc size
void integer_overflow_malloc(int count)
{
    // VULNERABLE: count * sizeof(int) may overflow
    int *array = malloc(count * sizeof(int));
    if (array == NULL)
        return;

    for (int i = 0; i < count; i++)
    {
        array[i] = i; // May write out of bounds if overflow occurred
    }

    free(array);
}

// Vulnerable: Size calculation overflow
void integer_overflow_memcpy(char *src, size_t len)
{
    size_t buffer_size = len * 4; // VULNERABLE: May overflow
    char *buffer = malloc(buffer_size);

    if (buffer)
    {
        memcpy(buffer, src, len * 4); // Uses overflowed size
        free(buffer);
    }
}

/* ============================================
 * SAFE ALTERNATIVES (For comparison)
 * ============================================ */

// Safe: Using strncpy with null termination
void safe_string_copy(char *user_input)
{
    char buffer[32];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Copied: %s\n", buffer);
}

// Safe: Using fgets instead of gets
void safe_input()
{
    char buffer[64];
    printf("Enter name: ");
    if (fgets(buffer, sizeof(buffer), stdin) != NULL)
    {
        // Remove newline if present
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n')
        {
            buffer[len - 1] = '\0';
        }
        printf("Hello, %s\n", buffer);
    }
}

// Safe: Using snprintf
void safe_sprintf(char *name, int age)
{
    char buffer[50];
    snprintf(buffer, sizeof(buffer), "Name: %s, Age: %d", name, age);
    printf("%s\n", buffer);
}

// Safe: Null after free
void safe_free()
{
    char *data = malloc(100);
    strcpy(data, "sensitive data");

    free(data);
    data = NULL; // Safe: Set to NULL after free

    if (data != NULL)
    {
        printf("Data: %s\n", data);
    }
}

// Safe: Overflow check before malloc
void safe_malloc(size_t count)
{
    if (count > SIZE_MAX / sizeof(int))
    {
        fprintf(stderr, "Integer overflow detected\n");
        return;
    }

    int *array = malloc(count * sizeof(int));
    if (array == NULL)
        return;

    for (size_t i = 0; i < count; i++)
    {
        array[i] = (int)i;
    }

    free(array);
}

/* ============================================
 * MAIN - Test harness
 * ============================================ */

int main(int argc, char *argv[])
{
    printf("BAT Test Cases - Vulnerable C Code\n");
    printf("===================================\n\n");

    if (argc < 2)
    {
        printf("Usage: %s <test_input>\n", argv[0]);
        return 1;
    }

    // These would trigger vulnerabilities:
    // buffer_overflow_strcpy(argv[1]);
    // buffer_overflow_gets();
    // use_after_free_basic();
    // integer_overflow_malloc(atoi(argv[1]));

    // Safe alternatives:
    safe_string_copy(argv[1]);
    safe_sprintf("Test", 42);
    safe_malloc(10);

    return 0;
}
