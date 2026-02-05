#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Use-after-free vulnerability
void use_after_free_example()
{
    char *buffer = malloc(64);
    if (buffer == NULL)
        return;

    strcpy(buffer, "Hello, World!");
    printf("Buffer: %s\n", buffer);

    free(buffer);

    // Bug: Using buffer after free
    printf("After free: %s\n", buffer);
}

// Double free vulnerability
void double_free_example()
{
    int *ptr = malloc(sizeof(int) * 10);
    if (ptr == NULL)
        return;

    ptr[0] = 42;
    free(ptr);

    // Some other code...
    int x = 5;

    // Bug: Double free
    free(ptr);
}

// Buffer overflow - stack based
void stack_buffer_overflow(char *input)
{
    char local_buffer[32];

    // Bug: No bounds checking
    strcpy(local_buffer, input);

    printf("Input: %s\n", local_buffer);
}

// Buffer overflow - heap based
void heap_buffer_overflow()
{
    char *heap_buf = malloc(16);
    if (heap_buf == NULL)
        return;

    // Bug: Writing more than allocated
    strcpy(heap_buf, "This string is definitely longer than 16 bytes!");

    free(heap_buf);
}

// Integer overflow in allocation
void integer_overflow_allocation(size_t n)
{
    // Bug: Integer overflow in multiplication
    int *array = malloc(sizeof(int) * n);
    if (array == NULL)
        return;

    for (size_t i = 0; i < n; i++)
    {
        array[i] = i;
    }

    free(array);
}

// Another integer overflow case
void integer_overflow_example2(int count)
{
    // Bug: Integer overflow without check
    size_t size = count * sizeof(long);
    char *data = malloc(size);
    if (data == NULL)
        return;

    memset(data, 0, size);
    free(data);
}

// Use after free with conditional
void conditional_uaf()
{
    char *ptr = malloc(100);
    int condition = 1;

    if (condition)
    {
        free(ptr);
    }

    // Bug: ptr might be freed
    if (ptr != NULL)
    {
        strcpy(ptr, "test");
    }
}

// Multiple allocations and frees
void complex_memory_pattern()
{
    char *a = malloc(10);
    char *b = malloc(20);
    char *c = malloc(30);

    if (a == NULL || b == NULL || c == NULL)
    {
        // Bug: Memory leak on partial allocation failure
        return;
    }

    strcpy(a, "short");
    strcpy(b, "medium length str");

    // Bug: Buffer overflow
    strcpy(c, "This is a very long string that exceeds 30 bytes easily");

    free(a);
    free(b);

    // Bug: Use after free of 'a'
    printf("a = %s\n", a);

    free(c);
}

// sprintf overflow
void sprintf_overflow()
{
    char buffer[8];
    int value = 12345678;

    // Bug: sprintf can overflow buffer
    sprintf(buffer, "%d", value);
}

// gets() usage - always dangerous
void gets_usage()
{
    char buffer[64];

    // Bug: gets is always dangerous
    printf("Enter input: ");
    gets(buffer);

    printf("You entered: %s\n", buffer);
}

// strcat overflow
void strcat_overflow()
{
    char dest[20] = "Hello, ";
    char *src = "World! This is a long string.";

    // Bug: strcat doesn't check bounds
    strcat(dest, src);
}

int main()
{
    printf("Vulnerable program examples\n");

    use_after_free_example();
    double_free_example();
    stack_buffer_overflow("This is a very long string that will overflow the buffer!");
    heap_buffer_overflow();
    integer_overflow_allocation(0xFFFFFFFF);
    integer_overflow_example2(0x7FFFFFFF);
    conditional_uaf();
    complex_memory_pattern();
    sprintf_overflow();
    gets_usage();
    strcat_overflow();

    return 0;
}
