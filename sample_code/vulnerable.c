/*
 * vulnerable.c
 *
 * Intentionally insecure C code for demonstrating the AI-Driven
 * CI/CD Security Guardrail.  Do not use in production.
 */
#include <stdio.h>
#include <string.h>

void process_input(const char *input) {
    char buffer[64];

    /* Vulnerable to buffer overflow (CWE-121) */
    strcpy(buffer, input);

    printf("Processed: %s\n", buffer);
}

int main(void) {
    char user_input[256];

    printf("Enter input: ");
    fgets(user_input, sizeof(user_input), stdin);

    process_input(user_input);

    return 0;
}
