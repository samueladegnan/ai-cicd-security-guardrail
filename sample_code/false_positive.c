/*
 * false_positive.c
 *
 * This file illustrates a common false-positive scenario: a static
 * analyzer may flag the local variable as "unused" even though it
 * improves readability and is used in a future expansion. The
 * guardrail's LLM triage should classify this as a false positive.
 */
#include <stdio.h>

int calculate(int a, int b) {
    /* Static analyzer might complain this variable is unused. */
    int result = a + b;
    return result;
}

int main(void) {
    int x = 10;
    int y = 20;
    printf("Sum = %d\n", calculate(x, y));
    return 0;
}
