#include <stdio.h>

int main(void)
{
    FILE *file;

    printf("File access test started.\n");

    file = fopen("sandbox_test.txt", "w");

    if (file == NULL)
    {
        perror("File access");
        return 1;
    }

    fprintf(file, "SecCage file access test.\n");

    fclose(file);

    printf("File was created successfully.\n");

    return 0;
}
