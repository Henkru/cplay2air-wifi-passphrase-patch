#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mman.h>

#define BASE_ADDR 0x10000
#define SECTION_SIZE 0x5f000
#define PASSWD_OFFSET 0x4f580

// Source: https://gist.github.com/ccbrown/9722406
void dump_hex(const void *data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i)
    {
        printf("%02X ", ((unsigned char *) data)[i]);
        if (((unsigned char *) data)[i] >= ' ' && ((unsigned char *) data)[i] <= '~')
        {
            ascii[i % 16] = ((unsigned char *) data)[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            printf(" ");
            if ((i + 1) % 16 == 0)
            {
                printf("|  %s \n", ascii);
            }
            else if (i + 1 == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8)
                {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j)
                {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

// Source: https://stackoverflow.com/questions/4770985/how-to-check-if-a-string-starts-with-another-string-in-c
int starts_with(const char *pre, const char *str)
{
    size_t lenpre = strlen(pre);
    size_t lenstr = strlen(str);
    return lenstr < lenpre ? 0 : memcmp(pre, str, lenpre) == 0;
}

// Source: https://stackoverflow.com/questions/122616/how-do-i-trim-leading-trailing-whitespace-in-a-standard-way
void trim_whitespace(char *str)
{
    char *end;

    if (*str == 0)  // All spaces?
        return;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char) *end)) end--;

    // Write new null terminator character
    end[1] = '\0';
}

char *get_password(const char *filepath)
{
    FILE * stream;
    char *line = NULL;
    size_t len = 0;
    char *passwd = NULL;

    stream = fopen(filepath, "r");
    if (stream == NULL)
        return NULL;

    while (getline(&line, &len, stream) != -1)
    {
        if (starts_with("wpa_passphrase=", line))
        {
            trim_whitespace(line);
            char *value = line + strlen("wpa_passphrase=");
            size_t length = strlen(value);
            passwd = malloc(length + 1);
            if (passwd)
            {
                strcpy(passwd, value);
            }
            break;
        }
    }

    free(line);
    fclose(stream);
    return passwd;
}

void __attribute__((constructor)) run_me_at_load_time()
{
    char prog_name[PATH_MAX];

    memset(prog_name, 0, sizeof(prog_name));
    readlink("/proc/self/exe", prog_name, sizeof(prog_name) - 1);

    if (strcmp(prog_name, "/usr/sbin/ARMiPhoneIAP2_org") == 0)
    {
        printf("\n[+] Inject.so Loaded!\n");
        printf("[*] PID: %d\n", getpid());
        printf("[*] Process: %s\n", prog_name);

        // Get the current password from the config file
        // and ensure the length is exactly 8
        char *new_passwd = get_password("/etc/hostapd.conf");
        if (new_passwd == NULL)
        {
            printf("[-] Error: Could not find the wpa_passhare from /etc/hostapd.conf\n");
            return;
        }

        if (strlen(new_passwd) != 8)
        {
            printf("[-] Error: The password must be 8 characters\n");
            free(new_passwd);
            return;
        }

        // Calculate the absolute location for patch location
        void *passwd = (void*)(BASE_ADDR + PASSWD_OFFSET);

        printf("[+] Original value:\n");
        dump_hex(passwd, 16);

        // Add write access
        if (mprotect((void*) BASE_ADDR, SECTION_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC))
        {
            printf("[-] Error: Could not change access rights\n");
            free(new_passwd);
            return;
        }

        // Patch the password and remove the write access
        memcpy(passwd, (void*) new_passwd, 8);
        mprotect((void*) BASE_ADDR, SECTION_SIZE, PROT_READ | PROT_EXEC);
        printf("[+] Password patched!\n");

        printf("[+] Patched value:\n");
        dump_hex(passwd, 16);

        free(new_passwd);
    }
}
