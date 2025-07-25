#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "lib/snp_report.h"
#include "lib/base64.h"


int main() {
    if (access("/dev/sev-guest", F_OK) == 0) {
        printf("SNP Version: 6 (SEV Guest)\n");
    } else if (access("/dev/sev", F_OK) == 0) {
        printf("SNP Version: 5 (SEV)\n");
    } else {
        printf("SNP Version: Virtual\n");
    }
}