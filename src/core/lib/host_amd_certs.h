
#ifndef AMD_HOST_CERTS_H
#define AMD_HOST_CERTS_H


// Attempts to read the genuine host AMD certificates from the ACI security
// context. If those files aren't present, returns an example version. Caller
// must free the returned string.
char* get_host_amd_certs(void);


#endif // AMD_HOST_CERTS_H