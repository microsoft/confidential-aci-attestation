#ifndef UVM_ENDORSEMENTS_H
#define UVM_ENDORSEMENTS_H

// Attempts to read the UVM endorsements from the ACI security context.
// If those files aren't present, returns an example version.
// Caller must free the returned string.
char* get_uvm_endorsements(void);

#endif // UVM_ENDORSEMENTS_H