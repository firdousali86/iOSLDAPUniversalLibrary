//
//  OpenLDAP.m
//  OpenLDAP
//
//  Created by Firdous on 29/02/2016.
//  Copyright © 2016 TenPearls. All rights reserved.
//

#import "OpenLDAP.h"
#include "ldap.h"
#import <Foundation/Foundation.h>
#include <stdio.h>

LDAP *
ldap_init( LDAP_CONST char *defhost, int defport );
int
ldap_simple_bind_s( LDAP *ld, LDAP_CONST char *dn, LDAP_CONST char *passwd );
int
ldap_unbind( LDAP *ld );

int isADUserAuthentic(LDAP_CONST char *defhost, int defport, LDAP_CONST char *binddn, LDAP_CONST char *passwd ){
    LDAP          *ld;
    int           version, rc;
    
    /* STEP 1: Get a handle to an LDAP connection and
     set any session preferences. */
    if ( (ld = ldap_init( defhost, defport )) == NULL ) {
        perror( "ldap_init" );
        return LDAP_STATUS_NOTCONNECTED;
    }
    
    /* Use the LDAP_OPT_PROTOCOL_VERSION session preference to specify
     that the client is an LDAPv3 client. */
    version = LDAP_VERSION3;
    ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );
    
    /* STEP 2: Bind to the server.
     In this example, the client binds anonymously to the server
     (no DN or credentials are specified). */
    rc = ldap_simple_bind_s( ld, binddn, passwd );
    if ( rc != LDAP_SUCCESS ) {
        fprintf(stderr, "ldap_simple_bind_s: %s\n", ldap_err2string(rc));
        return LDAP_STATUS_AUTHFAIL;
    }
    
    /* STEP 4: Disconnect from the server. */
    ldap_unbind( ld );
    
    return LDAP_STATUS_AUTHSUCCESS;
}

