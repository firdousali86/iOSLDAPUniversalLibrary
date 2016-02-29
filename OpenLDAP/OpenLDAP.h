//
//  OpenLDAP.h
//  OpenLDAP
//
//  Created by Firdous on 29/02/2016.
//  Copyright © 2016 TenPearls. All rights reserved.
//

#define LDAP_STATUS_AUTHFAIL        0
#define LDAP_STATUS_AUTHSUCCESS     1
#define LDAP_STATUS_NOTCONNECTED    2

int isADUserAuthentic(const char *defhost, int defport, const char *binddn, const char *passwd );