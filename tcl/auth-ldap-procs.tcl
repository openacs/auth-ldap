ad_library {
    Drrivers for authentication, account management, and password management over LDAP.

    @author Lars Pind (lars@collaobraid.biz)
    @creation-date 2003-05-13
    @cvs-id $Id$
}

namespace eval auth {}
namespace eval auth::ldap {}
namespace eval auth::ldap::authentication {}
namespace eval auth::ldap::password {}


ad_proc -private auth::ldap::after_install {} {} {
    set spec {
        contract_name "auth_authentication"
        owner "auth-ldap"
        name "LDAP"
        pretty_name "LDAP"
        aliases {
            Authenticate auth::ldap::authentication::Authenticate
            GetParameters auth::ldap::authentication::GetParameters
        }
    }

    set auth_impl_id [acs_sc::impl::new_from_spec -spec $spec]

    set spec {
        contract_name "auth_password"
        owner "ldap-auth"
        name "LDAP"
        pretty_name "LDAP"
        aliases {
            CanChangePassword auth::ldap::password::CanChangePassword
            ChangePassword auth::ldap::password::ChangePassword
            CanRetrievePassword auth::ldap::password::CanRetrievePassword
            RetrievePassword auth::ldap::password::RetrievePassword
            CanResetPassword auth::ldap::password::CanResetPassword
            ResetPassword auth::ldap::password::ResetPassword
            GetParameters auth::ldap::password::GetParameters
        }
    }

    set pwd_impl_id [acs_sc::impl::new_from_spec -spec $spec]
}

ad_proc -private auth::ldap::before_uninstall {} {} {

    acs_sc::impl::delete -contract_name "auth_authentication" -impl_name "LDAP"

    acs_sc::impl::delete -contract_name "auth_password" -impl_name "LDAP"

}


ad_proc -private auth::ldap::check_password {
    password_from_ldap
    password_from_user
} {
    Checks a password from LDAP and returns 1 for match, 0 for no match or problem verifying.
    Supports MD5, SMD5, SHA, SSHA, and CRYPT.

    @param password_from_ldap The value of the userPassword attribute in LDAP, typically something like 
                              {SSHA}H1W8YiEXl5lwzc7odaU73pNDun9uHRSH.
           
    @param password_from_user The password entered by the user.

    @return 1 if passwords match, 0 otherwise.
} {
    set result 0

    if { [regexp "{(.*)}(.*)" $password_from_ldap match cypher digest_base64] } {
        switch [string toupper $cypher] {
            MD5 - SMD5 {
                set digest_from_ldap [base64::decode $digest_base64]
                set hash_from_ldap [string range $digest_from_ldap 0 15]
                set salt_from_ldap [string range $digest_from_ldap 16 end]
                set hash_from_user [binary format H* [md5::md5 "${password_from_user}${salt_from_ldap}"]]
                if { [string equal $hash_from_ldap $hash_from_user] } {
                    set result 1
                }
            }
            SHA - SSHA {
                set digest_from_ldap [base64::decode $digest_base64]
                set hash_from_ldap [string range $digest_from_ldap 0 19]
                set salt_from_ldap [string range $digest_from_ldap 20 end]
                set hash_from_user [binary format H* [ns_sha1 "${password_from_user}${salt_from_ldap}"]]
                if { [string equal $hash_from_ldap $hash_from_user] } {
                    set result 1
                }
            }
            CRYPT {
                set hash_from_ldap $digest_base64
                set salt_from_ldap [string range $digest_base64 0 1]
                set hash_from_user [ns_crypt $password_from_user $salt_from_ldap]
                if { [string equal $hash_from_ldap $hash_from_user] } {
                    set result 1
                }
            }
        }
    }
    return $result
}

#####
#
# LDAP Authentication Driver
#
#####


ad_proc -private auth::ldap::authentication::Authenticate {
    username
    password
    {parameters {}}
} {
    Implements the Authenticate operation of the auth_authentication 
    service contract for LDAP.
} {
    # Default parameters
    array set params $parameters

    # Default to failure
    set result(auth_status) auth_error

    # Find the user
    set lh [ns_ldap gethandle ldap]
    set search_result [ns_ldap search $lh -scope subtree $params(BaseDN) "($params(UsernameAttribute)=$username)"]
    ns_ldap releasehandle $lh

    if { [llength $search_result] != 1 } {
        return [array get result]
    }

    foreach { attribute value } [lindex $search_result 0] {
        if { [string equal $attribute "userPassword"] } {
            if { [auth::ldap::check_password [lindex $value 0] $password] } {
                set result(auth_status) ok
            }
            break
        }
    }
    
    set result(account_status) ok
    
    return [array get result]
}

ad_proc -private auth::ldap::authentication::GetParameters {} {
    Implements the GetParameters operation of the auth_authentication 
    service contract for LDAP.
} {
    return {
        BaseDN "Base DN when searching for users. Typically something like 'o=Your Org Name', or 'dc=yourdomain,dc=com'"
        UsernameAttribute "LDAP attribute to match username against, typically uid"
    }
}


#####
#
# Password Driver
#
#####

ad_proc -private auth::ldap::password::CanChangePassword {
    {parameters ""}
} {
    Implements the CanChangePassword operation of the auth_password 
    service contract for LDAP.
} {
    return 0
}

ad_proc -private auth::ldap::password::CanRetrievePassword {
    {parameters ""}
} {
    Implements the CanRetrievePassword operation of the auth_password 
    service contract for LDAP.
} {
    return 0
}

ad_proc -private auth::ldap::password::CanResetPassword {
    {parameters ""}
} {
    Implements the CanResetPassword operation of the auth_password 
    service contract for LDAP.
} {
    return 0
}

ad_proc -private auth::ldap::password::ChangePassword {
    username
    old_password
    new_password
    {parameters {}}
} {
    Implements the ChangePassword operation of the auth_password 
    service contract for LDAP.
} {
    # TODO
    
    return [array get result]
}

ad_proc -private auth::ldap::password::RetrievePassword {
    username
    parameters
} {
    Implements the RetrievePassword operation of the auth_password 
    service contract for LDAP.
} {
}

ad_proc -private auth::ldap::password::ResetPassword {
    username
    parameters
} {
    Implements the ResetPassword operation of the auth_password 
    service contract for LDAP.
} {
}

ad_proc -private auth::ldap::password::GetParameters {} {
    Implements the GetParameters operation of the auth_password
    service contract for LDAP.
} {
    return [list]
}
