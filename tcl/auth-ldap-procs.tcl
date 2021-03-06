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
namespace eval auth::ldap::registration {}
namespace eval auth::ldap::user_info {}
namespace eval auth::ldap::search {}

ad_proc -private auth::ldap::after_install {} {} {
    set spec {
        contract_name "auth_authentication"
        owner "auth-ldap"
        name "LDAP"
        pretty_name "LDAP"
        aliases {
            MergeUser auth::ldap::authentication::MergeUser
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

    set spec {
        contract_name "auth_registration"
        owner "ldap-auth"
        name "LDAP"
        pretty_name "LDAP"
        aliases {
            GetElements auth::ldap::registration::GetElements
            Register auth::ldap::registration::Register
            GetParameters auth::ldap::registration::GetParameters
        }
    }

    set registration_impl_id [acs_sc::impl::new_from_spec -spec $spec]

    set spec {
        contract_name "auth_user_info"
        owner "ldap-auth"
        name "LDAP"
        pretty_name "LDAP"
        aliases {
            GetUserInfo auth::ldap::user_info::GetUserInfo
            GetParameters auth::ldap::user_info::GetParameters
        }
    }

    set user_info_impl_id [acs_sc::impl::new_from_spec -spec $spec]

    set spec {
        contract_name "auth_search"
        owner "ldap-auth"
        name "LDAP"
        pretty_name "LDAP"
        aliases {
            Search auth::ldap::search::Search
            GetParameters auth::ldap::search::GetParameters
            FormInclude auth::ldap::search::FormInclude
        }
    }

    set search_impl_id [acs_sc::impl::new_from_spec -spec $spec]

}

ad_proc -private auth::ldap::before_uninstall {} {} {

    acs_sc::impl::delete -contract_name "auth_authentication" -impl_name "LDAP"
    acs_sc::impl::delete -contract_name "auth_password" -impl_name "LDAP"
    acs_sc::impl::delete -contract_name "auth_registration" -impl_name "LDAP"
    acs_sc::impl::delete -contract_name "auth_user_info" -impl_name "LDAP"
}

ad_proc -private auth::ldap::get_user {
    {-element ""}
    {-username:required}
    {-parameters:required}
} {
    Find a user in LDAP by username, and return a list
    of { attribute value attribute value ... } or a specific attribute value,
    if the -element switch is set.
} {
    # Parameters
    array set params $parameters

    set lh [ns_ldap gethandle ldap]

    ad_try {
        ns_ldap search $lh -scope subtree $params(BaseDN) "($params(UsernameAttribute)=$username)"
    } on ok {search_result} {
    } on error {errorMsg} {
        error "ns_ldap search returns error: $errorMsg"
    } finally {
        ns_ldap releasehandle $lh
    }

    if { [llength $search_result] != 1 } {
        return [list]
    }

    if { $element eq "" } {
        return $search_result
    }

    foreach { attribute value } [lindex $search_result 0] {
        if {$attribute eq $element} {
            # Values are always wrapped in an additional list
            # not for dn (roc)
            if {$element eq "dn"} {
                return $value
            } else {
                return [lindex $value 0]
            }
        }
    }

    return {}
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
                package require md5
                set hash_from_user [md5::md5 -- ${password_from_user}${salt_from_ldap}]
                if {$hash_from_ldap eq $hash_from_user} {
                    set result 1
                }
            }
            SHA - SSHA {
                set digest_from_ldap [base64::decode $digest_base64]
                set hash_from_ldap [string range $digest_from_ldap 0 19]
                set salt_from_ldap [string range $digest_from_ldap 20 end]
                set hash_from_user [binary format H* [ns_sha1 "${password_from_user}${salt_from_ldap}"]]
                if {$hash_from_ldap eq $hash_from_user} {
                    set result 1
                }
            }
            CRYPT {
                set hash_from_ldap $digest_base64
                set salt_from_ldap [string range $digest_base64 0 1]
                set hash_from_user [ns_crypt $password_from_user $salt_from_ldap]
                if {$hash_from_ldap eq $hash_from_user} {
                    set result 1
                }
            }
        }
    }
    return $result
}

ad_proc -private auth::ldap::set_password {
    {-dn:required}
    {-new_password:required}
    {-parameters:required}
} {
    Update an LDAP user's password.
} {
    # Parameters
    array set params $parameters

    set password_hash [string toupper $params(PasswordHash)]
    set new_password_hashed {}

    switch $password_hash {
        MD5 {
            package require md5
            set new_password_hashed [md5::md5 $new_password]
        }
        SMD5 {
            package require md5
            set salt [ad_generate_random_string 4]
            set new_password_hashed [md5::md5 "${new_password}${salt}"]
            append new_password_hashed $salt
        }
        SHA {
            set new_password_hashed [binary format H* [ns_sha1 $new_password]]
        }
        SSHA {
            set salt [ad_generate_random_string 4]
            set new_password_hashed [binary format H* [ns_sha1 "${new_password}${salt}"]]
            append new_password_hashed $salt
        }
        CRYPT {
            set salt [ad_generate_random_string 2]
            set new_password_hashed [ns_crypt $new_password $salt]
        }
        default {
            error "Unknown hash method, $password_hash"
        }
    }

    set lh [ns_ldap gethandle ldap]

    ad_try {
        ns_ldap modify $lh $dn mod: userPassword [list "{$password_hash}[base64::encode $new_password_hashed]"]
    } on ok {result} {
    } on error {errorMsg} {
        error "ns_ldap modify returns error: $errorMsg"
    } finally {
        ns_ldap releasehandle $lh
    }
}


#####
#
# LDAP Authentication Driver
#
#####

ad_proc -private auth::ldap::authentication::MergeUser {
    from_user_id
    to_user_id
    {authority_id ""}
} {
    Implements the merge operation of the auth_authentication
    service contract for local_LDAP.
} {
    ns_log Notice "Running ldap MergeUser ..."
    auth::ldap::delete_user $from_user_id
    set msg "MergeUser is complete"
    ns_log Notice $msg
}

ad_proc -private auth::ldap::bind {
    lh
    fdn
    password
} {

    Call "ns_ldap bind" with provided ldap handle, fdn and password.
    In case the provided fdn is empty (result of a previous search
    command), or the "ns_ldap bind" raises an error, this function
    returns 0. Otherwise, it checks the password and reurns the
    boolean result

    @return boolean result
} {
    set result 0
    if { $fdn ne ""} {
        try {
            ns_ldap bind $lh $fdn $password
        } on error {errorMsg} {
            ns_log warning "ns_ldap bind returns error: $errorMsg"
        } on ok {
            set result 1
        }
    }
    return result
}

ad_proc -private auth::ldap::authentication::Authenticate {
    username
    password
    {parameters {}}
    {authority_id {}}
} {
    Implements the Authenticate operation of the auth_authentication
    service contract for LDAP.
} {
    # Parameters
    array set params $parameters

    # Default to failure
    set result(auth_status) auth_error

    if { $params(BindAuthenticationP) ne "" && $params(BindAuthenticationP) } {

        set lh [ns_ldap gethandle]

        #
        # First, find the user's FDN, then try an ldap bind with the
        # FDN and supplied password.
        #
        ad_try {
            ns_ldap search $lh -scope subtree \
                $params(BaseDN) \
                "($params(UsernameAttribute)=$username)" dn

        } on ok {ldap_search_result} {
            if {[auth::ldap::bind $lh [lindex $ldap_search_result 0 1] $password]} {
                set result(auth_status) ok
            }

        } on error {errorMsg} {
            error "ns_ldap search returns error: $errorMsg"

        } finally {
            ns_ldap disconnect $lh
            ns_ldap releasehandle $lh
        }

    } else {

        # Find the user
        set userPassword [auth::ldap::get_user \
                              -username $username \
                              -parameters $parameters \
                              -element "userPassword"]
        if { $userPassword ne "" && [auth::ldap::check_password $userPassword $password] } {
            set result(auth_status) ok
        }
    }

    # We do not check LDAP account status
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
        BindAuthenticationP "If you set this to 1, the driver will attempt to first find the user's fully distinguished name and then bind as that user. Otherwise, the driver will try to retrieve the password from LDAP and compare against the password provided"
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
    return 1
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
    return 1
}

ad_proc -private auth::ldap::password::ChangePassword {
    username
    new_password
    old_password
    {parameters {}}
    {authority_id {}}
} {
    Implements the ChangePassword operation of the auth_password
    service contract for LDAP.
} {
    # Parameters
    array set params $parameters

    set result(password_status) change_error

    # Find the user
    set search_result [auth::ldap::get_user -username $username -parameters $parameters]

    # More than one, or not found
    if { [llength $search_result] != 1 } {
        return [array get result]
    }

    set userPassword {}
    set dn {}
    foreach { attribute value } [lindex $search_result 0] {
        switch $attribute {
            userPassword {
                set userPassword [lindex $value 0]
            }
            dn {
                set dn $value
            }
        }
    }

    if { $dn ne "" && $userPassword ne "" } {

        set ok_to_change_password 0
        #
        # TODO: abstract this... -> remove duplicated code!
        #
        if { $params(BindAuthenticationP) ne "" && $params(BindAuthenticationP) } {

            set lh [ns_ldap gethandle]

            #
            # First, find the user's FDN, then try an ldap bind with the
            # FDN and supplied password.
            #
            ad_try {
                ns_ldap search $lh -scope subtree \
                    $params(BaseDN) \
                    "($params(UsernameAttribute)=$username)" dn

            } on ok {ldap_search_result} {

                if {[auth::ldap::bind $lh [lindex $ldap_search_result 0 1] $password]} {
                    set ok_to_change_password 1
                }

            } on error {errorMsg} {
                error "ns_ldap search returns error: $errorMsg"

            } finally {
                ns_ldap disconnect $lh
                ns_ldap releasehandle $lh
            }

        } else {

            if { [auth::ldap::check_password $userPassword $old_password] } {
                set ok_to_change_password 1
            }
        }
        if { ! $ok_to_change_password } {
            set result(password_status) old_password_bad
        } else {
            auth::ldap::set_password -dn $dn -new_password $new_password -parameters $parameters
            set result(password_status) ok
        }
    }

    return [array get result]
}

ad_proc -private auth::ldap::password::RetrievePassword {
    username
    parameters
} {
    Implements the RetrievePassword operation of the auth_password
    service contract for LDAP.
} {
    return { password_status not_supported }
}

ad_proc -private auth::ldap::password::ResetPassword {
    username
    parameters
    {authority_id {}}
} {
    Implements the ResetPassword operation of the auth_password
    service contract for LDAP.
} {
    # Parameters
    array set params $parameters

    set result(password_status) change_error

    # Find the user
    set dn [auth::ldap::get_user -username $username -parameters $parameters -element dn]

    if { $dn ne "" } {
        set new_password [ad_generate_random_string]

        auth::ldap::set_password -dn $dn -new_password $new_password -parameters $parameters

        set result(password_status) ok
        set result(password) $new_password
    }

    return [array get result]
}

ad_proc -private auth::ldap::password::GetParameters {} {
    Implements the GetParameters operation of the auth_password
    service contract for LDAP.
} {
    return {
        BaseDN "Base DN when searching for users. Typically something like 'o=Your Org Name', or 'dc=yourdomain,dc=com'"
        UsernameAttribute "LDAP attribute to match username against, typically uid"
        PasswordHash "The hash to use when storing passwords. Supported values are MD5, SMD5, SHA, SSHA, and CRYPT."
        UsernameAttribute "LDAP attribute to match username against, typically uid"
        BindAuthenticationP "If you set this to 1, the driver will attempt to first find the user's fully distinguished name and then bind as that user. Otherwise, the driver will try to retrieve the password from LDAP and compare against the password provided"
    }
}



#####
#
# Registration Driver
#
#####

ad_proc -private auth::ldap::registration::GetElements {
    {parameters ""}
} {
    Implements the GetElements operation of the auth_registration
    service contract.
} {
    set result(required) { username email first_names last_name }
    set result(optional) { password }

    return [array get result]
}

ad_proc -private auth::ldap::registration::Register {
    parameters
    username
    authority_id
    first_names
    last_name
    screen_name
    email
    url
    password
    secret_question
    secret_answer
} {
    Implements the Register operation of the auth_registration
    service contract.
} {
    # Parameters
    array set params $parameters

    array set result {
        creation_status "reg_error"
        creation_message {}
        element_messages {}
        account_status "ok"
        account_message {}
    }

    set dn $params(DNPattern)
    foreach var { username first_names last_name email screen_name url } {
        regsub -all "{$var}" $dn [set $var] dn
    }
    append dn ",$params(BaseDN)"

    set attributes [list]
    foreach elm [split $params(Attributes) ";"] {
        set elmv [split $elm "="]
        set attribute [string trim [lindex $elmv 0]]
        set value [string trim [lindex $elmv 1]]

        foreach var { username first_names last_name email screen_name url } {
            regsub -all "{$var}" $value [set $var] value
        }
        # Note that this makes a list out of 'value' if it isn't already
        lappend attributes $attribute $value
    }

    # Create the account
    set lh [ns_ldap gethandle ldap]
    ns_log Notice "LDAP: Adding user: [concat ns_ldap add [list $lh] [list $dn] $attributes]"

    ad_try {
        ns_ldap add $lh $dn {*}$attributes

    } on ok {result} {
    } on error {errorMsg} {
        error "ns_ldap add returns error: $errorMsg $::errorInfo"

    } finally {
        ns_ldap releasehandle $lh
    }

    auth::ldap::set_password \
        -dn $dn \
        -new_password $password \
        -parameters $parameters

    set result(creation_status) "ok"
    return [array get result]
}

ad_proc -private auth::ldap::registration::GetParameters {} {
    Implements the GetParameters operation of the auth_registration
    service contract.
} {
    return {
        BaseDN "Base DN when searching for users. Typically something like 'o=Your Org Name', or 'dc=yourdomain,dc=com'"
        UsernameAttribute "LDAP attribute to match username against, typically uid"
        PasswordHash "The hash to use when storing passwords. Supported values are MD5, SMD5, SHA, SSHA, and CRYPT."
        DNPattern "Pattern for constructing the first part of the DN for new accounts. Will automatically get ',BaseDN' appended. {username}, {first_names}, {last_name}, {email}, {screen_name}, {url} will be expanded with their respective values. Example: 'uid={username}'."
        Attributes "Attributes to assign in the new LDAP entry. The value should be a semicolon-separated list of the form 'attribute=value; attribute=value; ...'. {username}, {first_names}, {last_name}, {email}, {screen_name}, {url} will be expanded with their respective values. Example: 'objectClass=person organizationalPerson inetOrgPerson;uid={username};cn={{first_names} {last_name}};sn={last_name};givenName={first_names};mail={email}'."
    }
}



#####
#
# On-Demand Sync Driver
#
#####

ad_proc -private auth::ldap::user_info::GetUserInfo {
    username
    parameters
} {

} {
    # Parameters
    array set params $parameters

    # Default result
    array set result {
        info_status "ok"
        info_message {}
        user_info {}
    }

    set search_result [auth::ldap::get_user \
                           -username $username \
                           -parameters $parameters]

    # More than one, or not found
    if { [llength $search_result] != 1 } {
        set result(info_status) no_account
        return [array get result]
    }

    # Set up mapping data structure
    array set map [list]
    foreach elm [split $params(InfoAttributeMap) ";"] {
        set elmv [split $elm "="]
        set oacs_elm [string trim [lindex $elmv 0]]
        set ldap_attr [string trim [lindex $elmv 1]]

        lappend map($ldap_attr) $oacs_elm
    }

    # Map LDAP attributes to OpenACS elements
    array set user [list]
    foreach { attribute value } [lindex $search_result 0] {
        if { [info exists map($attribute)] } {
            foreach oacs_elm $map($attribute) {
                if {$oacs_elm ni { username authority_id }} {
                    set user($oacs_elm) [lindex $value 0]
                }
            }
        }
    }

    set result(user_info) [array get user]

    return [array get result]
}


ad_proc -private auth::ldap::user_info::GetParameters {} {
    Implements the GetParameters operation of the auth_user_info
    service contract.
} {
    return {
        BaseDN "Base DN when searching for users. Typically something like 'o=Your Org Name', or 'dc=yourdomain,dc=com'"
        UsernameAttribute "LDAP attribute to match username against, typically uid"
        InfoAttributeMap "Mapping attributes from the LDAP entry to OpenACS user information in the format 'element=attrkbute;element=attribute'. Example: first_names=givenName;last_name=sn;email=mail"
    }
}

ad_proc -private auth::ldap::search::Search {
    search_text
    parameters
} {

} {
    # Parameters
    array set search_terms $search_text
    unset search_text
    foreach name [array names search_terms] {
        set $name $search_terms($name)
    }
    array set params $parameters

    set lh [ns_ldap gethandle ldap]
    set filter "(&(objectClass=Person)"
    if {[info exists search_text] && $search_text ne ""} {
        append filter "(|($params(UsernameAttribute)=*$search_text*)"
        set name_filter "(|"
        foreach attribute_mapping [split $params(InfoAttributeMap) ";"] {
            set attr [lindex [split $attribute_mapping "="] 1]
            if {[lsearch {first_names last_name} [lindex [split $attribute_mapping "="] 0]] >= 0} {
                append name_filter "(|"
                foreach text [split $search_text] {
                    append name_filter "($attr=*$text*)"
                }
                append name_filter ")"
            }
        }
        if {$name_filter ne "(&"} {
            append filter "${name_filter})"
        }

        foreach attribute_mapping [split $params(InfoAttributeMap) ";"] {
            set attr [lindex [split $attribute_mapping "="] 1]
            if {[lsearch {first_names last_name} [lindex [split $attribute_mapping "="] 0]] < 0} {
                append filter "(&"
                foreach text [split $search_text] {
                    append filter "($attr=*$text*)"
                }
                append filter ")"
            }
        }
        append filter ")"

    }
    append filter "(&"
    foreach attribute_mapping [split $params(InfoAttributeMap) ";"] {
        set attr [lindex [split $attribute_mapping "="] 1]
        if {[info exists $attr] && [set $attr] ne ""} {
            set attr_search [join [split [set $attr]] "*"]
            append filter "($attr=*[set $attr_search]*)"
        }
    }
    append filter ")"
    append filter ")"
    ns_log notice "auth::ldap::search::Search: filter = $filter"

    ad_try {
        ns_ldap search $lh -scope subtree $params(BaseDN) $filter cn

    } on ok {matches} {
    } on error {errorMsg} {
        error "ns_ldap search returns error: $errorMsg"
    } finally {
        ns_ldap releasehandle $lh
    }

    if { [llength $matches] < 1 } {
        return {}
    } else {
        set usernames [list]
        foreach user $matches {
            lappend usernames [lindex $user 3]
        }
        return $usernames
    }
}

ad_proc -private auth::ldap::search::GetParameters {} {
    Implements the GetParameters operation of the auth_search
    service contract.
} {
    return {
        BaseDN "Base DN when searching for users. Typically something like 'o=Your Org Name', or 'dc=yourdomain,dc=com'"
        UsernameAttribute "LDAP attribute to match username against, typically uid"
        InfoAttributeMap "Mapping attributes from the LDAP entry to OpenACS user information in the format 'element=attrkbute;element=attribute'. Example: first_names=givenName;last_name=sn;email=mail"
    }
}

ad_proc -private auth::ldap::search::FormInclude {} {
    Implements the FormInclude operation of the auth_search
    service contract.
} {
    return "/packages/auth-ldap/lib/search"
}

#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:
