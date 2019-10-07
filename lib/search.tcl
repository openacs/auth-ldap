# creation-date 2007-01-21
# author Dave Bauer (dave@solutiongrove.com)
# includable search form
# results should be appended to multirow called users
# ADP level
# should get authority_id, return_url passed in.

ad_form -name user-search \
    -export {authority_id object_id} \
    -html {id "user-search"} \
    -has_submit 1 -form {
    {search_text:text(text),optional
        {label "Search"}
    }
    {search_btn:text(button) {label ""} {value "Search"} {html {onclick {document.getElementById('searchform').style.display='';document.getElementById('user-search').submit()}}}}
}

if {![info exists orderby]} {
    set orderby ""
}
set auth_search_impl_id [auth::authority::get_element \
                             -authority_id $authority_id \
                             -element "search_impl_id"]

set auth_search_parameters [auth::driver::get_parameter_values \
                                -authority_id $authority_id \
                                -impl_id $auth_search_impl_id]

array set auth_search_parameters_arr $auth_search_parameters
set search_attribs [list]
# foreach attribute_mapping [split $auth_search_parameters_arr(InfoAttributeMap) ";"] {
#     set attr [lindex [split $attribute_mapping "="] 1]
#     set pretty_name [lindex [split $attribute_mapping "="] 0]
#     lappend search_attribs $attr
#     ad_form -extend -name user-search -form \
#       [list [list $attr:text,optional [list label $pretty_name]]]
#     }


ad_form -extend -name user-search -on_request {
#    element set_value user-search search_text $search_text
} -on_submit {

} -validate {
    {search_text
        {[string length $search_text] >= 3
            || [string length $search_text] <3
            || [string length $department] >= 3}
        "\"search_text\" must be a string containing three or more characters"
    }
}

set search_terms [list]
foreach attr [concat search_text $search_attribs] {
    if {[info exists $attr] && [set $attr] ne ""} {
        lappend search_terms $attr [set $attr]
    }
}
if {[llength $search_terms]} {
    set matches [auth::ldap::search::Search $search_terms $auth_search_parameters]

    set user_info_impl_id [auth::authority::get_element -authority_id $authority_id -element "user_info_impl_id"]
    set user_info_parameters [auth::driver::get_parameter_values \
                                  -authority_id $authority_id \
                                  -impl_id $user_info_impl_id]

    # matches will contain a list of either usernames or user_ids
    foreach user $matches {
        # user info is an array - info_status, user_info, info_message
        set user_info_raw [auth::ldap::user_info::GetUserInfo $user $user_info_parameters]
#	ns_log notice "user info is $user_info_raw"
        # some objects (like resources in LDAP for example), may not return any information so we check first
        if { [lindex $user_info_raw 3] ne "" } {
            array set user_info [lindex $user_info_raw 3]
        } else {
            array set user_info [list first_names "" last_name "" email ""]
        }

        # unpack user_info
        set extra_attributes ""
        foreach name [array names user_info] {
            if {[lsearch {first_names last_name username email} $name] < 0} {
                append extra_attributes "$name $user_info($name) "
            }
            set $name $user_info($name)
        }
        if { ![info exists email] } { set email "" }

        if { [auth::UseEmailForLoginP] } {
            set username $email
        } else {
            set username $user
        }

        # does the user have a local account?
        set local_account_p 0
        set user_id ""
        set status [list]
        db_0or1row user_exists_p {
            select user_id
            from cc_users
            where upper(username) = upper(:user) and upper(email) = upper(:email)
        }
        if {$user_id eq ""} {
            set group_member_p 0
        } else {
            set group_member_p [group::member_p -group_id $group_id -user_id $user_id -cascade]
        }
        set group_name [group::get_element -element group_name -group_id $group_id]
        if {$group_member_p} {
            lappend status [_ acs-authentication.Member_of_group_name]
        } else {
            lappend status [_ acs-authentication.Not_a_member_of_group_name]
        }
        if {[info exists object_id]} {
            set group_member_p [permission::permission_p \
                                    -object_id $object_id \
                                    -party_id $user_id \
                                    -privilege $privilege]
        }
        set create_account_url [export_vars -base create-local-account {
            username first_names last_name email authority_id
        }]
        #
        # We could go on to retrieve member information here if there
        # is a local account (for instance to allow member_state
        # change, etc).
        #

        set ldap_status [lindex $user_info_raw 5]
        set system_name [ad_system_name]
        set status "[join $status <br>]"
        template::multirow -ulevel 2 -local append users \
            $first_names $last_name $username $email $status $group_member_p \
            $create_account_url "" $extra_attributes $user_id $authority_id
        unset user_info email

    }
}


set orderby_list [split $orderby ,]
set orderby_column [lindex $orderby_list 0]
set direction [lindex $orderby_list 1]
set direction [string map {asc -increasing desc -decreasing} $direction]
if {$orderby_column ne ""} {
    eval "template::multirow -ulevel 2 -local sort users $direction $orderby_column"
}

# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:
