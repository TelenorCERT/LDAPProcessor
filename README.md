# Usage
Run bin/build_output.py -h 
# Config 
* ldap_server = _The server running Active Directory or LDAP_
* ldap_port = _The port the server is listening on_
* ldap_protocol = _The protocol used for communicating (usually ldap:// or ldaps://)_
* ldap_base = _The base used when querying for data_
* ldap_dn = _The user used when querying for data_
* ldap_dn_pass = _The password used when querying for data_
* source = _Custom field introduced into the extracted data. Used to keep control of the source of the data_
* source_type = _Custom field introduced into the extracted data. Used to differentiate between source types, e.g. Active Directory or LDAP_
* source_value = _Custom field intoduced into the extracted data. Used to differentiate between different domains_
