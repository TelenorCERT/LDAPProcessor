#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
from ConfigParser import SafeConfigParser
import codecs
import ldap
from ldap.controls import SimplePagedResultsControl
import uuid
import time
import json
import struct

class AD_parser:
    def __init__(self, domain, debug_level=0):
        """Class used to connect to Telenors different AD controllers.

        Uses python-ldap to talk to the AD controllers via LDAP. Will 
        initialize and bind to the AD server during the init phase.

        Args:
            domain (str): Name of Active Directory domain that is to be contacted. Must match a 
                domain named in the configuration file.
            debug_level (int): Level of debug information that python-ldap prints to stdout.

        Attributes:
            LDAP_SERVER (str): URL of AD server.
            LDAP_PORT (str): Port listening on the AD server.
            LDAP_PROTOCOL (str): Protocol to be used for communication.
            LDAP_BASE (str): Base used in searching the Active Directory tree.
            LDAP_DN (str): User used to searh in AD.
            LDAP_DN_PASS (str): Password for the user.
            BIND_STATUS (bool): False until bind to server is successful.
            SOURCE (str): The source the data is coming from.
            SOURCE_TYPE (str): The type of source the data is coming from.
            SOURCE_VALUE (str): Specific value for the source type. Used to distinguish between 
                data of the same source type.
            LDAP_PAGE_SIZE (int): The page size used for paged searching.

        Raises:
            ValueError: If domain does not match a domain in the configuration 
                file.
            ValueError: If debug_level is not int 
            ldap.LDAPError: If connection to AD can't be initialized.
            ldap.LDAPError: If bind() operation to AD is unsuccessful.
            ldap.LDAPError: If disconnect() operation to AD is unsuccessful.
            ldap.INVALID_CREDENTIALS: If username or password is wrong.
        
        Examples:
            >>> ad = LDAPProcessor.AD_parser(ad)
            >>> results = ad.paged_search(filterstr)
            >>> ad.build_json(results, output_file)
            >>> ad.disconnect()
        """
        #Read correct domain config
        parser = SafeConfigParser()

        with codecs.open('ldap.ini', 'r', encoding='utf-8') as f:
            parser.readfp(f)
        
        #Check if input domain exists in config file
        if parser.has_section(domain) is False:
            valid_domains = parser.sections()
            error_msg = u'Needs valid domain as input. Valid domains are: '
            error_msg += u', '.join(valid_domains)
            raise ValueError(error_msg)
        
        #Check that debug_level is int
        try:
            int(debug_level)
        except ValueError:
            error_msg = u'debug_level must be type int.'
            raise ValueError(error_msg)

        self.LDAP_SERVER = parser.get(domain, 'ldap_server')
        self.LDAP_PORT = parser.get(domain, 'ldap_port')
        self.LDAP_PROTOCOL = parser.get(domain, 'ldap_protocol')
        self.LDAP_BASE = parser.get(domain, 'ldap_base')
        self.LDAP_DN = parser.get(domain, 'ldap_dn')
        self.LDAP_DN_PASS = parser.get(domain, 'ldap_dn_pass')
        self.BIND_STATUS = False
        self.SOURCE_TYPE = parser.get(domain, 'source_type')
        self.SOURCE_VALUE = parser.get(domain, 'source_value')
        self.LDAP_PAGE_SIZE = 1000
        
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 100)
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        ldap.set_option(ldap.OPT_DEBUG_LEVEL, debug_level)
        self.ldap = self._initialize_connection()
        self.ldap.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        self.SOURCE = (self.ldap.get_option(ldap.OPT_HOST_NAME).split(':')[0])
        self.BIND_STATUS = self._bind()
    
    def _initialize_connection(self):
        """Initializes the connection to the AD controller.

        Returns:
            ldap.LDAPObject: If connection is successful
            
        Raises:
            ldap.LDAPError: If connection to AD can't be initialized.
        """
        try:
            l = ldap.initialize(self.LDAP_PROTOCOL + self.LDAP_SERVER + ":" + self.LDAP_PORT)
            return l
        except ldap.LDAPError, e:
            print ("Initialisation failed: " + e.args[0]['desc'])
            sys.exit()

    def _bind(self):
        """Binds the connection to the AD controller.

        Returns:
            bool: True if bind to AD is successful, False if not.
            
        Raises:
            ldap.LDAPError: If bind to AD is unsuccessful.
            ldap.INVALID_CREDENTIALS: If username or password is wrong.
        """
        try:
            self.ldap.simple_bind_s(self.LDAP_DN, self.LDAP_DN_PASS)
            return True
        except ldap.LDAPError, e:
            print ("Bind operation failed: " + e.args[0]['desc'])
            sys.exit()
        except ldap.INVALID_CREDENTIALS, e:
            print ("Invalid credentials in bind operation: " + e.args[0]['desc'])
            sys.exit()
    
    def disconnect(self):
        """Disconnects from the AD controller.

        Raises:
            ldap.LDAPError: If disconnect from AD is unsuccessful.
        """
        try:
            self.ldap.unbind_ext_s()
        except ldap.LDAPError, e:
            print ("Unbind operation failed: " + e.args[0]['desc'])
            sys.exit()
    
    def search(self, filterstr):
        """Searches Active Directory for a give search string.

        This search uses the LDAP_BASE value read from configuration. If there is need for 
        searching higher up in the AD tree then the configuration should be changed.

        Args:
            filterstr (str): The search term to look for in AD.
        
        Returns:
            String if search yields results from AD.
            None if there is no results.
        """
        try:
            results = self.ldap.search_s(self.LDAP_BASE, ldap.SCOPE_SUBTREE, filterstr)
        except ldap.SIZELIMIT_EXCEEDED, e:
            print('Warning: Server-side size limit exceeded. ' + e.args[0]['desc'])
            print('Try using paged_search instead.')
            self.disconnect()
            sys.exit()
        else:
            return results
        
    def build_json(self, search_results, output):
        """Converts search results from list to JSON.
        
        Converts the default search results from a list/tuples format into JSON unicode output.

        Decodes the following fields:
        objectGUID: Used the built-in python UUID library.
        objectSid: Decodes the byte array returned from AD.
        
        Args:
            search_results (list): The search results returned from search.
            output (str): Path to output file.
        
        Raises:
            ValueError: If output file is not a file.
        """
        if os.path.isdir(output):
            error_msg = u'Output file is a directory, needs filename.'
            raise ValueError(error_msg)
        else:
            f = open(output, 'a')
            try:
                os.utime(output, None)
            finally:
                f.close()
        
        f = codecs.open(output, "w", "utf-8")
        os.chmod(output, 0440)

        for user in search_results:
            json_output = {}
            current_time = unicode(time.mktime(time.localtime()))
            
            json_output['extractTime'] = current_time
            json_output['datasource'] = self.SOURCE
            json_output['datasource_type'] = self.SOURCE_TYPE
            json_output['datasource_value'] = self.SOURCE_VALUE
            
            for item in user[1].iteritems():
                key = unicode(item[0])
                
                if key == u'objectGUID':
                    value = []
                    for objectGUID in item[1]:
                        value.append(unicode(uuid.UUID(bytes=objectGUID)))
                elif key == u'objectSid':
                    value = self.decode_sid(item[1])
                elif key == u'mail':
                    value = []
                    for each in item[1]:
                        split_mail = each.split(',')
                        strip_mail = [x.strip() for x in split_mail]
                        for mail in strip_mail:
                            try:
                                value.append(unicode(mail))
                            except UnicodeDecodeError:
                                value.append(mail.decode('utf-8'))
                else:
                    try:
                        value = []
                        length = len(item[1])
                        for i, each in enumerate(item[1]):
                            value.append(item[1][i].decode('utf-8'))
                    except UnicodeDecodeError:
                        value = unicode(item[1])
                
                json_output[key] = value

            json.dump(json_output, f, indent=4, separators=(',', ': '), ensure_ascii=False, 
                sort_keys=True)
            f.write(u'\n')
        f.close()

    def decode_sid(self, objectSids):
        """Converts objectSids to human readable SID.
        
        Decodes the byte array returned from AD as follows.
            version = unsigned char[0:1]
            length = unsigned char[1:2]
            authority = unsigned long long[2:8], big endian
            machine = 4 * unsigned long [8:], little endian
        
        Args:
            objectSids (list): ObjectSids as list as returned from AD.
        
        Returns:
            list: List of SIDs.
        """
        processed_sids = []
        for objectSid in objectSids:
            version = struct.unpack('B', objectSid[0:1])[0]
            assert version == 1, version
            
            length = struct.unpack('B', objectSid[1:2])[0]
            authority = unicode(struct.unpack('>Q', '\x00\x00' + objectSid[2:8])[0])
            value = u'S-'+unicode(version)+u'-'+authority
            binary = objectSid[8:]
            assert len(binary) == 4 * length
            
            for i in xrange(length):
                machine = unicode(struct.unpack('<L', binary[4*i:4*(i+1)])[0])
                value += u'-'+machine

            processed_sids.append(value)
        return processed_sids

    def paged_search(self, filterstr='(objectClass=*)', attrlist=None, 
            attrsonly=0, timeout=-1): 
        """Searches Active Directory for a given search string.
        
        Uses RFC 2696 paged results control to search AD. This comes into play when the search 
        yields more then ldap.SIZE_LIMIT results.

        This search uses the LDAP_BASE value read from configuration. If there is need for 
        searching higher up in the AD tree then the configuration should be changed.

        Args:
            filterstr (str): The search term to look for in AD.
            attrlist (list): List of attributes to get from AD. Defaults to all.
            attrsonly (bool): Only gets attributes, not values.
            timeout (int): Time the search waits for results before giving up.
        
        Returns:
            list: List with all results.
        """
        #Simple paged results control to keep track of the search status
        req_ctrl = SimplePagedResultsControl(ldap.LDAP_CONTROL_PAGE_OID, True, 
                (self.LDAP_PAGE_SIZE, ''))
        
        #Send first search request
        msgid = self.ldap.search_ext(self.LDAP_BASE, ldap.SCOPE_SUBTREE, filterstr=filterstr, 
                attrlist=attrlist, serverctrls=[req_ctrl], timeout=timeout)

        all_results = []

        while True:
            rtype, rdata, rmsgid, rctrls = self.ldap.result3(msgid)
            all_results.extend(rdata)

            #Extract the simple paged results response control
            pctrls = [c for c in rctrls if c.controlType == ldap.LDAP_CONTROL_PAGE_OID]

            if pctrls:
                est, cookie = pctrls[0].controlValue
                if cookie:
                    #Copy cookie from response control to request control
                    req_ctrl.controlValue = (self.LDAP_PAGE_SIZE, cookie)
                    
                    #Continue the search with updated request control
                    msgid = self.ldap.search_ext(self.LDAP_BASE, ldap.SCOPE_SUBTREE, 
                            filterstr=filterstr, attrlist=attrlist, serverctrls=[req_ctrl],
                            timeout=timeout)
                else:
                    break
            else:
                print("Warning: Server ignores RFC 2696 control.")
                break

        return all_results
