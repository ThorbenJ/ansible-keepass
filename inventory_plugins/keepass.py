# coding=utf8
#
# (c) 2018 Thorben Jändling <ThorbenJ@users.noreply.github.com>
#
# Licenced under the LGPL 3 (see LICENCE)
#

from __future__ import absolute_import

DOCUMENTATION = '''
inventory: keepass
version_added: "N/A"
short_description: "Read a Keepass kdbx file as an inventory source."
description:
    - "Will read a Keepass2 kdb/kdbx file as an inventory source. "
    - "The following 'YAML fields' must start with '---' or will be ignored."
    - "First: The Database Description is read as a YAML field with configuration options."
    - "Second: The Group and/or Entry 'Notes' fields are read as a YAML field with vars for that Group/Host. "
    - "Keepass Entries will be ignored, except:"
    - "A) Entries with titles starting with '@' are read as a Host/"
    - "B) Entries with titles starting with ':' are read as a (dict) Variable for its containing Group. "
    - "Finally, Groups with the same name are merged, including both parent and child groups."
    - "Possible Keepass passwords are taken from Enviroment Variables and the Ansible vault password (if given)."
notes:
    - "Setting 'try_envvar_list' in the Database Description is obviously too late to be of use"
options:
    ignore_groups:
        description: List of groups to ignore
        type: list
        default: ["Recycle Bin"]
    host_field_map:
        description: Mapping for Host String Fields
        type: dict
        default:
            title: null
            username: login.username
            password: login.password
            url:      login.url
            notes:    login.notes
    vars_field_map:
        description: Mapping for Vars String Fields
        type: dict
        default:
            title: null
    symgroup_field_map:
        description: Mapping for symbolic group (link) String Fields
        type: dict
        default: 
            title:    null
            username: null
            password: null
            url:      null
            notes:    null
    try_envvar_list:
        description: List of environment variables to try for passwords
        type: list
        default: ["KEEPASS_PW", "RD_OPTION_KEEPASS_PW"]
'''

EXAMPLES='''
(G) = Group
(E) = Entry

The following keepass file hierarchy:-
(G) Top
 |-(E) :Top_var
 |-(E) @top_host1.example.com
 |-(E) FooBar.example.com
 |
 |-(G) Aa
 |  |-(E) @aa_host1.exmaple.com
 |  |
 |  |-(G) Bb
 |  |  |-(E) @bb_host1.example.com
 |  |  |
 |  |  `-(G) Cc
 |  |     `-(E) @cc_host1.example.com
 |  |
 |  `-(G) Dd
 |     |
 |     `-(G) Bb
 |        |-(E) :bb_var
 |        |
 |        `-(G) Ee
 `-(G) Ff

Will get the following output from ansible-inventory --list :-
{
    "Aa": {
        "hosts": [
                "aa_host1.example.com"
                #No FooBar it's ignored
        ],
        "children": [
            "Bb",
            "Dd"
        ]
    }, 
    "Bb": {
        "hosts": [
            "bb_host1.example.com"
        ],
        "children": [
            "Cc",
            "Ee"
        ]
    }, 
    "Cc": {
        "hosts": [
            "cc_host1.exmaple.com"
        ]
    }, 
    "Dd": {
        "children": [
            "Bb"
        ]
    },
    "Top": {
        "children": [
            "Aa", 
            "Ff"
        ]
    }, 
    "_meta": {
        "hostvars": {
            "aa_host1.example.com": {
                "Top_var": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "user"
                }, 
                "login": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "aa_host1_user"
                }
            }, 
            "bb_host1.example.com": {
                "Top_var": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "top_user"
                }, 
                "bb_var": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "bb_user"
                }, 
                "login": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "bb_host1_user"
                }
            }, 
            "cc_host1.exmaple.com": {
                "Top_var": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "top_user"
                }, 
                "bb_var": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "bb_user"
                }, 
                "login": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "cc_host1_user"
                }
            }, 
            "top_host1.example.com": {
                "Top_var": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "top_user"
                }, 
                "login": {
                    "password": "abc123", 
                    "url": null, 
                    "username": "top_host1_user"
                }
            }
        }
    }, 
    "all": {
        "children": [
            "Top", 
            "ungrouped"
        ]
    }, 
    "ungrouped": {}
}

This example does not include variables set via "Notes" nor "String fields"

'''

import os
import yaml

from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.errors import AnsibleError, AnsibleParserError

try:
    from pykeepass import PyKeePass
    #Version check?
except:
    raise AnsibleError("This plugin requires pykeepass, please install pykeepass or disable this plugin")


class InventoryModule(BaseInventoryPlugin):

    NAME = 'keepass'  # used internally by Ansible

    _SKIP_TAGS = ['Meta', 'Times', 'DeletedObjects', 'History']

    def __init__(self):
        super(InventoryModule, self).__init__()

    def verify_file(self, path):
        ''' return true/false if this is possibly a valid file for this plugin to consume '''
     
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(('.kdb', '.kdbx')):
                self.display.vvvv("Valid keepass filename: "+path)
                return True
        self.display.vvvv("Invalid keepass filename: "+path)
        return False

    def parse(self, inventory, loader, path, cache=False):
    
        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        # Populate option defaults
        self.set_options()
        
        kp_db = None
        for pw in self.get_kp_passwords():
            try:
                kp_db = PyKeePass(path, password=pw)
                if kp_db: 
                    self.display.vvv("Attempt to decrypt the keepass file succeeded")
                    break
            except Exception as ex:
                # Assuming we've not reached the correct pw
                self.display.vvv("An attempt to decrypt the keepass file failed: "+str(ex))
                continue

        if kp_db:
            # Load config options from kdb file
            d = kp_db.tree.find('Meta/DatabaseDescription')
            if d is not None and d.text:
                options = self.read_notes(d.text)
                if options: 
                    self._consume_options(options)
                if options:
                    self.display.warning("Database Description contains unsupported options")
                
            self._parse_kp_db(kp_db)
        else:
            raise AnsibleParserError("Unable to decrypt keepass file")

        
        

    def _parse_kp_db(self, kp_db):

        # This was originally written for libkeepass, so uses lxml directly
        # Would that complete features than rewrite for the new API
        skipping = None
        for el in kp_db.tree.getiterator():

            if skipping != None:
                if self.is_ancestor(el, skipping):
                    continue
                else:
                    skipping = None
                
            if el.tag == "Group":
                if not self.got_group(el):
                    skipping = el
                continue
            
            if el.tag == "Entry":
                self.got_entry(el)
                skipping = el
                continue
            
            if el.tag in self._SKIP_TAGS:
                skipping = el
                continue
                
            

    def got_group(self, el):
        inv = self.inventory
        name = el.find('Name')
        ig = self.get_option('ignore_groups')
        
        if name is None:
            raise AnsibleParserError("Impossible group without a name")
        else:
            name = name.text
        if not name or name in ig:
            return False
        
        self.display.vvvv("= Group: " + name)
        
        if name not in inv.groups:
            inv.add_group(name)
            
        pgn = self.get_pgroup_name(el)
        # It should not be possible to have a child added before the parent, but just in case..
        if pgn is not None:
            inv.add_child(pgn, name)
        
        notes = el.find('Notes')    
        notes = self.read_notes(notes.text)
        if notes is not None: 
            for k in notes: inv.set_variable(name, k , notes[k])
        
        return True

    def got_entry(self, el):
        fields = self.get_entry_fields(el)
        if not 'title' in fields:
            # Maybe add some way to find this..
            self.display.warning("Entry has no Title set!")
            return
        
        self.display.vvvv("- Entry: " + fields['title'])
        
        # --- Process host entry ---
        if fields['title'].startswith('@'):
            self.got_host(el, fields)
        
        # --- Process variables entry ---
        if fields['title'].startswith(':'):
            self.got_vars(el, fields)
            
        # --- Process symbolic group entry
        if fields['title'].startswith('%'):
            self.got_symgroup(el, fields)
            
                
    def got_host(self, el, fields):
        inv = self.inventory
        h = fields['title'].split('@', 1)[-1]
        
        inv.add_host(h, group=self.get_pgroup_name(el))

        notes = self.read_notes(fields['notes'])
        if notes: fields.pop('notes')
        
        varz = self.map_fields(fields, self.get_option('host_field_map'))
        if varz:
            for k in varz: inv.set_variable(h, k, varz[k])
        
        # Notes has priority over string fields
        if notes:
            for k in notes: inv.set_variable(h, k , notes[k])


    def got_vars(self, el, fields):
        e = fields['title'].split(':', 1)[-1]
        
        if not e or len(e) < 1:
            self.display.warning("Vars entry has no name")
            return
        
        notes = self.read_notes(fields['notes']) or {}
        if notes: fields.pop('notes')
        
        varz = self.map_fields(fields, self.get_option('vars_field_map')) or {}
        
        if notes:
            for k in notes: 
                if k in varz:
                    self.display.warning("Overwriting string varible ("+k+") with notes value")
                varz[k] = notes[k]
                
        self.inventory.set_variable(self.get_pgroup_name(el), e , varz)
        
    # Symbolc groups do not overwritte existing variables
    def got_symgroup(self, el, fields):
        inv = self.inventory
        g = fields['title'].split('%', 1)[-1]
        
        if g not in inv.groups: inv.add_group(g)
        inv.add_child(self.get_pgroup_name(el), g)
            
        notes = self.read_notes(fields['notes']) or {}
        
        group = inv.groups[g]
        
        if notes:
            fields.pop('notes')
            for k in notes: 
                if k not in group.vars:
                    inv.set_variable(g, k , notes[k])
            
        varz = self.map_fields(fields, self.get_option('symgroup_field_map'))
        if varz:
            for k in varz: 
                if k not in group.vars:
                    inv.set_variable(g, k, varz[k])
        

    

    def map_fields(self, fields, mapping):
        varz = {}
        for k in fields:
            dest = k
            if k in mapping: dest = mapping[k]
            if dest is None: continue
            
            path = dest.split('.')
 
            it = varz
            while path:
                p = path.pop(0)
                if path: #Not last
                    if p not in it:
                        it[p] = {}
                    elif not isinstance(it[p], dict):
                        self.display.warning("field mapping replacing a value with dict")
                        it[p] = {}
                    it = it[p]
                else:
                    it[p] = fields[k]
        
        return varz
    

    def get_pgroup_name(self, el):
        p = el.getparent()
        if p is not None and p.tag != "Root":
            pgn = p.find('Name').text
            self.display.vvvv("> "+pgn+" is parent group of "+el.tag)
            return pgn
        return None


    def read_notes(self, notes):
        if notes is not None and notes.startswith('---'):
            return yaml.safe_load(notes) or {}
        return None
        

    def get_entry_fields(self, el):
        fields = {}
        for s in el.findall('String'):
            k = s.find('Key')
            v = s.find('Value')
            if k is not None and v is not None:
                fields[k.text.lower()] = v.text

        return fields


    def is_ancestor(self, el, an):
        if el is None or an is None:
            return False
        # Should never get more then one level deep, but just in case..
        for p in el.iterancestors():
            if an == p: return True
        return False


    # Current solution is to support a list of enviroment variables, 
    # to allow easier integration into various enviroments (e.g. Rundeck)
    # We also grab the default vault password
    def get_kp_passwords(self):
        kp_pw = []
        
        for k in self.get_option('try_envvar_list'):
            if k in os.environ and os.environ[k]:
                kp_pw.append(os.environ[k])

        for s in self.loader._vault.secrets:
            # Currently we only grab the default key
            if s[0] != u'default': continue
        
            kp_pw.append(s[1].bytes)

        if not kp_pw:
            raise AnsibleParserError("Could not get any keepass password")
        
        return kp_pw
