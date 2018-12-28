
from __future__ import absolute_import

import os
import yaml
from pykeepass import PyKeePass

from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.errors import AnsibleError, AnsibleParserError

class InventoryModule(BaseInventoryPlugin):

    NAME = 'keepass'  # used internally by Ansible

    _PW_ENV_LIST = ["RD_OPTION_KEEPASS_PW", "KEEPASS_PW"]
    _SKIP_TAGS = ['Meta', 'Times', 'DeletedObjects', 'History']

    opts = {
#        'host_fields_in': "keepass_data",
#        'entry_fields_in': "keepass_data",
        'ignore_groups': ["Recycle Bin"],
        'host_field_map': {
            'password': 'login.password',
            'username': 'login.username',
            'url':      'login.url',
            'title': None
        },
        'vars_field_map': {
            'title': None
        }
    }
    
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
            d = kp_db.tree.find('Meta/DatabaseDescription')
            if d is not None and d.text:
                options = self.read_notes(d.text)
                for k in options: 
                    self.opts[k] = options[k]
                    # Two options "systems" is redundant, need to switch
                    self.set_option(k, options[k])
                
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
        
        if name is None:
            raise AnsibleParserError("Impossible group without a name")
        if name.text in self.opts['ignore_groups']:
            return False
        
        self.display.vvvv("Group: " + name.text)
        
        if name.text not in inv.groups:
            inv.add_group(name.text)
            
        pgn = self.get_pgroup_name(el)
        # It should not be possible to have a child added before the parent, but just in case..
        if pgn is not None and pgn in inv.groups:
            inv.add_child(pgn, name.text)
        
        notes = el.find('Notes')    
        if notes is not None: 
            notes = self.read_notes(notes.text)
        if notes is not None: 
            for k in notes: inv.set_variable(name.text, k , notes[k])
        
        return True

    def got_entry(self, el):
        fields = self.get_entry_fields(el)
        if not 'title' in fields:
            # Maybe add some way to find this..
            self.display.warning("Entry has no Title set!")
            return
        
        self.display.vvvv("Entry: " + fields['title'] +"\n")
        
        # --- Process host entry ---
        if fields['title'].startswith('@'):
            self.got_host(el, fields)
        
        # --- Process variables entry ---
        if fields['title'].startswith(':'):
            self.got_vars(el, fields)
            
                
    def got_host(self, el, fields):
        inv = self.inventory
        h = fields['title'].split('@', 1)[-1]
        
        inv.add_host(h, group=self.get_pgroup_name(el))
            
        notes = fields.pop('notes')
        if notes is not None: notes = self.read_notes(notes)
        for k in notes: inv.set_variable(h, k , notes[k])
        
        varz = self.map_fields(fields, self.opts['host_field_map'])
        for k in varz:
            inv.set_variable(h, k, varz[k])

                
        #if self.opts['host_fields_in']:
            #inv.set_variable(h, self.opts['host_fields_in'], fields)

    def got_vars(self, el, fields):
        e = fields['title'].split(':', 1)[-1]
        
        if e and len(e) > 2:
            notes = fields.pop('notes')
            if notes is not None: notes = self.read_notes(notes)
             
            varz = self.map_fields(fields, self.opts['vars_field_map'])
            for k in varz:
                if k in notes:
                    self.display.warning("dropping field with same key as notes")
                    continue
                notes[k] = varz[k]
                
            self.inventory.set_variable(self.get_pgroup_name(el), e , notes)
        else:
            self.display.warning("Vars entry has no name")
    
    def map_fields(self, fields, mapping):
        varz = {}
        for k in fields:
            dest = k
            if k in mapping:
                dest = mapping[k]
            if dest is None:
                continue
            
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
            return p.find('Name').text
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
            if an == p:
                return True
        return False

    # Current solution is to support a list of enviroment variables, 
    # to allow easier integration into various enviroments (e.g. Rundeck)
    # We also grab the default vault password
    def get_kp_passwords(self):
        kp_pw = []
        
        for k in self._PW_ENV_LIST:
            if k in os.environ and os.environ[k]:
                kp_pw.append(os.environ[k])

        for s in self.loader._vault.secrets:
            # Currently we only grab the default key
            if s[0] != u'default':
                continue
            kp_pw.append(s[1].bytes)

        if not kp_pw:
            raise AnsibleParserError("Could not get any keepass password")
        
        return kp_pw
