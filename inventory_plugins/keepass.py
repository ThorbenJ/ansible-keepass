
from __future__ import absolute_import

import pprint
import os
import libkeepass
import yaml

from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.errors import AnsibleError, AnsibleParserError

class InventoryModule(BaseInventoryPlugin):

    NAME = 'keepass'  # used internally by Ansible, it should match the file name but not required

    _PW_ENV_LIST = ["RD_OPTION_KEEPASS_PW", "KEEPASS_PW"]
    _SKIP_TAGS = ['Meta', 'Times', 'DeletedObjects', 'History']
    _IGNORE_GROUPS = ["Recycle Bin"]
    
    def verify_file(self, path):
        ''' return true/false if this is possibly a valid file for this plugin to consume '''
        valid = False
        print("keepass verify_file\n")
        
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(('.kdb', '.kdbx')):
                valid = True
        return valid

    def parse(self, inventory, loader, path, cache=False):
    
        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)
    
        pprint.pprint(dir(inventory))
        
        # this method will parse 'common format' inventory sources and
        # update any options declared in DOCUMENTATION as needed
        # config = self._read_config_data(self, path)
    
        # if NOT using _read_config_data you should call set_options directly,
        # to process any defined configuration for this plugin,
        # if you dont define any options you can skip
        #self.set_options()
    
        skipping = None
        with libkeepass.open(path, password=self.get_kp_pw()) as kp_db:
            print(kp_db.pretty_print())
            #pprint.pprint(dir(kp_db.obj_root))
            for el in kp_db.obj_root.getiterator():
                if skipping != None:
                    if skipping == el.getparent():
                        # We've skipped the subtree
                        skipping = None;
                    else:
                        continue
                    
                if el.tag == "Group":
                    if not self.got_group(el):
                        skipping = el.getparent()
                    continue
                
                if el.tag == "Entry":
                    self.got_entry(el)
                    skipping = el.getparent()
                    continue
                
                if el.tag in self._SKIP_TAGS:
                    skipping = el.getparent()
                    continue
                
                if el.getparent() is not None:
                    print(str(el.getparent().tag) + " / " + str(el.tag))
                else:
                    print("ROOT / "+ str(el.tag))
                
            

    def got_group(self, el):
        inv = self.inventory
        name = el.find('Name')
        if not name:
            raise AnsibleParserError("Impossible group without a name")
        if name.text in self._IGNORE_GROUPS:
            return False
        
        print("Group: " + name.text)
        
        if name.text not in inv.groups:
            inv.add_group(name.text)
            pgn = self.get_pgroup_name(el)
            if pgn is not None and pgn in inv.groups:
                inv.add_child(pgn, name.text)
        
        notes = el.find('Notes')    
        if notes is not None:
                self.load_notes(notes.text, name.text)
        return True

        
    def got_entry(self, el):
        inv = self.inventory
        data = self.map_entry_strings(el)
        if not 'title' in data:
            print "NO TITLE in Entry"
            return
        
        pgn = self.get_pgroup_name(el) or "ungrouped"
        print "GOT entry: " + data['title'] +" in Group: "+ pgn +"\n"
        
        if data['title'].startswith('@'):
            h = data['title'].split('@', 1)[-1]
            inv.add_host(h, group=pgn)
            self.load_notes(data['notes'], h)
            
            
    def get_pgroup_name(self, el):
        p = el.getparent()
        if p is not None and p.tag != "Root":
            return p.find('Name').text
        return None

    def load_notes(self, notes, entry):
        if notes is not None and notes.startswith('---'):
            y = yaml.safe_load(notes) or {}
            for k in y:
                self.inventory.set_variable(entry, k, y[k])

    def map_entry_strings(self, el):
        elmap = {}
        for s in el.findall('String'):
            k = s.find('Key')
            v = s.find('Value')
            if k and v:
                elmap[k.text.lower()] = v.text
        #pprint.pprint(elmap)
        return elmap

    # Would love to grab the vault password and use that or at least extra vars..
    # (or even re-use its password prompt function)
    # Current solution is to support a list of enviroment variables, 
    # to allow easier integration into various enviroments (e.g. Rundeck)
    def get_kp_pw(self):
        kp_pw = None
        
        for k in self._PW_ENV_LIST:
            if not k in os.environ:
                continue

            if os.environ[k]:
                kp_pw = os.environ[k]
                break
    
        if not kp_pw :
            raise AnsibleParserError("Could not get a keepass password")
        
        return kp_pw
