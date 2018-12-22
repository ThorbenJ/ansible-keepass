

from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.errors import AnsibleError, AnsibleParserError

import pprint
import os
import libkeepass

class InventoryModule(BaseInventoryPlugin):

    NAME = 'keepass'  # used internally by Ansible, it should match the file name but not required

    _PW_ENV_LIST = ["RD_OPTION_KEEPASS_PW", "KEEPASS_PW"]
    
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
        
    
        # this method will parse 'common format' inventory sources and
        # update any options declared in DOCUMENTATION as needed
        # config = self._read_config_data(self, path)
    
        # if NOT using _read_config_data you should call set_options directly,
        # to process any defined configuration for this plugin,
        # if you dont define any options you can skip
        #self.set_options()
    
        with libkeepass.open(path, password=self.get_kp_pw()) as kp_db:
            #print(kp_db.pretty_print())
            pprint.pprint(dir(kp_db))
            


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
