USAGE
=====

Invocation
----------

    ansible -i kp_file.kdbx all --list-hosts

or

    ansible-inventory -i kp_file.kdbx --list

If no password is found, via env-vars or the ansible vault password, then this will fail. See next:
    
Keepass file password
---------------------

The keepass plugin will try to use the "default" (vault id) password, if given; alternatively it will look for the following environment variables:

 * KEEPASS_PW
 * RD_OPTION_KEEPASS_PW (simplify Rundeck usage)

It will try all available passwords in turn, starting with env-vars, until one succeeds; otherwise the plugin will fail.

The list of env-vars to try is a configurable option; that could be set via the "auto" inventory plugin's yaml file.

examples with vault password

    ansible -i kp_file.kdbx --ask-vault-pass all -list

    ansible -i kp_file.kdbx --vault-password-file a_file all --list

exmaple with an environment variable:

    export KEEPASS_PW=foobar
    ansible -i kp_file.kdbx all --list-hosts

EDITING
=======

You can edit the keepass file with any of the keepass clients, that is capable of writing a kdb/kdbx file in a format supported by pykeepass. I use keepass2 from http://keepass.info/.

Configuration options
---------------------

If the "Description" field in Database settings starts with --- (YAML's three dashes), it will be read as a YAML configuration to load configuration options. (Available options to be documented)

Host / Group variables
----------------------

If the "Notes" field in both Groups and Entries starts with --- (YAML's three dashes), it will be read and the variables added to that Group or Host in the inventory.

Entry string fields
-------------------

Found under the advanced tab in keepass2.

These fields will be added as variables to the host (or group variable). The field name supports a dot-notation '.'; so if you had two fields like:

  * foo.bar = 1
  * foo.moo = 2

You will get:

    foo: {
        bar: 1
        moo: 2
    }

The is a field name mapping that is applied. The default mapping will hide the 'title' field and map 'url', 'username' and 'password' under "login". The mappings can be controled by configuration options (to be documented).

Group "vars" entries
--------------------

Any Keepass entry starting with a ':' (colon) will be added as a variable under that group. All text following the ':' will be the variable's name. All Notes or String fields will be added under that variable (thus it will always be a dictionary)

Group inheritance
-----------------

The Keepass db only has a single inheritance hierarchy, but ansible supports hosts and groups as children of more than one group.

To support this, this plugin treat all groups in the keepass db with identical names as being the same group in the inventory, so:

  - Aa
    - Bb
      - Cc
    - Dd
  - Ee
    - Bb
      - Ff

In the ansible inventory there will be a single "Bb" group with both "Aa" and "Ee" as a parent and both "Cc" and "Ff" as a children.

This is all fine for Groups, but not so straight forward for hosts and variable: If two identically named groups have identically named hosts or variables in them, it is undefined which group will "win". 

Please avoid having identically named hosts or variables in multiple same named groups. It is recommended to only populate one such group with hosts and variables, and leave the rest empty and just for relationship mapping.

Host entries
------------

Only Keepass entries starting with '@' in the title will be read in as an inventory host, all other entries will be ignored. All text following the '@' will be treated as the host's name/fqdn. e.g.:

    @myhost.example.com

Will result in an inventory host called "myhost.example.com":

    hostname: myhost.example.com
    login: {
        password: "abc123"
        url: null,
        username: null,
    }
    

