USAGE
=====

Invocation
----------

    ansible -i kp_file.kdbx all --list-hosts

or

    ansible-inventory -i kp_file.kdbx --list

Keepass file password
---------------------

The keepass plugin will try to use the "default" (vault id) password, if given; failing that it will look for the following environment variables:

 * KEEPASS_PW
 * RD_OPTION_KEEPASS_PW (simplify Rundeck usage)

If you're not scared of Python you will find the list of env-vars to try near the top of the source file.

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

Entry fields
------------

You will find these set in a subkey, I am still working the best way to do this.

Group inheritance
-----------------

The Keepass db only has a single inheritance hierarchy, but ansible supports hosts and groups to be a child of more than one group.

To support this, this plugin treat all groups in the keepass db with identical names as being the same group in the inventory, so:

  - Aa
    - Bb
      - Cc
  - Dd
    - Bb
      - Ee

In the ansible inventory there will be a single "Bb" group with both "Aa" and "Dd" as a parent and both "Cc" and "Ee" as a children.

This is all fine for Groups, but not so straight forward for hosts and variable: If two identically named groups have identically named hosts or variables in them, it is undefined which group will "win". Please avoid having identically named hosts or variables in multiple same named groups.

Host entries
------------

Only Keepass entries starting with '@' in the title will be read in as an inventory host, all other entries will be ignored. All text following the '@' will be treated as the host's name/fqdn. e.g.:

    @myhost.example.com

Will result in an inventory host called "myhost.example.com":

    hostname: myhost.example.com
    keepass_data: {
        title: "@myhost.example.com",
        password: "abc123"
        url: null,
        username: null,
    }
    

