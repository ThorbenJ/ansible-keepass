Ansible Keepass inventory plugin
================================

Lets you use a keepass file as an ansible inventory. e.g.:

    ansible -i keepass_file.kdbx all --list-hosts
      hosts (4):
        win1.example.com
        host.exmaple.com
        debian2.example.com
        debian1.example.com

This is implemented as an ansible plugin (rather than an inventory script) for tighter integration, such as unlocking the keepass file with a given ansible vault password; i.e. No need for environment varibles (although env-vars are possible).

INSTALL.md gives advice on how to install it

USEAGE.md explains how you can use it in your ansible project

