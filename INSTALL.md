Installation
============

Firstly you will need to install "pykeepass" either via os package or via pip. Pykeepass and its dependancies (plus ansible) covers all this plugins own dependancies.

Secondly, there are three locations you could place the "keepass.py" plugin from this repository for ansible to pick it up:

 * /usr/share/ansible/plugins/inventory
 * ~/.ansible/plugins/inventory
 * ./inventory_plugins (where . is your playbook directory)

You will need to make chages to ansible's configuration, as described below. There are three places where ansible could source its configuration:

 * ./ansible.cfg (where . is your playbook directory)
 * ~/.ansible.cfg
 * /etc/ansible/ansible.cfg

Plugin search dirs
------------------

I have found that the listed plugin search dirs don't quite work, and found it better to explicitly set them:

    [defaults]
    inventory_plugins   = ~/.ansible/plugins/inventory:/usr/share/ansible/plugins/inventory

Enabled plugins
---------------

You will have to enable the keepass plugin for ansible to use it.
Your ansible config will already have something like this:

    [inventory]
    enable_plugins = host_list, script, yaml, ini, auto

You will need to add "keepass" to it:

    [inventory]
    enable_plugins = keepass, host_list, script, yaml, ini, auto


That's it, the plugin should now be usable.

