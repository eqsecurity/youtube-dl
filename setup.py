#!/usr/bin/env python
# coding: utf-8

# Copyright
 Cloud Linux GmbH & Cloud Linux Software, Inc 2010-2019 All Rights Reserved
# Licensed under CLOUD LINUX LICENSE AGREEMENT
# http://cloudlinux.com/docs/LICENSE.TXT
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
from builtins import *
import json
import os
import sys
import syslog
from future.utils import native_str
CONFIGS_DIR = '/etc/cagefs/filters'
LOG_AUTHPRIV = 10<<3
def dmesg(debug, msg, *args):
    if debug:
        print(msg % args)
def load_config(command_path):
    """
    Load JSON config by command name
    """
    try:
        name = os.path.basename(command_path)
        f = open(os.path.join(CONFIGS_DIR, "%s.json" % name), "r")
        full_config = json.load(f)
        f.close()
    except Exception:
        return None
    if len(full_config) == 1 and ("allow" in full_config or
                                  "deny" in full_config or
                                  "restrict_path" in full_config):
        # get full config if only `allow` or `deny` or `restrict_path` key present in it
        return full_config
    # find config for command path or get default
    return full_config.get(command_path, full_config.get("default", None))
def is_option_name(arg):
    """
    Return True if arg is option name, not parameter of an option
    :param arg: option or parameter
    :type arg: string
    """
    return arg.startswith('-')
def has_denied_params(args, deny_list):
    """
    Check denied params in args list
    """
    for arg in args:
        for opt in deny_list:
            if arg.startswith(opt):
                return True
    return False
def has_extra_params(args, allow_list):
    """
    Check is all args allow for program
    """
    for arg in args:
        if is_option_name(arg) and (arg not in allow_list):
            return True
    return False
def to_log(message, *args):
    """
    Wrapper for syslog or other logging system
    """
    syslog.openlog(native_str("cagefs.check_params"))
    syslog.syslog(LOG_AUTHPRIV | syslog.LOG_PID, message % args)
    syslog.closelog()
def addslash(path):
    if path == '':
        return '/'
    if (path[-1] != '/'):
        return '%s/' % (path,)
    return path
def expanduser(path, user, home_dir):
    home_dir = addslash(os.path.realpath(home_dir))
    userpath = '~'+user
    if path == '~' or path.startswith('~/'):
        return os.path.realpath(path.replace('~', home_dir))
    if path == userpath or path.startswith(userpath+'/'):
        return os.path.realpath(path.replace(userpath, home_dir))
    return os.path.realpath(path)
def check_path(user, homedir, command_path, args, restrict_path_list, debug = False):
    """
    Return True when args contain paths that refer outside of user's home directory
    :param args: parameters (options) from command line
    :type args: list of strings
    :param restrict_path_list: names of parameters (options) that should use paths inside user's home directory only
    :type restrict_path_list: list of strings
    """
    home_dir = addslash(os.path.realpath(homedir))
    for i, arg in enumerate(args):
        if arg in restrict_path_list:
            try:
                # path is specified in the next argument
                path = args[i+1]
            except IndexError:
                continue
            path = expanduser(path, user, home_dir)
            path = addslash(path)
            if not path.startswith(home_dir):
                dmesg(debug, "Attempt to call program %s with %s %s parameters", command_path, args[i], args[i+1])
                to_log("Attempt to call program %s with %s %s parameters", command_path, args[i], args[i+1])
                return True
        else:
            for opt in restrict_path_list:
                if arg.startswith(opt):
                    # path is specified in the current argument
                    path = arg[len(opt):]
                    path = expanduser(path, user, home_dir)
                    path = addslash(path)
                    if not path.startswith(home_dir):
                        dmesg(debug, "Attempt to call program %s with %s parameter", command_path, args[i])
                        to_log("Attempt to call program %s with %s parameter", command_path, args[i])
                        return True
    return False
def main(user, homedir, params, debug = False):
    """
    Program main function
    :params - list of strings that specify command and its parameters, such as ['/path/command', '-a', 'arg', '-C', '/path/to/config']
    """
    if len(params) == 0:
        dmesg(debug, 'No parameters specified')
        return 1
    # permit execution of any command when called without parameters
    if len(params) < 2:
        dmesg(debug, 'Command has no parameters. Allow execution of command %s', params[0])
        return 0
    command_path = params[0]
    args = params[1:]
    config = load_config(command_path)
    dmesg(debug, 'config: %s', str(config))
    if not config:
        dmesg(debug, 'Config not found. Allow execution of command %s', command_path)
        return 0
    allow_list = config.get("allow", None)
    deny_list = config.get("deny", None)
    restrict_path_list = config.get("restrict_path", None)
    if not (allow_list or deny_list or restrict_path_list):
        dmesg(debug, 'empty config - allow user to run the command')
        return 0
    if allow_list and deny_list:
        dmesg(debug, 'invalid config - both allow and deny lists are specified. allow user to run the command')
        return 0
    if deny_list and has_denied_params(args, deny_list):
        dmesg(debug, "Attempt to call program %s with denied parameters", command_path)
        to_log("Attempt to call program %s with denied parameters", command_path)
        return 2
    if allow_list and has_extra_params(args, allow_list):
        dmesg(debug, "Attempt to call program %s with extra parameters", command_path)
        to_log("Attempt to call program %s with extra parameters", command_path)
        return 2
    if restrict_path_list and check_path(user, homedir, command_path, args, restrict_path_list, debug):
        return 2
    dmesg(debug, 'Execution allowed')
    return 0
if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3:]))
