# Cuckoo Sandbox - Automated Malware Analysis
# Copyright (C) 2010-2012  Claudio "nex" Guarnieri (nex@cuckoobox.org)
# http://www.cuckoobox.org
#
# This file is part of Cuckoo.
# Cuckoo is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cuckoo is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.
##
##
# memdump.py - Memory Dump module for Cuckoo Sandbox
# To use this in your analyis package, add this line to the imports
#
#     from cuckoo.memdump import memory_dump
#
# and add this line to your cuckoo_finish function before the return True.
#
#     memory_dump()
#
# You will need to set a number of configuration options in
#     shares/setup/conf/analyzer.conf
# and place the fastdump executible (or your preferered tool) into 
#     shares/setup/extensions/
#
# You will need to get your own memory dumper binary. I have tested this code
# with FastDump Pro CE from HBGary. That is what the default options are 
# setup for.
#
# Module Author: Bryan Nolen @bryannolen on twitter/github
##
##

import sys
import os
import ConfigParser
import time
import logging

sys.path.append("\\\\VBOXSVR\\setup\\lib\\")

import cuckoo.defines
from cuckoo.paths import *
from cuckoo.checkprocess import check_process
from cuckoo.execute import cuckoo_execute

def memory_dump():
    """
    Performs a dump of the guest memory utilising a memory dumping utility.
    Requires config of paths in shares/setup/analyser.conf
    and the the utility itself located in shares/setup/extensions/ folder
    """
    log = logging.getLogger("Core.Analyzer.Memdump")

    ## Read the config file for the Cuckoo analyser module
    analyser_config = ConfigParser.ConfigParser()
    analyser_config_path = os.path.join(CUCKOO_SETUP_SHARE, "conf\\analyzer.conf")
    analyser_config.read(analyser_config_path)

    try:
        ## default value memdump = on
        memdump_enable = analyser_config.getboolean("Analysis", "memdump")
        ## default value memdump_exec = extensions\_fdpro.exe
	memdump_exec = analyser_config.get("Analysis", "memdump_exec")
        ## default value memdump_exec_args = 
	memdump_exec_args = analyser_config.get("Analysis", "memdump_exec_args")
        ## default value memdump_target_file = memdump.bin
	memdump_target_file = analyser_config.get("Analysis", "memdump_target_file")
    except:
        ## Incase people have not enabled this module or completed the configuration, 
        ## fail gracefully and set safe default.
        memdump_enable = False

    if (memdump_enable != True):
        log.info("Module disable by configuration")
        return True

    ## Read the config file for the specific analysis job being performed
    ### Grabbing the path from sys.argv[1] as a hackish workaround :)
    target_config = ConfigParser.ConfigParser()
    target_config_path = os.path.join(sys.argv[1], "analysis.conf")
    target_config.read(target_config_path)
    
    ## default value share = \\VBOXSVR\cuckoo1\
    memdump_dumpfile_path = target_config.get("analysis", "share")

    memdump_target_exec = CUCKOO_SETUP_SHARE 
    memdump_target_exec = os.path.join(memdump_target_exec, memdump_exec)    
    memdump_target_path = os.path.join(memdump_dumpfile_path, memdump_target_file)
    memdump_target_args = memdump_exec_args + memdump_target_path
   
    log.info("Launching Memory Dumper \"%s\"" % memdump_target_exec)
    log.info("Output will be written to \"%s\"" % memdump_target_path)

    ## File not found type exceptions are caught by the cuckoo_execute code, so we don't need to here.
    (dump_pid, h_thread) = cuckoo_execute(memdump_target_exec, memdump_target_args, False)
    
    while check_process(dump_pid):
        log.info("Memory Dumper Process Still Running, sleeping for 10 seconds")
        time.sleep(10)

    log.info("Memory Dump Process Completed")
    return True

