
import idc
import ida_auto
import os
import sys
import logging

# logger = logging.getLogger(__file__)
# logger.warning("findpanic")
script_dir = os.path.dirname( __file__ )
sys.path.append( script_dir )
from pre_analysis import find_panic_trap_to_debugger
from post_analysis import post_analyzer

find_panic_trap_to_debugger()
ida_auto.enable_auto(True)
idc.auto_wait()

post_analyzer()
idc.auto_wait()

idc.qexit(0)
