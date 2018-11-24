import os
from yacs.config import CfgNode as CN

# -----------------------------------------------------------------------------
# Config definition
# -----------------------------------------------------------------------------
_C = CN()

_C.DEVICES = CN()
_C.DEVICES.LOCALHOST = CN()
_C.DEVICES.LOCALHOST.NAME = 'eth1'
_C.DEVICES.LOCALHOST.IP = '192.168.1.106'
_C.DEVICES.LOCALHOST.MAC = '00:0A:CD:31:??:??'

_C.DEVICES.HMI = CN()
_C.DEVICES.HMI.IP = '192.168.1.100'
_C.DEVICES.HMI.MAC = '00:0C:29:1E:??:??'

_C.DEVICES.PLC = CN()
_C.DEVICES.PLC.IP = '192.168.1.220'
_C.DEVICES.PLC.MAC = '00:80:F4:0E:??:??'
_C.DEVICES.PLC.SIZE = 125

# ---------------------------------------------------------------------------- #
# Misc options
# ---------------------------------------------------------------------------- #
_C.OUTPUT_DIR = "."
_C.MODELS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models'))
_C.LEARN_TIME = 1200  # In seconds

# Exporting as cfg
cfg = _C


