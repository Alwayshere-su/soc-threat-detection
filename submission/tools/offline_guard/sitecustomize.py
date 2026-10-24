"""Loaded in every inference child process: deny network and optional original-tree reads."""
import os,socket,sys
from pathlib import Path
if os.environ.get('SOC_REPRO_DENY_NETWORK')=='1':
 def denied(*args,**kwargs):raise RuntimeError('Network is disabled for reproducible offline inference.')
 socket.socket.connect=denied;socket.socket.connect_ex=denied;socket.create_connection=denied
blocked=os.environ.get('SOC_REPRO_BLOCK_ORIGINAL_ROOT')
if blocked:
 original=Path(blocked).resolve();package=Path(os.environ['SOC_REPRO_PACKAGE_ROOT']).resolve();allowed=Path(os.environ['SOC_REPRO_ALLOWED_INPUT']).resolve();venv=original/'.venv'
 def audit(event,args):
  if event!='open' or not args or not isinstance(args[0],(str,bytes,os.PathLike)):return
  try:p=Path(os.fsdecode(args[0])).resolve()
  except (OSError,ValueError):return
  if p.is_relative_to(original) and not (p==allowed or p.is_relative_to(package) or p.is_relative_to(venv)):
   raise RuntimeError('Independent reproduction tried to read outside the package/input/Python environment.')
 sys.addaudithook(audit)
