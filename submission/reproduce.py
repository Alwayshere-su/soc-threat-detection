"""Offline reproduction of the scored B submission from models and frozen reviews."""
import argparse,hashlib,json,os,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
EXPECTED='d792a4f9eb6327bf7b4af157e4e8940dd3310954a728e10db4f91f230a26189d'
INPUTS={'5a3db3aab57c33680e4627b0df75f9d526445c17964fd9f09d36f44eb6ae1d0b','ca4a6ddc6cfda4c67d336c0ff75c67efedaded0a034213c27d9dad6b22266182'}
def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
 return h.hexdigest()
def verify_package():
 manifest=json.loads((ROOT/'manifest.json').read_text(encoding='utf-8'))
 for name,expected in manifest['files'].items():
  p=(ROOT/name).resolve()
  if not p.is_relative_to(ROOT) or not p.is_file() or sha(p)!=expected:raise ValueError('Package integrity check failed: '+name)
 return len(manifest['files'])
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',required=True,help='Original official B CSV or canonical Parquet; not bundled.');p.add_argument('--out',default=str(ROOT/'outputs/res.csv'));p.add_argument('--keep-intermediates',action='store_true');a=p.parse_args()
 source=Path(a.input).resolve(strict=True);target=Path(a.out).resolve();reportpath=target.with_suffix('.report.json');logpath=target.with_suffix('.log')
 if not source.is_file() or sha(source) not in INPUTS:raise ValueError('This scored release is bound to the reviewed official B input. Use the original CSV or canonical Parquet.')
 if target==source or target==ROOT/'res.csv' or target.is_relative_to(ROOT/'runtime'):raise ValueError('Choose a new output outside the immutable runtime/reference result.')
 if any(x.exists() for x in [target,reportpath,logpath]):raise FileExistsError('Output/report/log already exists; choose a fresh output path.')
 count=verify_package();target.parent.mkdir(parents=True,exist_ok=True);start=time.monotonic()
 env=os.environ.copy();env['PYTHONPATH']=str(ROOT/'tools/offline_guard');env['PYTHONIOENCODING']='utf-8';env['SOC_REPRO_PACKAGE_ROOT']=str(ROOT);env['SOC_REPRO_ALLOWED_INPUT']=str(source)
 env['SOC_REPRO_DENY_NETWORK']='1'
 # Optional independent-verification fence used to prove no files are loaded
 # from the original working tree outside its Python environment/input.
 cmd=[sys.executable,str(ROOT/'runtime/lib/stages/17_refinement/predict.py'),'--input',str(source)]
 import pandas as pd
 if a.keep_intermediates:
  stage=target.parent/(target.stem+'_intermediates');stage.mkdir();manager=None
 else:
  manager=tempfile.TemporaryDirectory(prefix='soc-reproduction-');stage=Path(manager.name)
 try:
  intermediate=stage/'res.csv'
  with logpath.open('w',encoding='utf-8') as log:
   result=subprocess.run(cmd+['--out',str(intermediate)],cwd=ROOT/'runtime',env=env,stdout=log,stderr=subprocess.STDOUT)
  if result.returncode:raise RuntimeError('Inference failed; inspect '+str(logpath))
  if sha(intermediate)!=EXPECTED:raise ValueError('Prediction bytes do not match the scored release.')
  output=pd.read_csv(intermediate,dtype=str,keep_default_na=False)
  ids=pd.read_csv(source,usecols=['event_id'],dtype=str,keep_default_na=False,encoding='utf-8-sig').event_id if source.suffix.lower()=='.csv' else pd.read_parquet(source,columns=['event_id']).event_id
  if output.shape!=(55837,2) or list(output.columns)!=['event_id','pred_label'] or not output.event_id.is_unique or not output.event_id.equals(ids) or not output.pred_label.isin(['benign','suspicious','malicious']).all():raise ValueError('Submission schema/order check failed.')
  # Exclusive publication avoids overwriting a file created during inference.
  with target.open('xb') as dest,intermediate.open('rb') as src:
   for part in iter(lambda:src.read(1024*1024),b''):dest.write(part)
  if sha(target)!=EXPECTED:raise ValueError('Output copy check failed.')
  report=dict(passed=True,rows=55837,prediction_sha256=EXPECTED,input_sha256=sha(source),official_score=.97279254,score_source='user_reported_in_chat',package_files_verified=count,fresh_native_models_executed=True,frozen_LLM_and_content_reviews_replayed=True,new_LLM_generation=False,API_key_required=False,network_disabled_in_inference=True,private_answers_read=False,input_order_verified=True,seconds=round(time.monotonic()-start,3),label_counts=output.pred_label.value_counts().to_dict(),intermediates_retained=bool(a.keep_intermediates))
  reportpath.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(report,ensure_ascii=False))
 finally:
  if manager:manager.cleanup()
if __name__=='__main__':main()
