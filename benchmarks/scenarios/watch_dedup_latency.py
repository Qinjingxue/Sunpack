"""Isolated release Watch E2E benchmark. Event timestamps, not polling detection times."""
import argparse,os,time,json,uuid,statistics,subprocess
from pathlib import Path
from benchmarks.scenarios.watch_dedup_index import write_zip
from tests.helpers.package import package as fixture
import tests.helpers.native_fixture as nf
ROOT=Path(__file__).resolve().parents[2]
nf._fixture_tool=lambda:ROOT/'.cache/rust-target/x86_64-pc-windows-msvc/ci/examples/real_fixture.exe'
from tests.real.plan7_watch_downloads.plan7_support import watch_setup
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=Path)
parser.add_argument('--resume',action='store_true')
args=parser.parse_args()
os.environ['SUNPACK_TEST_BUILD_PROFILE']='release'
work=ROOT/'benchmarks/.work'/('latency-'+uuid.uuid4().hex)
report={'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'work':str(work),'rows':[], 'method':'Release runtime; per-process isolated ProgramData and test Broker. Atomic rename of already-closed ZIP_STORED from outside monitor root to inside. Latency is persisted done.ts minus time.time_ns before rename. Default quiet strategy, no production changes; retained warm OS cache; one outstanding input; fixture-tool event polling is only observation, not endpoint. No cache flushing. Zero same-size confirmed input signatures. Initial startup and baseline rebuild excluded and separately recorded. Every mode/order run uses fresh root/index/output; source and output retained.'}
out=args.output or ROOT/'benchmarks/results'/f'dedup-e2e-{report["head"][:8]}-{time.time_ns()}.json'
if args.resume:
 saved=json.loads(out.read_text());assert saved['head']==report['head'],'Cannot combine different commits'
 report=saved;work=Path(report['work']);assert work.is_dir(),'Missing retained fixtures'
else:
 assert not out.exists(),'Use a new output path or --resume'
 work.mkdir(parents=True)
out.parent.mkdir(parents=True,exist_ok=True)
def save():out.write_text(json.dumps(report,indent=2))
for scale in [0,512]:
 for payload in [4096,4*1024*1024]:
  for repeat in range(3):
   modes=['none','file_id','hash'];modes=modes[repeat:]+modes[:repeat]
   for mode in modes:
    if any((r['scale'],r['payload'],r['repeat'],r['mode'])==(scale,payload,repeat,mode) for r in report['rows']):continue
    case=work/f'{scale}-{payload}-{repeat}-{mode}-{uuid.uuid4().hex[:6]}';case.mkdir()
    gen=fixture.__wrapped__(case,ROOT);app=next(gen)
    try:
     app.configure(watch={'deduplication':mode,'deduplication_scope':'root'})
     root=case/'watch';root.mkdir()
     for i in range(scale):write_zip(root/f'baseline-{i:05}.zip',1024+i,i)
     for i in range(31):write_zip(case/f'input-{i:03}.zip',payload+i,i)
     t=time.perf_counter();watch=watch_setup(app,case,passwords=[],deep=False)
     if mode!='none':app.await_watch_event('watch_dedup_rebuilt')
     if scale:
      from tests.helpers.package import wait_for
      def drained():
       if sum(1 for p in watch.output.rglob('payload.bin')) != scale:return False
       status=app.json('watch','status')['summary']
       return status.get('pending') == 0
      wait_for(drained, 'all baseline archive tasks complete', timeout=60)
     startup_ms=(time.perf_counter()-t)*1000
     samples=[]
     for i in range(31):
      source=case/f'input-{i:03}.zip';dest=root/source.name
      wall=time.time_ns();a=time.perf_counter_ns();source.rename(dest);b=time.perf_counter_ns()
      event=app.await_watch_event('done',path=dest.name)
      samples.append({'i':i,'latency_ms':(event['ts']-wall/1e9)*1000,'rename_ms':(b-a)/1e6,'event':event['event']})
     row={'scale':scale,'payload':payload,'repeat':repeat,'mode':mode,'startup_ms':startup_ms,'samples':samples}
     report['rows'].append(row);save();print(json.dumps({**{k:v for k,v in row.items() if k!='samples'},'median_ms':statistics.median(s['latency_ms'] for s in samples[1:])}),flush=True)
     watch.stop()
    finally:
     try:next(gen)
     except StopIteration:pass
save()

