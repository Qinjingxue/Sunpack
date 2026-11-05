"""Closed-loop ablations of existing observations, with the mapping frozen.

Run calibration before selection. Every variant uses the production scheduler,
native catalog and admission path; writer truth is only used for scoring.
"""
from __future__ import annotations

import argparse
import gzip
import importlib.util
import inspect
import json
import os
import statistics
import types
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sunpack_native import fast_hash128_file
from sunpack.runtime.watch import quiet_policy, scheduler
from benchmarks.harness.workspace import BenchmarkWorkspace
from .corpus import CHANNELS, CONTRACT, WIDTHS, Trace, generate
from .scheduler_replay import prepare_metadata, replay_scheduler
from .search import Accumulator, TIES, combine, violation, write_json
from .statistics import EVALUATION_CONTRACT, interval

REPO=Path(__file__).resolve().parents[2]
VARIANTS=('baseline','close','ready','boundary','close_boundary','ready_boundary','close_active','metadata_close',
          'metadata_close_slo')


def baseline_class(path):
    spec=importlib.util.spec_from_file_location('_quiet_lifecycle_baseline',path)
    module=importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    # Bind frozen methods to the replay-patched production boundary globals.
    methods={name:types.FunctionType(value.__code__,scheduler.__dict__,value.__name__,value.__defaults__,value.__closure__)
             for name,value in vars(module.WatchScheduler).items() if isinstance(value,types.FunctionType)}
    for name, value in methods.items():
        value.__kwdefaults__=getattr(module.WatchScheduler,name).__kwdefaults__
    return type('FrozenWatchScheduler',(scheduler.WatchScheduler,),methods)


def run_block(destination, split, seed, variant, baseline):
    root=Path(destination)
    corpus=root/'corpus'/f'{split}-{seed}.jsonl.gz'
    policy=quiet_policy.AdaptiveQuietPolicy()
    factory=lambda:SimpleNamespace(tracker=quiet_policy.AdaptiveQuietTracker(policy))
    cls=baseline_class(baseline)
    observe=cls._observe_candidate_activity
    metadata=cls._accept_metadata_observation_locked
    boundary=cls._record_boundary_activity
    counter=defaultdict(int)

    def compatible(candidate):
        try:
            return scheduler.watch_file_is_ready(candidate.path)
        except OSError:
            return False

    def observed(self,candidate,now,**kwargs):
        learned=observe(self,candidate,now,**kwargs)
        wants=(variant.startswith('ready') or (variant.startswith('close') and candidate.change_reasons_known
                                               and candidate.change_reasons & scheduler.USN_REASON_CLOSE))
        if variant=='close_active' and candidate.path not in self._active_states:
            wants=False
        if wants and compatible(candidate):
            counter['early_ready']+=1
            return 0.
        return learned

    def accepted(self,candidate,now):
        metadata(self,candidate,now)
        state=self._active_states.get(candidate.path)
        wants=(variant.startswith(('ready','close','metadata_close'))) and candidate.change_reasons_known and candidate.change_reasons & scheduler.USN_REASON_CLOSE
        if variant=='metadata_close_slo' and state is not None:
            wants=wants and state.last_event_at+state.quiet_seconds-now>=.1
        if state is not None and wants and compatible(candidate):
            state.last_event_at=now
            state.quiet_seconds=0.
            state.generation+=1
            self._schedule_active_locked(candidate.path,state)
            counter['metadata_close']+=1

    def recorded(self,path,epoch,generation,candidate,now,**kwargs):
        boundary(self,path,epoch,generation,candidate,now,**kwargs)
        state=self._active_states.get(path)
        if kwargs.get('content_changed',True) and state is not None and compatible(candidate):
            state.quiet_seconds=0.
            self._schedule_active_locked(path,state)
            counter['boundary_ready']+=1

    if variant not in ('baseline','production'):
        cls._observe_candidate_activity=observed
        cls._accept_metadata_observation_locked=accepted
        if variant=='boundary' or variant.endswith('_boundary'):
            cls._record_boundary_activity=recorded
    metadata_root=prepare_metadata(root/'metadata'/str(os.getpid()))
    accumulator=Accumulator()
    cohorts=defaultdict(list)
    maximum=0.
    with ExitStack() as stack:
        if variant!='production':
            stack.enter_context(patch.object(scheduler,'WatchScheduler',cls))
        stream=stack.enter_context(gzip.open(root/'timelines'/f'{variant}-{split}-{seed}.jsonl.gz','wt',encoding='utf8'))
        source=stack.enter_context(gzip.open(corpus,'rt',encoding='utf8'))
        for line in source:
            trace=Trace.from_record(json.loads(line))
            files={file.key:file for file in trace.files}
            for tie in TIES:
                result=replay_scheduler(trace,factory,tie_order=tie,metadata_root=metadata_root)
                accumulator.add(trace.family,trace.width,result['inputs'])
                stream.write(json.dumps(dict(trace=trace.key,variant=variant,tie_order=tie,inputs=result['inputs']),separators=(',',':'))+'\n')
                for item in result['inputs']:
                    ready=item['processing_ready_at']
                    if ready is None:
                        continue
                    latency=item['ready_to_valid_proposal_seconds']
                    if latency is not None:
                        maximum=max(maximum,latency)
                    sources=[files[key] for key in item['members']]
                    times=sorted([min(file.actions[0].at for file in sources),ready,
                                  *(a.at for file in sources for a in file.actions
                                    if a.kind in ('write','bad_write','receive') and a.at<=ready)])
                    gap=max(b-a for a,b in zip(times,times[1:]))
                    entry=dict(latency=latency,family=trace.family,trace=trace.key,tie=tie)
                    for label in ('all','channel/'+trace.channel,*('response_gap_le_'+str(limit)+'s' for limit in (.1,.5,1.,5.) if gap<=limit)):
                        cohorts[label].append(entry)
                    if trace.channel=='immediate':
                        for limit in (.1,.5,1.,5.):
                            if gap<=limit:
                                cohorts['immediate_response_gap_le_'+str(limit)+'s'].append(entry)
    result=dict(score=accumulator.result(),cohorts=dict(cohorts),max_latency_seconds=maximum,actions=dict(counter))
    write_json(root/'scores'/f'{variant}-{split}-{seed}.json',result)
    return result


def cohort_summary(rows):
    traces=defaultdict(list)
    for row in rows:
        traces[row['family'],row['trace'],row['tie']].append(row['latency'])
    families=defaultdict(list)
    for (family,_,_),values in traces.items():
        known=[value for value in values if value is not None]
        families[family].append(dict(hit=sum(round(value*1e9)<100_000_000 for value in known)/len(values),
                                     mean=statistics.mean(known) if known else None))
    known=[row['latency'] for row in rows if row['latency'] is not None]
    return dict(cases=len(rows),missing=len(rows)-len(known),violations=len(rows)-sum(round(value*1e9)<100_000_000 for value in known),
                hit=statistics.mean(statistics.mean(item['hit'] for item in values) for values in families.values()),
                mean=statistics.mean(statistics.mean(item['mean'] for item in values if item['mean'] is not None) for values in families.values()),
                maximum=max(known,default=None))


def report(root, variants, split, seeds, ratio):
    blocks={variant:[json.loads((root/'scores'/f'{variant}-{split}-{seed}.json').read_text(encoding='utf8')) for seed in seeds] for variant in variants}
    baseline=combine(block['score'] for block in blocks['baseline'])
    results={}
    for variant, values in blocks.items():
        score=combine(block['score'] for block in values)
        cohorts=defaultdict(list)
        for block in values:
            for key,rows in block['cohorts'].items():
                cohorts[key].extend(rows)
        results[variant]=dict(score=score,burst_violation=violation(score,baseline,ratio),
                             cohorts={key:cohort_summary(rows) for key,rows in cohorts.items()},
                             paired_latency=interval([value['score']['metrics']['mean_ready_to_valid_proposal_seconds']-base['score']['metrics']['mean_ready_to_valid_proposal_seconds'] for value,base in zip(values,blocks['baseline'])]),
                             maximum=max(value['max_latency_seconds'] for value in values))
        print(split,variant,'latency',score['metrics']['mean_ready_to_valid_proposal_seconds'],
              'under100',score['metrics']['valid_under_100ms'],'burst violation',results[variant]['burst_violation'],flush=True)
    write_json(root/f'{split}-report.json',results)
    return results


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--run',type=Path)
    parser.add_argument('--seeds',type=int,default=2)
    parser.add_argument('--seed-start',type=int,default=0)
    parser.add_argument('--split',choices=('development','validation','heldout'),default='development')
    parser.add_argument('--variants',default=','.join(VARIANTS))
    parser.add_argument('--jobs',type=int,default=6)
    parser.add_argument('--reuse-baseline',action='store_true',help='reuse reference blocks only with the same immutable evaluation identity')
    args=parser.parse_args(argv)
    variants=tuple(args.variants.split(','))
    if 'baseline' not in variants or any(v not in (*VARIANTS,'production') for v in variants):
        parser.error('include baseline and only registered ablations')
    if args.seeds < 1 or args.seed_start < 0 or args.jobs < 1 or len(set(variants)) != len(variants):
        parser.error('use positive seeds/jobs, nonnegative seed start and unique variants')
    with ExitStack() as stack:
        if args.run:
            root=args.run.resolve()
        else:
            workspace=stack.enter_context(BenchmarkWorkspace('scheduling.watch-quiet-information'))
            root=workspace.result_dir
        for folder in ('corpus','scores','timelines'):
            (root/folder).mkdir(parents=True,exist_ok=True)
        seeds=list(range(args.seed_start,args.seed_start+args.seeds))
        plan=dict(contract=CONTRACT,metric_contract=EVALUATION_CONTRACT,arguments=vars(args)|{'baseline':str(args.baseline.resolve()),'run':str(root)},
                  variants=variants,seeds=seeds,burst_ratio=1.1,
                  sources={str(Path(path).relative_to(REPO)):fast_hash128_file(path) for path in (
                      __file__,inspect.getsourcefile(scheduler),inspect.getsourcefile(quiet_policy),str(REPO/'benchmarks/quiet_window/corpus.py'),str(REPO/'benchmarks/quiet_window/writers.py'),str(REPO/'benchmarks/quiet_window/scheduler_replay.py'))},
                  baseline_scheduler_xxh128=fast_hash128_file(str(args.baseline)))
        # Production is the intervention; corpus, scoring and the frozen
        # reference must stay identical when adding a production comparison.
        immutable=dict(contract=CONTRACT,metric_contract=EVALUATION_CONTRACT,
                       baseline=plan['baseline_scheduler_xxh128'],
                       sources={str(Path(path).relative_to(REPO)):fast_hash128_file(str(path)) for path in (
                           REPO/'benchmarks/quiet_window/corpus.py', REPO/'benchmarks/quiet_window/writers.py',
                           REPO/'benchmarks/quiet_window/scheduler_replay.py', REPO/'benchmarks/quiet_window/statistics.py',
                           REPO/'benchmarks/quiet_window/search.py', Path(inspect.getsourcefile(quiet_policy)))})
        identity=root/'evaluation-identity.json'
        if identity.exists():
            if json.loads(identity.read_text(encoding='utf8')) != immutable:
                raise ValueError('corpus/evaluation/reference changed; start a new run')
        elif args.reuse_baseline:
            raise ValueError('reference reuse requires a prior evaluation identity')
        write_json(identity,immutable)
        previous_plan=root/f'{args.split}-plan.json'
        if previous_plan.exists():
            archive=root/'plans'/f'{args.split}-{__import__("time").time_ns()}.json'
            archive.parent.mkdir(parents=True,exist_ok=True)
            archive.write_bytes(previous_plan.read_bytes())
        write_json(root/f'{args.split}-plan.json',plan)
        for seed in seeds:
            path=root/'corpus'/f'{args.split}-{seed}.jsonl.gz'
            if not path.exists():
                with gzip.open(path,'wt',encoding='utf8') as stream:
                    for trace in generate(1,(args.split,),CHANNELS,WIDTHS,seed_start=seed):
                        stream.write(json.dumps(trace.record(),separators=(',',':'))+'\n')
        plan['corpus_xxh128']={str(seed):fast_hash128_file(str(root/'corpus'/f'{args.split}-{seed}.jsonl.gz')) for seed in seeds}
        write_json(root/f'{args.split}-plan.json',plan)
        print('results:',root,flush=True)
        with ProcessPoolExecutor(max_workers=args.jobs) as pool:
            pending={}
            for variant in variants:
                for seed in seeds:
                    if variant=='baseline' and args.reuse_baseline:
                        if not (root/'scores'/f'{variant}-{args.split}-{seed}.json').exists():
                            raise ValueError(f'missing frozen reference block: {seed}')
                        continue
                    pending[pool.submit(run_block,str(root),args.split,seed,variant,str(args.baseline.resolve()))]=(variant,seed)
            for future in as_completed(pending):
                future.result()
                print('completed',pending[future],flush=True)
        report(root,variants,args.split,seeds,1.1)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
