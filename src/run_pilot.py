"""Deterministic, single-process pilot and reproduction. Output may be redirected."""
from __future__ import annotations
import argparse,csv,json,resource,time
from pathlib import Path
from itertools import product,combinations
from finite_model import Case,analyze,threshold_safe,minimal_supports,maximum_exposure,interval_obstruction
from replay import oracle_exposed_sets,verify,all_minimal_supports
from controls import evaluate_controls


def dump(path:Path,obj:object)->None:path.write_text(json.dumps(obj,indent=2,sort_keys=True)+'\n')


def main()->None:
    resource.setrlimit(resource.RLIMIT_AS,(3*1024**3,3*1024**3))
    resource.setrlimit(resource.RLIMIT_CPU,(120,120))
    ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'results/reproduced')
    args=ap.parse_args();out=args.output
    # Refuse to silently replace an existing result folder.
    out.mkdir(parents=True,exist_ok=False)
    wall=time.perf_counter();cpu=time.process_time()
    n=3;windows=[(0,),(1,),(0,1)]
    subsets=[tuple(i for i in range(n) if m&(1<<i)) for m in range(1,1<<n)]
    count=0;forks=0;threshold_count=0;safe_thresholds=0;oracle_states=0
    with (out/'threshold-results.csv').open('w',newline='') as ft, (out/'cases.jsonl').open('w') as fi,(out/'certificates.jsonl').open('w') as fc,(out/'case-results.csv').open('w',newline='') as fr:
        tw=csv.writer(ft);tw.writerow(['window_tuple','capacities','left_committee','right_committee','left_threshold','right_threshold','predicted_safe','oracle_safe'])
        writer=csv.writer(fr);writer.writerow(['case_id','common_keys','matching_size','fork_feasible','oracle_fork','certificate_accepted'])
        for ws in product(windows,repeat=n):
            for caps in product((0,1),repeat=2):
                proto={'id':'oracle','windows':[list(w) for w in ws],'capacity':list(caps),'left':[0],'right':[0]}
                states=oracle_exposed_sets(proto);oracle_states+=len(states)
                for left,right in product(subsets,repeat=2):
                    count+=1
                    raw={**proto,'id':f'case-{count:05d}','left':list(left),'right':list(right)}
                    case=Case.parse(raw);cert=analyze(case)
                    actual=cert['result']=='fork-feasible'
                    expected=any(set(left)&set(right)<=s for s in states)
                    accepted=verify(raw,cert)
                    if actual!=expected or not accepted:raise AssertionError((raw,cert,expected))
                    forks+=actual
                    fi.write(json.dumps(raw,separators=(',',':'))+'\n');fc.write(json.dumps(cert,separators=(',',':'))+'\n')
                    writer.writerow([raw['id'],len(case.common()),len(maximum_exposure(case.common(),ws,caps)),int(actual),int(expected),int(accepted)])
                for a,b in product(subsets,repeat=2):
                    for qa in range(1,len(a)+1):
                        for qb in range(1,len(b)+1):
                            predicted=threshold_safe(set(a),set(b),qa,qb,ws,caps)
                            # Independent enumeration over all exact-size quorums and every exposed set.
                            expected=not any(set(x)&set(y)<=s for x in combinations(a,qa) for y in combinations(b,qb) for s in states)
                            if predicted!=expected:raise AssertionError(('threshold',a,b,qa,qb,ws,caps))
                            tw.writerow([json.dumps(ws,separators=(',',':')),json.dumps(caps),json.dumps(a),json.dumps(b),qa,qb,int(predicted),int(expected)])
                            threshold_count+=1;safe_thresholds+=predicted
    # Replay the exact originally seeded policy inputs, not a runtime-dependent PRNG.
    policy_count=0;assignments=0
    frozen=Path(__file__).resolve().parents[1]/'inputs/policies.jsonl'
    with frozen.open() as fin,(out/'policies.jsonl').open('w') as fp:
        for p,line in enumerate(fin):
            raw=json.loads(line)
            if set(raw)!={'id','key_count','nodes','root'} or raw['id']!=f'policy-{p+1:03d}' or raw['key_count']!=6:
                raise ValueError('policy input does not match the fixed pilot selection')
            nodes=raw['nodes'];root=raw['root']
            got=minimal_supports(nodes,root,6);expected=all_minimal_supports(nodes,root,6)
            if set(map(frozenset,got))!=expected:raise AssertionError('policy mismatch')
            fp.write(json.dumps({**raw,'minimal_supports':got},separators=(',',':'))+'\n')
            policy_count+=1;assignments+=64
    if policy_count!=128:raise AssertionError('frozen policy input count differs from protocol')
    dump(out/'controls.json',evaluate_controls())
    summary={'purpose':'pre-lock feasibility pilot','main_cases':count,'fork_feasible':forks,'pair_blocked':count-forks,'solver_oracle_mismatches':0,'independent_certificate_replay_failures':0,'threshold_cases':threshold_count,'threshold_safe':safe_thresholds,'threshold_unsafe':threshold_count-safe_thresholds,'threshold_mismatches':0,'policy_cases':policy_count,'policy_truth_assignments':assignments,'policy_mismatches':0,'oracle_distinct_state_sum_over_window_capacity_inputs':oracle_states,'workers':1,'cpu_seconds':time.process_time()-cpu,'wall_seconds':time.perf_counter()-wall,'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'finite_not_mechanized_general_proof':True}
    assert count==5292 and threshold_count==15552
    dump(out/'summary.json',summary);print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
