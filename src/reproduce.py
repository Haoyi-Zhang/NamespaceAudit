"""Run the documented checks sequentially in a fresh, explicit output directory."""
import argparse,json,os,resource,subprocess,sys,time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,required=True)
    args=ap.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1'}
    def limits():
        resource.setrlimit(resource.RLIMIT_AS,(3*1024**3,3*1024**3))
        resource.setrlimit(resource.RLIMIT_CPU,(120,120))
    ledger=[]
    steps=[('unit-tests',['-m','unittest','discover','-s','tests','-v']),
           ('finite-reproduction',['src/run_pilot.py','--output',str(out/'finite')]),
           ('continuity-reproduction',['src/run_continuity.py','--output',str(out/'continuity')]),
           ('certificate-generation',['src/audit.py',str(out/'finite/cases.jsonl'),str(out/'recomputed-certificates.jsonl')]),
           ('certificate-replay',['src/replay.py',str(out/'finite/cases.jsonl'),str(out/'recomputed-certificates.jsonl')]),
           ('continuity-replay',['src/continuity_replay.py',str(out/'continuity/graph-models.jsonl'),str(out/'continuity/graph-results.jsonl')])]
    for label,command in steps:
        before=resource.getrusage(resource.RUSAGE_CHILDREN);start=time.perf_counter()
        run=subprocess.run([sys.executable]+command,cwd=ROOT,env=env,preexec_fn=limits,
                           stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=120)
        after=resource.getrusage(resource.RUSAGE_CHILDREN)
        (out/(label+'.txt')).write_text(run.stdout)
        ledger.append({'step':label,'exit_code':run.returncode,'workers':1,
                       'cpu_seconds':after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
                       'wall_seconds':time.perf_counter()-start,
                       'cumulative_child_peak_rss_kib':after.ru_maxrss})
        if run.returncode:
            (out/'run-ledger.json').write_text(json.dumps(ledger,indent=2)+'\n')
            raise SystemExit(label+' failed; retain output as failure evidence')
    assert (out/'recomputed-certificates.jsonl').read_bytes()==(out/'finite/certificates.jsonl').read_bytes()
    summary=json.loads((out/'finite/summary.json').read_text())
    expected=json.loads((ROOT/'inputs/expected-finite-counts.json').read_text())
    for key,value in expected.items():
        if summary.get(key)!=value:raise AssertionError('count mismatch: '+key)
    continuity=json.loads((out/'continuity/summary.json').read_text())
    expected_continuity=json.loads((ROOT/'inputs/expected-continuity-counts.json').read_text())
    observed_continuity={
        'total_recorded_rows':continuity['evidence_unit_totals']['total_recorded_rows'],
        'checker_replay_namespace_models':continuity['evidence_unit_totals']['checker_replay_namespace_models'],
        'threshold_recorded_rows':continuity['threshold_grid']['recorded_rows'],
        'threshold_formula_oracle_cases':continuity['threshold_grid']['incomparable_formula_oracle_cases'],
        'threshold_ordered_relation_rows':continuity['threshold_grid']['ordered_relation_derived_rows'],
        'threshold_no_conflict':continuity['threshold_grid']['counts']['no-conflict'],
        'threshold_prevented':continuity['threshold_grid']['counts']['prevented'],
        'threshold_accountable_fork':continuity['threshold_grid']['counts']['accountable-fork'],
        'threshold_silent_fork':continuity['threshold_grid']['counts']['silent-fork'],
        'threshold_formula_oracle_mismatches':continuity['threshold_grid']['formula_oracle_mismatches'],
        'threshold_derived_relation_mismatches':continuity['threshold_grid']['derived_relation_mismatches'],
        'graph_models':continuity['graph_grid']['models'],
        'graph_no_conflict':continuity['graph_grid']['result_counts']['no-conflict'],
        'graph_prevented':continuity['graph_grid']['result_counts']['prevented'],
        'graph_accountable_fork':continuity['graph_grid']['result_counts']['accountable-fork'],
        'graph_silent_fork':continuity['graph_grid']['result_counts']['silent-fork'],
        'graph_incompatible_view_pairs':continuity['graph_grid']['incompatible_view_pairs'],
        'graph_multi_locus_incompatible_pairs':continuity['graph_grid']['multi_locus_incompatible_pairs'],
        'graph_pairs_with_multiple_local_options':continuity['graph_grid']['pairs_with_multiple_local_options'],
        'graph_pairs_with_multiple_final_sets':continuity['graph_grid']['pairs_with_multiple_final_sets'],
        'graph_joint_exposure_blocked_pairs':continuity['graph_grid']['joint_exposure_blocked_pairs'],
        'graph_hall_obstruction_certificates':continuity['graph_grid']['hall_obstruction_certificates'],
        'reduction_cases':continuity['hitting_set_reduction_grid']['cases'],
        'reduction_feasible':continuity['hitting_set_reduction_grid']['fork_feasible'],
        'policy_pair_cases':continuity['policy_pair_grid']['cases'],
        'policy_pair_feasible':continuity['policy_pair_grid']['fork_feasible'],
        'controls':continuity['controls']['cases'],
        'controls_no_conflict':continuity['controls']['result_counts']['no-conflict'],
        'controls_prevented':continuity['controls']['result_counts']['prevented'],
        'controls_accountable_fork':continuity['controls']['result_counts']['accountable-fork'],
        'controls_silent_fork':continuity['controls']['result_counts']['silent-fork'],
        'margin_oracle_cases':continuity['capacity_margin_oracle_grid']['cases'],
        'margin_oracle_mismatches':continuity['capacity_margin_oracle_grid']['mismatches'],
        'branching_family_cases':continuity['branching_pruning_regressions']['family_cases'],
        'branching_model_cases':continuity['branching_pruning_regressions']['model_cases'],
        'branching_mismatches':continuity['branching_pruning_regressions']['mismatches'],
        'replay_admission_checks':continuity['replay_admission_controls']['checks'],
        'replay_admission_all_passed':continuity['replay_admission_controls']['all_passed'],
    }
    if observed_continuity!=expected_continuity:
        raise AssertionError('continuity count mismatch')
    (out/'run-ledger.json').write_text(json.dumps(ledger,indent=2)+'\n')
    result={'all_commands_succeeded':True,'deterministic_certificate_bytes_equal':True,
            'expected_finite_counts_equal':True,'expected_continuity_counts_equal':True,'measured_child_cpu_seconds':sum(r['cpu_seconds'] for r in ledger),
            'cumulative_child_peak_rss_kib':ledger[-1]['cumulative_child_peak_rss_kib'],
            'general_proof_mechanized':False,'independent_human_review':False}
    (out/'reproduction.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
