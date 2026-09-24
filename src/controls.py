"""Self-contained model boundary examples; no service, keys or crypto operations."""
from itertools import combinations
from finite_model import Case, analyze, maximum_exposure, interval_obstruction, minimal_supports
from replay import verify, oracle_pair


def evaluate_controls():
    cases=[]
    for name,ws,caps,left,right,expected in [
        ('static-snapshot', [[0,1]]*4, [1,1], [0,1,2], [0,1,3], True),
        ('total-budget', [[0]]*4, [1,1], [0,1,2], [0,1,3], False),
        ('cross-mode-shared-lock', [[0]]*3, [0], [0,1], [1,2], False),
    ]:
        raw={'id':name,'windows':ws,'capacity':caps,'left':left,'right':right}
        cert=analyze(Case.parse(raw));actual=cert['result']=='fork-feasible'
        assert actual==expected==oracle_pair(raw) and verify(raw,cert)
        cases.append({'case':raw,'certificate':cert,'expected_fork':expected})
    ws=((0,2),)*3;caps=(1,1,1)
    matching_size=len(maximum_exposure(range(3),ws,caps))
    assert matching_size==2
    try: interval_obstruction(range(3),ws,caps)
    except ValueError: rejected=True
    else: raise AssertionError('noninterval input was not rejected')
    # Deliberately check why an interval-only condition misses a holey set.
    overloads=[(a,b) for a in range(3) for b in range(a,3)
               if sum(all(a<=t<=b for t in w) for w in ws)>sum(caps[a:b+1])]
    assert not overloads
    shared=[{'op':'key','key':0},{'op':'key','key':0},
            {'op':'threshold','k':2,'children':[0,1]}]
    supports=minimal_supports(shared,2,1)
    assert supports==((0,),)
    # The following is a different, correlated-exposure model on one toy domain.
    domains=[{0,1}];budget=1;common={0,1}
    domain_states=[set().union(*(domains[j] for j in selection))
                   for k in range(budget+1) for selection in combinations(range(len(domains)),k)]
    domain_covers=any(common<=s for s in domain_states)
    key_prediction=analyze(Case.parse({'id':'separate-keys','windows':[[0],[0]],
                                      'capacity':[1],'left':[0,1],'right':[0,1]}))['result']
    assert domain_covers and key_prediction=='pair-blocked'
    # Separate locks per operation permit a common honest witness to sign twice.
    def decisions(per_mode):
        locks={};accepted=[]
        for mode,statement,signers in [('rotate','left',[0,1]),('recover','right',[1,2])]:
            votes=[]
            for witness in signers:
                lock=(witness,'parent',mode if per_mode else 'all-modes')
                if lock not in locks or locks[lock]==statement:
                    locks[lock]=statement;votes.append(witness)
            accepted.append(len(votes)==len(signers))
        return accepted
    reset=decisions(True);shared_lock=decisions(False)
    assert reset==[True,True] and shared_lock==[True,False]
    # Identity of the local observation is illustrative, not a freshness detector.
    view=['anchor','rotation'];worlds=[view,view+['later-revocation']]
    observed=[list(view),list(view)]
    assert observed[0]==observed[1] and worlds[0]!=worlds[1]
    return {'cases':cases,
      'baseline_comparisons':{'static_snapshot_declares_safe':2*3>4+max([1,1]),
                             'lumped_budget_declares_safe':2*3>4+sum([1,1])},
      'noninterval':{'rejected_by_interval_routine':rejected,'matching_size':matching_size,
                     'contiguous_interval_overloads':overloads},
      'shared_descendants':{'nodes':shared,'minimal_supports':supports},
      'correlated_storage':{'domains':[sorted(s) for s in domains],'budget':budget,
                            'independent_key_result':key_prediction,'domain_model_fork_feasible':domain_covers,
                            'status':'computed symbolic countermodel; not the main model'},
      'operation_lock':{'per_mode_acceptance':reset,'shared_lock_acceptance':shared_lock,
                        'status':'computed symbolic countermodel; no signatures'},
      'hidden_revocation':{'worlds':worlds,'observations':observed,
                           'status':'illustrates the mathematical indistinguishability argument'}}
