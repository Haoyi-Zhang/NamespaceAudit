import copy,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from finite_model import Case,analyze,minimal_supports,maximum_exposure,hall_obstruction,interval_obstruction,threshold_safe
from replay import verify,all_minimal_supports,validate_case
from controls import evaluate_controls
from continuity import NamespaceModel, audit
from continuity_replay import direct_union_antichain, oracle as replay_oracle, verify as verify_continuity
from run_continuity import branching_model, control_models, hitting_policy, run_controls, threshold_policy

class ModelTests(unittest.TestCase):
    def setUp(self):
        self.raw={'id':'toy','windows':[[0,1]]*4,'capacity':[1,1],
                  'left':[0,1,2],'right':[0,1,3]}
    def test_positive_and_negative_certificates(self):
        for windows in ([[0,1]]*4,[[0]]*4):
            raw={**self.raw,'windows':windows};self.assertTrue(verify(raw,analyze(Case.parse(raw))))
    def test_disjoint_has_empty_witness(self):
        raw={**self.raw,'left':[0],'right':[1]};cert=analyze(Case.parse(raw))
        self.assertEqual(cert['exposures'],[]);self.assertTrue(verify(raw,cert))
    def test_parser_malformed_cases(self):
        mutations=[{'capacity':[True,1]},{'capacity':[-1,1]},{'capacity':[13,1]},
                   {'windows':[[]]*4},{'windows':[[1,0]]*4},{'windows':[[2]]*4},
                   {'left':[0,0]},{'left':[-1]},{'left':[True]},{'left':[]},
                   {'id':''},{'id':'a'*81},{'extra':1}]
        for change in mutations:
            with self.subTest(change=change):
                raw={**self.raw,**change}
                with self.assertRaises(ValueError):Case.parse(raw)
                with self.assertRaises(ValueError):validate_case(raw)
    def test_fork_certificate_mutations(self):
        good=analyze(Case.parse(self.raw));bad=[]
        for field,value in [('id','other'),('result','safe'),('exposures',[]),('extra',True)]:
            c=copy.deepcopy(good);c[field]=value;bad.append(c)
        for schedule in [[[0,0],[0,1]],[[0,0],[1,0]],[[0,0],[2,1]],[[0,0],[1,2]],[[0,True],[1,1]]]:
            c=copy.deepcopy(good);c['exposures']=schedule;bad.append(c)
        for c in bad:self.assertFalse(verify(self.raw,c))
    def test_blocked_certificate_mutations(self):
        raw={**self.raw,'windows':[[0]]*4};good=analyze(Case.parse(raw));bad=[]
        for field,value in [('capacity',0),('confined',[0]),('confined',[0,0]),
                            ('confined',[0,2]),('interval',[1,1]),('interval',[0,2]),
                            ('capacity',True)]:
            c=copy.deepcopy(good);c['obstruction'][field]=value;bad.append(c)
        for c in bad:self.assertFalse(verify(raw,c))
    def test_holey_window_requires_general_hall(self):
        ws=((0,2),)*3;self.assertEqual(len(maximum_exposure(range(3),ws,(1,1,1))),2)
        with self.assertRaises(ValueError):interval_obstruction(range(3),ws,(1,1,1))
    def test_threshold_edge_cases(self):
        ws=((0,),)*4
        self.assertTrue(threshold_safe({0,1,2,3},{0,1,2,3},3,3,ws,(1,)))
        self.assertFalse(threshold_safe({0,1,2,3},{0,1,2,3},3,3,ws,(2,)))
        self.assertFalse(threshold_safe({0},{1},1,1,ws,(0,)))
        for q in [0,5,True,1.5]:
            with self.assertRaises(ValueError):threshold_safe({0,1,2,3},{0},q,1,ws,(0,))
    def test_shared_policy_leaf(self):
        nodes=[{'op':'key','key':0},{'op':'key','key':0},{'op':'threshold','k':2,'children':[0,1]}]
        self.assertEqual(minimal_supports(nodes,2,1),((0,),))
    def test_policy_boundaries(self):
        malformed=[([{'op':'key','key':True}],0),([{'op':'key','key':0},{'op':'threshold','k':1,'children':[1]}],1),
                   ([{'op':'key','key':0},{'op':'threshold','k':1,'children':[0,0]}],1),
                   ([{'op':'key','key':0},{'op':'threshold','k':0,'children':[0]}],1)]
        for nodes,root in malformed:
            with self.assertRaises(ValueError):minimal_supports(nodes,root,1)
    def test_maximum_gate_bound_not_cartesian_explosion(self):
        nodes=[{'op':'key','key':i%12} for i in range(63)]
        nodes.append({'op':'threshold','k':32,'children':list(range(63))})
        got=set(map(frozenset,minimal_supports(nodes,63,12)))
        self.assertEqual(got,all_minimal_supports(nodes,63,12))
        self.assertTrue(got)
    def test_seven_model_boundaries(self):
        result=evaluate_controls()
        self.assertEqual(result['operation_lock']['per_mode_acceptance'],[True,True])
        self.assertTrue(result['correlated_storage']['domain_model_fork_feasible'])

    def test_recovery_order_controls(self):
        expected={
            'control-resolved-recovery':'no-conflict',
            'control-omitted-resolution':'silent-fork',
            'control-bridge-blocked':'prevented',
            'control-bridge-exposed':'accountable-fork',
            'control-joint-amplification':'prevented',
            'control-joint-feasible':'accountable-fork',
            'control-holey-hall':'prevented',
            'control-transitive-dominance':'no-conflict',
        }
        for raw in control_models():
            with self.subTest(model=raw['id']):
                result=audit(raw)
                self.assertEqual(result['result'],expected[raw['id']])
                self.assertTrue(verify_continuity(raw,result))

    def test_joint_graph_stronger_than_local_checks(self):
        raw=next(x for x in control_models() if x['id']=='control-joint-amplification')
        result=audit(raw)
        self.assertEqual(result['valid_views'],2)
        self.assertEqual(result['pairs'][0]['conflict_loci'],['root','child'])
        self.assertEqual(result['pairs'][0]['minimal_forced_sets'],[[0,1]])
        self.assertTrue(result['globally_prevented'])

    def test_continuity_parser_rejects_bad_graphs(self):
        raw=next(x for x in control_models() if x['id']=='control-resolved-recovery')
        mutations=[]
        bad=copy.deepcopy(raw);bad['events'][1]['dominates']=['missing'];mutations.append(bad)
        bad=copy.deepcopy(raw);bad['events'][0]['policy']='missing';mutations.append(bad)
        bad=copy.deepcopy(raw);bad['loci'][0]['parents']=['future'];mutations.append(bad)
        bad=copy.deepcopy(raw);bad['exposure']['windows'][0]=[];mutations.append(bad)
        for item in mutations:
            with self.assertRaises(ValueError):NamespaceModel.parse(item)

    def test_hitting_set_reduction_small_instance(self):
        family=((0,1),(1,2))
        p=hitting_policy(family,3);q=threshold_policy('all',(0,1,2),3)
        def model(budget):
            return {'id':'hs','key_count':3,'exposure':{'windows':[[0]]*3,'capacity':[budget]},
                    'policies':[p,q],'loci':[{'id':'name','parents':[]}],
                    'events':[{'id':'a','locus':'name','policy':'hit','dominates':[],'requires':{}},
                              {'id':'b','locus':'name','policy':'all','dominates':[],'requires':{}}]}
        self.assertEqual(audit(model(0))['result'],'prevented')
        self.assertEqual(audit(model(1))['result'],'accountable-fork')

    def test_continuity_oracle_detects_mutation(self):
        raw=next(x for x in control_models() if x['id']=='control-bridge-exposed')
        result=audit(raw)
        self.assertTrue(verify_continuity(raw,result))
        bad=copy.deepcopy(result);bad['pairs'][0]['minimal_forced_sets']=[[]]
        self.assertFalse(verify_continuity(raw,bad))

    def test_general_hall_certificate_and_margin(self):
        windows=((0,2),)*3;capacity=(1,1,1)
        cert=hall_obstruction(range(3),windows,capacity)
        self.assertEqual(cert,{"keys":[0,1,2],"slots":[0,2],"demand":3,
                               "capacity":2,"deficit":1})
        raw={"id":"holey","key_count":3,
             "exposure":{"windows":[[0,2]]*3,"capacity":[1,1,1]},
             "policies":[threshold_policy("all",(0,1,2),3)],
             "loci":[{"id":"name","parents":[]}],
             "events":[{"id":"left","locus":"name","policy":"all","dominates":[],"requires":{}},
                       {"id":"right","locus":"name","policy":"all","dominates":[],"requires":{}}]}
        result=audit(raw)
        self.assertEqual(result["result"],"prevented")
        self.assertEqual(result["minimum_exposure_margin"],1)
        self.assertEqual(result["pairs"][0]["forced_set_analysis"][0]["hall_obstruction"],cert)
        self.assertTrue(verify_continuity(raw,result))

    def test_no_conflict_is_distinct_from_prevented_pair(self):
        raw=next(x for x in control_models() if x["id"]=="control-resolved-recovery")
        result=audit(raw)
        self.assertEqual(result["result"],"no-conflict")
        self.assertTrue(result["globally_prevented"])
        self.assertIsNone(result["minimum_exposure_margin"])
        self.assertEqual(result["pairs"],[])
        self.assertTrue(verify_continuity(raw,result))

    def test_transitive_dominance_satisfies_parent_requirement(self):
        raw={"id":"transitive","key_count":2,
             "exposure":{"windows":[[0],[0]],"capacity":[0]},
             "policies":[{"id":"p0","nodes":[{"op":"key","key":0}],"root":0},
                         {"id":"p1","nodes":[{"op":"key","key":1}],"root":0}],
             "loci":[{"id":"root","parents":[]},{"id":"child","parents":["root"]}],
             "events":[
                 {"id":"r0","locus":"root","policy":"p0","dominates":[],"requires":{}},
                 {"id":"r1","locus":"root","policy":"p0","dominates":["r0"],"requires":{}},
                 {"id":"r2","locus":"root","policy":"p1","dominates":["r1"],"requires":{}},
                 {"id":"c","locus":"child","policy":"p0","dominates":[],"requires":{"root":"r0"}}]}
        result=audit(raw)
        self.assertEqual(result["valid_views"],3)
        self.assertEqual(result["result"],"no-conflict")
        self.assertTrue(verify_continuity(raw,result))

    def test_continuity_reader_rejects_witness_and_margin_mutations(self):
        raw=next(x for x in control_models() if x["id"]=="control-joint-feasible")
        good=audit(raw)
        self.assertTrue(verify_continuity(raw,good))
        mutations=[]
        bad=copy.deepcopy(good);bad["pairs"][0]["fork_witness"]["exposures"]=[[0,0]];mutations.append(bad)
        bad=copy.deepcopy(good);bad["pairs"][0]["fork_witness"]["supports"][0]["left_support"]=[1];mutations.append(bad)
        bad=copy.deepcopy(good);bad["pairs"][0]["exposure_margin"]=1;mutations.append(bad)
        bad=copy.deepcopy(good);bad["pairs"][0]["forced_set_analysis"][0]["matching_size"]=1;mutations.append(bad)
        bad=copy.deepcopy(good);bad["minimal_fork_witness"]=copy.deepcopy(good["pairs"][0]);bad["minimal_fork_witness"]["left_view"]=["r1","c1"];mutations.append(bad)
        for item in mutations:
            self.assertFalse(verify_continuity(raw,item))

    def test_direct_union_oracle_exercises_branching_pruning(self):
        target=direct_union_antichain([[[0],[1]],[[1],[2]]])
        self.assertEqual(target['minimal_sets'],[[1],[0,2]])
        self.assertEqual(target['raw_combination_count'],4)
        duplicate=direct_union_antichain([[[0],[1]],[[0],[1]]])
        self.assertEqual(duplicate['minimal_sets'],[[0],[1]])
        self.assertEqual(duplicate['distinct_union_count'],3)
        superset=direct_union_antichain([[[0],[0,1]],[[2]]])
        self.assertEqual(superset['minimal_sets'],[[0,2]])
        shared=direct_union_antichain([[[0],[1]],[[0],[2]],[[0],[3]]])
        self.assertEqual(shared['minimal_sets'],[[0],[1,2,3]])
        reversed_target=direct_union_antichain([[[1],[2]],[[0],[1]]])
        self.assertEqual(reversed_target['minimal_sets'],target['minimal_sets'])

    def test_branching_model_preserves_feasible_incomparable_branch(self):
        for reverse in (False,True):
            with self.subTest(reverse=reverse):
                raw=branching_model('branching-test-'+str(reverse).lower(),reverse)
                result=audit(raw)
                self.assertTrue(verify_continuity(raw,result))
                self.assertEqual(result['valid_views'],2)
                self.assertEqual(len(result['pairs']),1)
                pair=result['pairs'][0]
                self.assertEqual(pair['option_counts'],[2,2])
                self.assertEqual(pair['minimal_forced_sets'],[[1],[0,2]])
                self.assertEqual(pair['classification'],'accountable-fork')
                self.assertTrue(pair['accountable'])
                self.assertEqual(pair['exposure_margin'],0)
                self.assertEqual(pair['fork_witness']['forced_keys'],[0,2])
                direct=replay_oracle(raw)
                self.assertEqual(direct['pairs'][0]['minimal_forced_sets'],[[1],[0,2]])

    def test_replay_admission_rejects_vacuity_and_null_witness(self):
        resolved=next(x for x in control_models() if x['id']=='control-resolved-recovery')
        self.assertTrue(verify_continuity(resolved,audit(resolved)))
        empty=copy.deepcopy(resolved);empty['id']='empty';empty['events']=[]
        forged={'id':'empty','result':'no-conflict','valid_views':0,'incompatible_view_pairs':0,
                'pair_counts':{'prevented':0,'accountable-fork':0,'silent-fork':0},
                'globally_prevented':True,'globally_accountable':True,
                'minimum_exposure_margin':None,'pairs':[]}
        self.assertFalse(verify_continuity(empty,forged))
        feasible=next(x for x in control_models() if x['id']=='control-joint-feasible')
        bad=audit(feasible);bad['pairs'][0]['fork_witness']=None
        self.assertFalse(verify_continuity(feasible,bad))

    def test_policy_children_may_be_unsorted_but_must_precede(self):
        nodes=[{'op':'key','key':0},{'op':'key','key':1},
               {'op':'threshold','k':1,'children':[1,0]}]
        self.assertEqual(minimal_supports(nodes,2,2),((0,),(1,)))

    def test_semantic_control_distribution_is_automatic(self):
        with tempfile.TemporaryDirectory() as directory:
            summary=run_controls(Path(directory))
        self.assertEqual(summary['result_counts'],{
            'no-conflict':2,'prevented':3,'accountable-fork':2,'silent-fork':1})

    def test_continuity_reader_rejects_numeric_type_substitutions(self):
        def leaves(value, path=()):
            if type(value) in (int, bool):
                yield path, value
            elif isinstance(value, dict):
                for key, child in value.items():
                    yield from leaves(child, path+(key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from leaves(child, path+(index,))
        for raw in control_models()+[branching_model('typed-branching')]:
            good=audit(raw)
            self.assertTrue(verify_continuity(raw,good))
            for path, old in leaves(good):
                replacements=[int(old)] if type(old) is bool else [float(old)]
                if type(old) is int and old in (0,1):
                    replacements.append(bool(old))
                for replacement in replacements:
                    with self.subTest(model=raw['id'],path=path,replacement=replacement):
                        bad=copy.deepcopy(good);parent=bad
                        for part in path[:-1]:parent=parent[part]
                        parent[path[-1]]=replacement
                        self.assertFalse(verify_continuity(raw,bad))

    def test_continuity_reader_preserves_valid_json_roundtrip(self):
        import json
        for raw in control_models()+[branching_model('roundtrip-branching')]:
            model=json.loads(json.dumps(raw))
            reported=json.loads(json.dumps(audit(model)))
            self.assertTrue(verify_continuity(model,reported))

if __name__=='__main__':unittest.main()
