"""Independent certificate reader and small state-space oracle.

Does not import the matching implementation, its parser, its policy compiler,
or its interval theorem. Symbolic certificates, not signature verification.
"""
from __future__ import annotations
from itertools import combinations,product
import json,sys
from pathlib import Path


def validate_case(raw:dict)->None:
    if not isinstance(raw,dict) or sorted(raw)!=['capacity','id','left','right','windows']:
        raise ValueError('bad case schema')
    if not isinstance(raw['id'],str) or not 1<=len(raw['id'])<=80:raise ValueError('bad id')
    if not isinstance(raw['capacity'],list) or not 1<=len(raw['capacity'])<=12:raise ValueError('bad horizon')
    if not isinstance(raw['windows'],list) or not 1<=len(raw['windows'])<=12:raise ValueError('bad key bound')
    n=len(raw['windows']);t=len(raw['capacity'])
    if any(type(v) is not int or v<0 or v>12 for v in raw['capacity']):raise ValueError('bad capacity')
    for arr,bound in [(x,t) for x in raw['windows']]+[(raw['left'],n),(raw['right'],n)]:
        if not isinstance(arr,list) or not arr:raise ValueError('empty/invalid index list')
        prev=-1
        for v in arr:
            if type(v) is not int or v<=prev or v>=bound:raise ValueError('bad index order/range')
            prev=v


def oracle_exposed_sets(raw:dict)->set[frozenset[int]]:
    """Enumerate all per-slot exposure subsets; no matching or Hall reasoning."""
    validate_case(raw)
    states={frozenset()}
    for t,cap in enumerate(raw['capacity']):
        active=[k for k,w in enumerate(raw['windows']) if t in w]
        choices=[frozenset(c) for size in range(min(cap,len(active))+1) for c in combinations(active,size)]
        states={s|c for s in states for c in choices}
    return states


def oracle_pair(raw:dict)->bool:
    common=set(raw['left']).intersection(raw['right'])
    return any(common<=s for s in oracle_exposed_sets(raw))


def verify(raw:dict,cert:dict)->bool:
    """Check a short witness without searching for a schedule or trusting solver."""
    try:
        validate_case(raw)
        if not isinstance(cert,dict) or cert.get('id')!=raw['id']:return False
        common=set(raw['left'])&set(raw['right'])
        if cert.get('result')=='fork-feasible':
            if set(cert)!={'id','result','exposures'} or not isinstance(cert['exposures'],list):return False
            used=set();counts=[0]*len(raw['capacity'])
            for item in cert['exposures']:
                if not isinstance(item,list) or len(item)!=2:return False
                k,t=item
                if type(k) is not int or type(t) is not int or k not in common or k in used:return False
                if t not in raw['windows'][k]:return False
                used.add(k);counts[t]+=1
            return used==common and all(a<=b for a,b in zip(counts,raw['capacity']))
        if cert.get('result')=='pair-blocked':
            if set(cert)!={'id','result','obstruction'}:return False
            ob=cert['obstruction']
            if not isinstance(ob,dict) or set(ob)!={'interval','confined','capacity'}:return False
            ends=ob['interval']
            if not isinstance(ends,list) or len(ends)!=2:return False
            a,b=ends
            if type(a) is not int or type(b) is not int or not 0<=a<=b<len(raw['capacity']):return False
            keys=ob['confined']
            if not isinstance(keys,list) or any(type(k) is not int for k in keys) or len(set(keys))!=len(keys):return False
            if not set(keys)<=common:return False
            if any(any(not a<=t<=b for t in raw['windows'][k]) for k in keys):return False
            cap=sum(raw['capacity'][a:b+1])
            return type(ob['capacity']) is int and ob['capacity']==cap and len(keys)>cap
        return False
    except (KeyError,TypeError,ValueError,IndexError):return False


def evaluate_policy(nodes:list[dict],root:int,available:set[int])->bool:
    values=[]
    for node in nodes:
        if node['op']=='key':values.append(node['key'] in available)
        else:values.append(sum(values[j] for j in node['children'])>=node['k'])
    return values[root]


def all_minimal_supports(nodes:list[dict],root:int,n:int)->set[frozenset[int]]:
    result=set()
    for mask in range(1<<n):
        keys={i for i in range(n) if mask&(1<<i)}
        if not evaluate_policy(nodes,root,keys):continue
        if any(evaluate_policy(nodes,root,keys-{i}) for i in keys):continue
        result.add(frozenset(keys))
    return result


def main()->None:
    import resource
    if len(sys.argv)!=3:raise SystemExit('usage: replay.py CASES.jsonl CERTIFICATES.jsonl')
    resource.setrlimit(resource.RLIMIT_AS,(3*1024**3,3*1024**3))
    resource.setrlimit(resource.RLIMIT_CPU,(120,120))
    count=0
    with Path(sys.argv[1]).open('rb') as a,Path(sys.argv[2]).open('rb') as b:
        while True:
            aline=a.readline(65537);bline=b.readline(65537)
            if not aline and not bline:break
            if not aline or not bline:raise SystemExit('different input/certificate counts')
            if len(aline)>65536 or len(bline)>65536:raise SystemExit('line exceeds 64 KiB bound')
            if count>=100000:raise SystemExit('input exceeds 100000-case batch bound')
            try:
                raw=json.loads(aline);cert=json.loads(bline)
            except (ValueError,UnicodeError) as exc:
                raise SystemExit('invalid JSON input: '+str(exc))
            if not verify(raw,cert):raise SystemExit('certificate rejected at input line '+str(count+1))
            count+=1
    print(json.dumps({'accepted_certificates':count,'reader_imports_solver':False}))

if __name__=='__main__':main()
