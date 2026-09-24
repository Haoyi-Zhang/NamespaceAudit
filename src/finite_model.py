"""Finite symbolic audit. No keys, cryptographic operations, networks, or protocol clients.

One checkpoint decision, one distinct key per witness, deterministic irreversible
one-successor locks, and independent key-exposure events. See proofs/model.md.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable

MAX_KEYS=12
MAX_SLOTS=12
MAX_POLICY_NODES=64

@dataclass(frozen=True)
class Case:
    name: str
    windows: tuple[tuple[int,...],...]
    capacity: tuple[int,...]
    left: tuple[int,...]
    right: tuple[int,...]

    @classmethod
    def parse(cls, raw: dict) -> 'Case':
        if not isinstance(raw,dict) or set(raw)!={'id','windows','capacity','left','right'}:
            raise ValueError('case must contain exactly id/windows/capacity/left/right')
        name=raw['id']
        if not isinstance(name,str) or not name or len(name)>80:
            raise ValueError('invalid case identifier')
        cap=raw['capacity'];win=raw['windows']
        if not isinstance(cap,list) or not 1<=len(cap)<=MAX_SLOTS:
            raise ValueError('slot count outside bounded model')
        if any(type(c) is not int or not 0<=c<=MAX_KEYS for c in cap):
            raise ValueError('nonnegative bounded integer capacities required')
        if not isinstance(win,list) or not 1<=len(win)<=MAX_KEYS:
            raise ValueError('key count outside bounded model')
        def ordered_ints(v: object, upper: int, allow_empty:bool) -> tuple[int,...]:
            if not isinstance(v,list) or (not v and not allow_empty):
                raise ValueError('invalid index list')
            if any(type(x) is not int or not 0<=x<upper for x in v):
                raise ValueError('index outside model')
            if v!=sorted(set(v)):
                raise ValueError('indices must be strictly increasing')
            return tuple(v)
        windows=tuple(ordered_ints(w,len(cap),False) for w in win)
        left=ordered_ints(raw['left'],len(win),False)
        right=ordered_ints(raw['right'],len(win),False)
        return cls(name,windows,tuple(cap),left,right)

    def common(self)->tuple[int,...]:
        return tuple(sorted(set(self.left)&set(self.right)))


def maximum_exposure(keys: Iterable[int], windows: tuple[tuple[int,...],...], capacity:tuple[int,...])->dict[int,int]:
    """Maximum cardinality key-to-slot assignment by augmenting paths.

    Slot capacities are represented as distinct unit positions. Deterministic
    iteration gives reproducible witnesses; no external matching library.
    """
    positions=[(t,j) for t,c in enumerate(capacity) for j in range(c)]
    owner: dict[tuple[int,int],int]={}
    def augment(k:int,seen:set[tuple[int,int]])->bool:
        for pos in positions:
            if pos[0] not in windows[k] or pos in seen:
                continue
            seen.add(pos)
            old=owner.get(pos)
            if old is None or augment(old,seen):
                owner[pos]=k
                return True
        return False
    for k in sorted(keys):augment(k,set())
    return {k:pos[0] for pos,k in sorted(owner.items())}


def hall_obstruction(keys: Iterable[int], windows: tuple[tuple[int,...],...], capacity:tuple[int,...])->dict|None:
    """Return a maximum-deficiency Hall witness for arbitrary key windows.

    The bipartite exposure graph expands slot ``t`` into ``capacity[t]`` unit
    positions.  A key subset ``Y`` violates Hall exactly when the total capacity
    in the union of its allowed slots is smaller than ``|Y|``.  The checker is
    bounded to at most twelve keys, so exhaustive subset enumeration is both
    simple and independently replayable.  The returned deficit equals
    ``|keys| - maximum_matching_size``.
    """
    ordered=tuple(sorted(set(keys)))
    if any(type(k) is not int or not 0<=k<len(windows) for k in ordered):
        raise ValueError('key outside exposure model')
    best:tuple[int,int,tuple[int,...],tuple[int,...],int]|None=None
    for mask in range(1,1<<len(ordered)):
        subset=tuple(ordered[i] for i in range(len(ordered)) if mask&(1<<i))
        slots=tuple(sorted({t for k in subset for t in windows[k]}))
        available=sum(capacity[t] for t in slots)
        deficit=len(subset)-available
        if deficit<=0:
            continue
        # Maximize deficit; then prefer fewer keys and lexicographically smaller
        # witnesses so certificates are deterministic.
        candidate=(deficit,-len(subset),tuple(-k for k in subset),slots,available)
        if best is None or candidate>best:
            best=candidate
    assignment=maximum_exposure(ordered,windows,capacity)
    matching_deficit=len(ordered)-len(assignment)
    if matching_deficit==0:
        if best is not None:
            raise AssertionError('Hall witness found for a saturating matching')
        return None
    if best is None or best[0]!=matching_deficit:
        raise AssertionError('maximum Hall deficit does not match matching deficit')
    deficit,_,neg_subset,slots,available=best
    subset=tuple(-k for k in neg_subset)
    return {'keys':list(subset),'slots':list(slots),'demand':len(subset),
            'capacity':available,'deficit':deficit}


def interval_obstruction(keys:Iterable[int], windows:tuple[tuple[int,...],...], capacity:tuple[int,...])->dict|None:
    """Hall obstruction for interval windows only; rejects noninterval inputs."""
    keys=tuple(sorted(keys))
    for k in keys:
        w=windows[k]
        if tuple(range(w[0],w[-1]+1))!=w:
            raise ValueError('interval certificate requires contiguous nonempty windows')
    candidates=[]
    for a in range(len(capacity)):
        for b in range(a,len(capacity)):
            confined=[k for k in keys if a<=windows[k][0] and windows[k][-1]<=b]
            budget=sum(capacity[a:b+1])
            if len(confined)>budget:
                candidates.append((b-a,a,b,confined,budget))
    if not candidates:return None
    _,a,b,confined,budget=min(candidates)
    return {'interval':[a,b],'confined':confined,'capacity':budget}


def analyze(case:Case)->dict:
    common=case.common()
    assignment=maximum_exposure(common,case.windows,case.capacity)
    if len(assignment)==len(common):
        return {'id':case.name,'result':'fork-feasible','exposures':[[k,assignment[k]] for k in common]}
    obstruction=interval_obstruction(common,case.windows,case.capacity)
    if obstruction is None:
        raise AssertionError('non-saturating interval matching lacks overload certificate')
    return {'id':case.name,'result':'pair-blocked','obstruction':obstruction}


def threshold_safe(left_committee:set[int],right_committee:set[int],ql:int,qr:int,windows:tuple[tuple[int,...],...],capacity:tuple[int,...])->bool:
    """Exact mixed-threshold test, only for the independent-exposure model."""
    if type(ql) is not int or type(qr) is not int or not 1<=ql<=len(left_committee) or not 1<=qr<=len(right_committee):
        raise ValueError('threshold must authorize at least one nonempty quorum')
    overlap=left_committee&right_committee
    rank=len(maximum_exposure(overlap,windows,capacity))
    return ql+qr>len(left_committee|right_committee)+rank


def minimal_supports(nodes:list[dict],root:int,key_count:int)->tuple[tuple[int,...],...]:
    """Compile a bounded monotone DAG with bit-parallel truth functions.

    At most 2**12 truth bits per gate, including for high-fanin thresholds.
    Counting true child predicates is not counting independent physical keys.
    This algorithm avoids constructing products of child support antichains.
    """
    if type(key_count) is not int or not 1<=key_count<=MAX_KEYS:
        raise ValueError('invalid key count')
    if not isinstance(nodes,list) or not 1<=len(nodes)<=MAX_POLICY_NODES or type(root) is not int or not 0<=root<len(nodes):
        raise ValueError('invalid policy bounds/root')
    assignments=1<<key_count
    all_bits=(1<<assignments)-1
    values=[]
    for i,node in enumerate(nodes):
        if not isinstance(node,dict):raise ValueError('node must be an object')
        if node.get('op')=='key':
            if set(node)!={'op','key'} or type(node['key']) is not int or not 0<=node['key']<key_count:
                raise ValueError('invalid key leaf')
            bit=1<<node['key']
            values.append(sum(1<<mask for mask in range(assignments) if mask&bit))
            continue
        if node.get('op')!='threshold' or set(node)!={'op','k','children'}:
            raise ValueError('unknown policy node')
        ch=node['children'];k=node['k']
        if not isinstance(ch,list) or not ch or any(type(x) is not int or not 0<=x<i for x in ch) or len(set(ch))!=len(ch):
            raise ValueError('children must be distinct preceding nodes')
        if type(k) is not int or not 1<=k<=len(ch):raise ValueError('invalid gate threshold')
        at_least=[all_bits]+[0]*k
        for seen,child in enumerate(ch,1):
            for j in range(min(k,seen),0,-1):
                at_least[j] |= at_least[j-1] & values[child]
        values.append(at_least[k])
    truth=values[root]
    supports=[]
    for mask in range(assignments):
        if not (truth>>mask)&1:continue
        keys=tuple(i for i in range(key_count) if mask&(1<<i))
        if any((truth>>(mask^(1<<i)))&1 for i in keys):continue
        supports.append(keys)
    return tuple(sorted(supports,key=lambda x:(len(x),x)))
