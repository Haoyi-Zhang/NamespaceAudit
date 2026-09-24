"""Bounded command-line interface for an interval-window certificate audit."""
import argparse,json,resource
from pathlib import Path
from finite_model import Case,analyze


def main():
    resource.setrlimit(resource.RLIMIT_AS,(3*1024**3,3*1024**3))
    resource.setrlimit(resource.RLIMIT_CPU,(120,120))
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('cases',type=Path);p.add_argument('certificates',type=Path)
    args=p.parse_args()
    count=0
    # Never overwrite an existing file. A failure may leave a partial file:
    # its name alone is not evidence of completion; the exit code is authoritative.
    with args.cases.open('rb') as inp,args.certificates.open('x') as out:
        while True:
            line=inp.readline(65537)
            if not line:break
            if len(line)>65536:raise SystemExit('input line exceeds 64 KiB bound')
            if count>=100000:raise SystemExit('input exceeds 100000-case batch bound')
            try:
                case=Case.parse(json.loads(line))
                if any(tuple(range(w[0],w[-1]+1))!=w for w in case.windows):
                    raise ValueError('CLI accepts contiguous exposure windows only')
                cert=analyze(case)
            except (ValueError,TypeError,UnicodeError) as exc:
                raise SystemExit(f'case {count+1} rejected: {exc}')
            out.write(json.dumps(cert,separators=(',',':'))+'\n');count+=1
    print(json.dumps({'completed_cases':count,'symbolic_only':True}))

if __name__=='__main__':main()
