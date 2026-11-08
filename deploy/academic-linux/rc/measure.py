"""Run a small bounded workload and record host-independent measurements."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import time
import uuid

from rc import HERE, Smoke, base, check, configure, run


def percentile(values, p):
    rows=sorted(values)
    pos=(len(rows)-1)*p
    lo=int(pos)
    return round(rows[lo]+(rows[min(lo+1,len(rows)-1)]-rows[lo])*(pos-lo),2)


def summary(values):
    return {'count':len(values),'p50_ms':percentile(values,.50),'p95_ms':percentile(values,.95),
            'p99_ms':percentile(values,.99)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',required=True,type=Path)
    p.add_argument('--config',default=HERE/'rehearsal.json',type=Path)
    p.add_argument('--project',default='zt-pd-r22')
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args()
    c,m,_,_=configure(a.config,a.manifest,a.project)
    s=Smoke(c)
    s.infrastructure()
    import risk_smoke as risk
    accounts=s.accounts()
    logins=[]
    tokens=[]
    for name in ('student_a','student_b'):
        started=time.monotonic()
        _,t=s.auth_flow(accounts[name])
        logins.append(round((time.monotonic()-started)*1000,2))
        tokens.append(t['access_token'])
    caller=risk.issue(risk.CLIENT)
    ids=base.compose('ps','-q','--status','running').stdout.splitlines()
    check(len(ids)==8,'Capacity test requires the full stack')
    stats=[]
    def sample():
        return [json.loads(x) for x in run('docker','stats','--no-stream','--format','{{json .}}',*ids).stdout.splitlines()]

    def job(index):
        client=s.client()
        risk_ms=[]
        school_ms=[]
        for _ in range(5):
            start=time.monotonic()
            status,_,_=s.request(client,s.portal+'/api/students/me/scores',token=tokens[index%len(tokens)])
            check(status==200,'School request failed during bounded load')
            school_ms.append((time.monotonic()-start)*1000)
            start=time.monotonic()
            risk.evaluate(caller,str(uuid.uuid4()),'198.51.100.22',None)
            risk_ms.append((time.monotonic()-start)*1000)
            time.sleep(.5)
        return school_ms,risk_ms

    metrics={}
    stats.append(sample())
    for concurrency in (2,5):
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            jobs=[executor.submit(job,n) for n in range(concurrency)]
            while not all(f.done() for f in jobs):
                stats.append(sample())
                time.sleep(.5)
            rows=[f.result() for f in jobs]
        metrics[str(concurrency)]={'school':summary([x for row in rows for x in row[0]]),
            'risk_docker_exec_inclusive':summary([x for row in rows for x in row[1]]),'errors':0}
    images={b['image']:int(run('docker','image','inspect','--format','{{.Size}}',b['image']).stdout) for b in m['builds'].values()}
    for ref in m['registry']:
        images[ref]=int(run('docker','image','inspect','--format','{{.Size}}',ref).stdout)
    sizes={}
    for service,dir in (('mysql','/var/lib/mysql'),('redis','/data')):
        sizes[service]=int(base.compose('exec','-T',service,'du','-sk',dir).stdout.split()[0])
    with a.output.open('x',encoding='utf-8') as f:
        json.dump({'workers_share_two_student_sessions':metrics,'login_sequential_wall_ms':logins,'login_errors':0,
            'docker_samples':stats,'image_logical_bytes':images,'data_volume_kib':sizes},f,indent=2)
    print('PASS bounded 2/5-worker School and Risk workload, two synthetic logins and Docker samples.',flush=True)


if __name__=='__main__':
    main()
