"""Run scoped Phase 2 checks only on the owned full-function synthetic project."""
import argparse
import json
import operate as full


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('inventory','inventory-resume','repair','test','boundaries','session-boundaries','remove-maintenance'))
    action=p.parse_args().action
    full.configure()
    out=full.OUT/'phase2';out.mkdir(exist_ok=True)
    result=full.run('docker','run','--rm','--name',full.PROJECT+'-phase2-check',
        '--label','io.zerotrust.scope='+full.PROJECT,'--network',full.PROJECT+'_core',
        '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1g','--shm-size','256m',
        '--mount',f'type=bind,source={full.STATE},target=/private,readonly',
        '--mount',f'type=bind,source={full.HERE},target=/tests,readonly',
        '--mount',f'type=bind,source={out},target=/results',
        'zt-full-function/browser:20261111-1','/tests/phase2_security.py',action,timeout=1200,check=False)
    safe='\n'.join(x for x in result.stdout.splitlines() if x.startswith(('PASS ','FAIL ')))+'\n'
    (out/(action+'.log')).write_text(safe,encoding='utf-8');print(safe,end='',flush=True)
    full.check(result.returncode==0,'Phase 2 targeted check failed; see sanitized receipt')


if __name__=='__main__':main()
