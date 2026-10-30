"""Reproducible offline study. Synthetic inputs only; no HTTP, Docker or DB access.

Generate frozen-rule fixtures, validate real Java outputs with a Fraction oracle,
then describe scenario agreement, ablations and bounded local microbenchmarks.
Bulk artifacts stay under ignored target/research/controlled-v1.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from fractions import Fraction as F
import hashlib
import json
from pathlib import Path
import random
import statistics
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
SPEC = HERE / 'controlled-v1.json'
OUT = ROOT / 'risk-scoring-service/target/research/controlled-v1'
MODELS = ('B0', 'TEMPORAL_ONLY', 'HISTORY_ONLY', 'B1')
ACTIONS = ('ALLOW', 'STEP_UP_MFA', 'DENY')
POLICY_V1 = {'weights':['0.25']*4, 'medium':'40', 'high':'75', 'zone':'UTC',
             'history_days':90, 'minimum_events':5, 'maximum_events':200}


def validate_spec(spec):
    if spec.get('schema_version') != 1 or spec.get('policy') != POLICY_V1:
        raise ValueError('Version 1 requires the declared unchanged baseline policy')
    if set(spec.get('splits',{})) != {'calibration','evaluation'} or spec.get('variants_per_group') != 4:
        raise ValueError('Unexpected split/variant configuration')
    families=spec.get('families',[])
    if len(families) != 21 or len({f['id'] for f in families}) != 21:
        raise ValueError('Version 1 requires 21 unique declared families')
    if any(set(f['expected_actions'])-set(ACTIONS) for f in families):
        raise ValueError('Unknown expected protection action')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_once(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError(f'Preserve existing artifact; content differs: {path.name}')
    else:
        path.write_bytes(raw)


def counter_at(elapsed):
    """Simulation only: expiry is anchored to first INCR, not extended at 899s."""
    expiry, count = None, 0
    for event in [0, 1, 2, 3, 4, 899]:
        if event > elapsed:
            break
        if expiry is not None and event >= expiry:
            count = 0
        if count == 0:
            expiry = event + 900
        count += 1
    return 0 if expiry is not None and elapsed >= expiry else count


def make_history(now, n, days, hours, seed):
    rng = random.Random(seed)
    day_ids = set(rng.sample(range(n), days))
    hour_ids = set(rng.sample(range(n), hours))
    offset = rng.randrange(3600)
    result = []
    for i in range(n):
        date = now.date() - timedelta(days=7 * (1 + i % 11) + (0 if i in day_ids else 1 + i % 6))
        hour = (now.hour + (0 if i in hour_ids else 6)) % 24
        event = datetime.combine(date, datetime.min.time(), timezone.utc) + timedelta(hours=hour, seconds=(offset + i * 97) % 3600)
        result.append(event.isoformat().replace('+00:00', 'Z'))
    assert len(set(result)) == n
    assert all(now - timedelta(days=90) <= parse(t) < now for t in result)
    return sorted(result, reverse=True)


def parse(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def selected(row):
    now = parse(row['now'])
    return sorted((parse(t) for t in row['history'] if now-timedelta(days=90) <= parse(t) < now), reverse=True)[:200]


def counts(row):
    now, events = parse(row['now']), selected(row)
    return len(events), sum(t.weekday() == now.weekday() for t in events), sum(min(abs(t.hour-now.hour), 24-abs(t.hour-now.hour)) <= 1 for t in events)


def dataset(spec):
    validate_spec(spec)
    rows = []
    for split, split_spec in spec['splits'].items():
        for family_index, family in enumerate(spec['families']):
            name = family['id']
            for group in range(split_spec['groups_per_family']):
                seed = int.from_bytes(hashlib.sha256(f"{split_spec['seed']}:{name}:{group}".encode()).digest()[:8], 'big') & ((1 << 63)-1)
                rng = random.Random(seed)
                now = datetime(2026, 9, 21, [0, 7, 8, 23][group % 4], tzinfo=timezone.utc) + timedelta(weeks=group % 3)
                n = [5, 10, 20, 50, 199, 200][(group + family_index) % 6]
                d, h, failures, ip_failures = max(1, n//2), max(1, n//2), 0, 0
                device, network = 'TRUSTED', 'TRUSTED'
                if name in ['legitimate_unusual', 'elevated_context', 'high_context']:
                    d, h, network = 0, 0, 'ELEVATED'
                if name == 'elevated_context':
                    n, d, h, failures = 20, 1, 3, 3
                if name == 'high_context':
                    network, failures = 'HIGH', 5
                    d, h = max(0, n//20), max(0, n//10)
                    device = 'MISSING' if group % 2 else 'TRUSTED'
                if name == 'nat_shared':
                    network, ip_failures = 'DEFAULT', [9, 10, 19, 20, 21][group % 5]
                if name == 'unfamiliar_device':
                    device = ['MISSING', 'NEW', 'PENDING'][group % 3]
                if name == 'expired_trust':
                    device = 'EXPIRED'
                if name == 'priority_device':
                    device = 'SECURITY_REVOKED'
                if name == 'cold_start':
                    n = group % 5
                    d = h = n
                if name == 'history_window':
                    n, d, h = 230, 120, 120
                if name == 'latent_nonowner':
                    n, d, h = 20, 20, 20
                if name == 'threshold_neighborhood':
                    n, network, failures = (50, 'ELEVATED', 3) if group % 2 == 0 else (200, 'HIGH', 5)
                    d, h = (2, 4) if group % 2 == 0 else (0, 0)
                for variant in range(spec['variants_per_group']):
                    vn, vd, vh, vf = n, d, h, failures
                    if variant in [1, 3]:
                        vd = d-1 if d else min(n, 1)
                    if variant in [2, 3]:
                        vf += 1
                    age = 86400
                    vdevice, vnetwork = device, network
                    expected = list(family['expected_actions'])
                    if name == 'sample_size':
                        vn = [4, 5, 199, 200][variant]; vd = vh = vn
                        expected = ['STEP_UP_MFA'] if vn < 5 else ['ALLOW']
                        vf = 0
                    if name == 'device_lifecycle':
                        age = [30*86400-1, 30*86400, 30*86400+1, 86400][variant]
                        vdevice = 'SECURITY_REVOKED' if variant == 3 else 'TRUSTED'
                        vd = vh = n; vf = 0
                        expected = ['ALLOW'] if variant == 0 else ['DENY'] if variant == 3 else ['STEP_UP_MFA']
                    if name == 'network_context':
                        vnetwork = ['TRUSTED', 'DEFAULT', 'ELEVATED', 'HIGH'][variant]
                        vd = vh = n; vf = 0
                        if variant == 3: expected = ['STEP_UP_MFA']
                    elapsed = [898, 899, 900, 901][variant] if name == 'counter_ttl' else None
                    if elapsed is not None:
                        vf = counter_at(elapsed); vd = vh = n
                    history = make_history(now, vn, min(vn, vd), min(vn, vh), seed)
                    if name == 'history_window':
                        history += [(now-timedelta(days=91+i)).isoformat().replace('+00:00', 'Z') for i in range(10)]
                    row = {'schema_version': 1, 'kind': 'CONTROLLED_SYNTHETIC', 'case_id': f'{split}-{name}-{group:02d}-v{variant}',
                           'group_id': f'{split}-{name}-{group:02d}', 'split': split, 'group_seed': seed,
                           'family': name, 'variant': variant, 'actor_label': family['actor'], 'label_confidence': family['confidence'],
                           'expected_actions': expected, 'now': now.isoformat().replace('+00:00', 'Z'), 'history': history,
                           'device': vdevice, 'trusted_age_seconds': age, 'network': vnetwork,
                           'subject_failures': vf, 'ip_failures': ip_failures,
                           'failed_counter': 1+(group%2) if name == 'counter_unavailable' else 0,
                           'temporal_unavailable': name == 'temporal_unavailable' or (name == 'priority_device' and variant == 3),
                           'network_enabled': name != 'network_unavailable', 'blocked_ip': name == 'priority_ip',
                           'reset_pending': name == 'reset_pending', 'ttl_simulation_elapsed_seconds': elapsed}
                    row['selected_n'], row['day_matches'], row['hour_matches'] = counts(row)
                    assert row['subject_failures'] >= 0 and row['ip_failures'] >= 0
                    rows.append(row)
    return rows


def generate():
    spec = json.loads(SPEC.read_text())
    rows = dataset(spec)
    nonempty = defaultdict(set)
    selected_histories = defaultdict(set)
    for r in rows:
        if r['history']: nonempty[r['split']].add(digest(encoded(r['history'])))
        if selected(r): selected_histories[r['split']].add(digest(encoded([t.isoformat() for t in selected(r)])))
    assert not nonempty['calibration'] & nonempty['evaluation']
    assert not selected_histories['calibration'] & selected_histories['evaluation']
    group_seeds = {s: {r['group_seed'] for r in rows if r['split'] == s} for s in spec['splits']}
    assert not group_seeds['calibration'] & group_seeds['evaluation']
    raw = b''.join(encoded(r)+b'\n' for r in rows)
    write_once(OUT/'snapshots.jsonl', raw)
    manifest = {'study': spec['study'], 'label_spec_sha256': digest(SPEC.read_bytes()), 'snapshots_sha256': digest(raw),
                'snapshots': len(rows), 'groups': len({r['group_id'] for r in rows}),
                'by_split': dict(Counter(r['split'] for r in rows)), 'same_nonempty_history_cross_split': 0,
                'same_group_seed_cross_split': 0, 'kind': 'CONTROLLED_SYNTHETIC_NOT_REAL_ATTACK_GROUND_TRUTH',
                'empty_histories': 'Contain no observations; do not imply independent real users.',
                'labels_frozen_before_outputs': True, 'analyst_blinded_to_previous_models': False}
    write_once(OUT/'dataset-manifest.json', encoded(manifest)+b'\n')
    print(json.dumps(manifest, indent=2))


def cents(value):
    q, r = divmod(value.numerator*100, value.denominator)
    return q + (r*2 >= value.denominator)


def failure(count, medium, high, continuous):
    if not continuous: return F(100 if count >= high else 50 if count >= medium else 0)
    return F(100) if count >= high else F(50*count, medium) if count <= medium else F(50)+F(50*(count-medium), high-medium)


def oracle(row, model):
    priority = row['reset_pending'] or row['blocked_ip'] or row['device'] == 'SECURITY_REVOKED'
    n, d, h = counts(row)
    incomplete = n < 5 or row['failed_counter'] or not row['network_enabled'] or row['temporal_unavailable']
    state = 'EXPIRED' if row['device'] == 'TRUSTED' and row['trusted_age_seconds'] >= 30*86400 else row['device']
    D = F({'TRUSTED':0, 'MISSING':80, 'NEW':60, 'PENDING':50, 'EXPIRED':60, 'MFA_RESET':60, 'SECURITY_REVOKED':100}[state])
    N = F({'TRUSTED':0, 'DEFAULT':50, 'ELEVATED':50, 'HIGH':100}[row['network']])
    H = max(failure(row['subject_failures'],3,5,model in ['HISTORY_ONLY','B1']), failure(row['ip_failures'],10,20,model in ['HISTORY_ONLY','B1']))
    T = None if n < 5 else 50*(max(F(0),1-F(10*d,n))+max(F(0),1-F(5*h,n))) if model in ['TEMPORAL_ONLY','B1'] else F(50*(10*d<n)+50*(5*h<n))
    mandatory = state != 'TRUSTED' or row['network'] == 'HIGH' or row['subject_failures'] >= 5 or row['ip_failures'] >= 20
    if priority: return {'score_cents':None, 'decision':'DENY', 'data_status':'NOT_EVALUATED', 'source':'PRIORITY_RULE'}
    if incomplete: return {'score_cents':None, 'decision':'STEP_UP_MFA', 'data_status':'INCOMPLETE', 'source':'INCOMPLETE_DATA'}
    score = cents((D+N+T+H)/4)
    action = 'DENY' if score >= 7500 else 'STEP_UP_MFA' if score >= 4000 or mandatory else 'ALLOW'
    return {'score_cents':score, 'decision':action, 'data_status':'COMPLETE',
            'source':'MANDATORY_STEP_UP' if score < 4000 and mandatory else 'SCORE_THRESHOLD'}


def percentile(values, q):
    values=sorted(values); position=(len(values)-1)*q
    low=int(position); high=min(low+1,len(values)-1)
    return values[low]+(values[high]-values[low])*(position-low)


def distribution(values):
    if not values: return {'n':0}
    return {'n':len(values),'mean':round(statistics.mean(values),6),'min':min(values),
            'median':statistics.median(values),'p95':round(percentile(values,.95),6),
            'max':max(values),'population_sd':round(statistics.pstdev(values),6)}


def monotonicity_violation(a, b, delta, coordinate):
    if coordinate == 'combined_day_counter': return None  # Opposing changes have no single direction.
    if coordinate == 'subject_counter': return delta < 0
    if coordinate == 'day_count': return delta*(b['day_matches']-a['day_matches']) > 0
    raise ValueError('Unknown perturbation coordinate')


def analyze():
    manifest=json.loads((OUT/'dataset-manifest.json').read_text())
    assert digest(SPEC.read_bytes())==manifest['label_spec_sha256']
    assert digest((OUT/'snapshots.jsonl').read_bytes())==manifest['snapshots_sha256']
    rows=[json.loads(line) for line in (OUT/'snapshots.jsonl').read_text().splitlines()]
    actual=[json.loads(line,parse_float=Decimal) for line in (OUT/'java-results.jsonl').read_text().splitlines()]
    by={(r['case_id'],r['variant']):r for r in actual}
    assert len(by)==len(rows)*4==4032
    for row in rows:
        for model in MODELS:
            expected=oracle(row,model); result=by[row['case_id'],model]
            observed=None if result['risk_score'] is None else int(result['risk_score']*100)
            assert observed==expected['score_cents'], (row['case_id'],model,expected,result['risk_score'])
            assert all(result[k]==expected[k] for k in ['decision','data_status','source'])
            trust=None if result['trust_score'] is None else int(result['trust_score']*100)
            assert trust==(None if observed is None else 10000-observed)
    boundaries=json.loads((OUT/'rounding-boundaries.json').read_text(),parse_float=Decimal)
    for row in boundaries:
        expected=cents(F(row['input_each_feature']))
        assert int(row['score']*100)==expected
        assert row['decision']==('DENY' if expected>=7500 else 'STEP_UP_MFA' if expected>=4000 else 'ALLOW')
    summary={'schema_version':2,'kind':'CONTROLLED_SYNTHETIC_NOT_ATTACK_GROUND_TRUTH','dataset':manifest,
             'fraction_oracle_matches':len(actual),'rounding_boundary_matches':len(boundaries),
             'policy_invariant_or_deterministic_output_violations':0,'splits':{}}
    for split in ['calibration','evaluation']:
        subset=[r for r in rows if r['split']==split]
        primary=[r for r in subset if r['label_confidence'] not in ['LOW_UNOBSERVABLE','DIAGNOSTIC_ONLY']]
        pairs=Counter((by[r['case_id'],'B0']['decision'],by[r['case_id'],'B1']['decision']) for r in subset)
        per={}
        for model in MODELS:
            records=[by[r['case_id'],model] for r in subset]
            scores=[float(r['risk_score']) for r in records if r['risk_score'] is not None]
            agreements=[by[r['case_id'],model]['decision'] in r['expected_actions'] for r in primary]
            per[model]={'actions':dict(Counter(r['decision'] for r in records)),
                        'sources':dict(Counter(r['source'] for r in records)),
                        'score':distribution(scores),'trust':distribution([100-x for x in scores]),
                        'scenario_agreement':{'agree':sum(agreements),'n':len(primary)},'by_confidence':{},
                        'by_family':{}}
            for confidence in ['CONTRACT','CONDITIONAL','LOW_UNOBSERVABLE']:
                cases=[r for r in subset if r['label_confidence']==confidence]
                per[model]['by_confidence'][confidence]={'agree':sum(by[r['case_id'],model]['decision'] in r['expected_actions'] for r in cases),'n':len(cases)}
            for family in sorted({r['family'] for r in subset}):
                cases=[r for r in subset if r['family']==family]
                per[model]['by_family'][family]={'n':len(cases),'actions':dict(Counter(by[r['case_id'],model]['decision'] for r in cases)),
                    'agree':sum(by[r['case_id'],model]['decision'] in r['expected_actions'] for r in cases) if cases[0]['expected_actions'] else None}
            legitimate=[r for r in subset if r['actor_label']=='LEGITIMATE_BY_SCENARIO']
            per[model]['synthetic_legitimate_action_mix']={'n':len(legitimate),'actions':dict(Counter(by[r['case_id'],model]['decision'] for r in legitimate))}
            per[model]['near_threshold']={str(t):sum(abs(float(r['risk_score'])-t)<=1 for r in records if r['risk_score'] is not None) for t in [40,75]}
            per[model]['by_history_size']={str(n):{'n':len(cases:=[r for r in subset if r['selected_n']==n]),
                    'actions':dict(Counter(by[r['case_id'],model]['decision'] for r in cases))} for n in sorted({r['selected_n'] for r in subset})}
        delta=[float(by[r['case_id'],'B1']['risk_score']-by[r['case_id'],'B0']['risk_score']) for r in subset if by[r['case_id'],'B0']['risk_score'] is not None]
        summary['splits'][split]={'n':len(subset),'groups':len({r['group_id'] for r in subset}),
            'primary_labelled_cases':len(primary),'primary_labelled_groups':len({r['group_id'] for r in primary}),
            'matrix':{a:{b:pairs[a,b] for b in ACTIONS} for a in ACTIONS},
            'changed':sum(v for (a,b),v in pairs.items() if a!=b),'models':per,'paired_score_delta':distribution(delta)}
    groups=defaultdict(dict)
    for r in rows: groups[r['group_id']][r['variant']]=r
    sensitivity={}
    for name,index in [('day_count',1),('subject_counter',2),('combined_day_counter',3)]:
        per={m:{'edges':0,'score_changes':0,'decision_flips':0,'flips_guard_unchanged':0,'monotonicity_violations':None if index==3 else 0,'absolute_delta':[]} for m in MODELS}
        for variants in groups.values():
            a,b=variants[0],variants[index]
            fixed=['selected_n','hour_matches','device','trusted_age_seconds','network','ip_failures','failed_counter','temporal_unavailable','network_enabled','blocked_ip','reset_pending']
            if index==1: fixed.append('subject_failures')
            if index==2: fixed.append('day_matches')
            if any(a[k]!=b[k] for k in fixed):continue
            if index in [2,3] and b['subject_failures']!=a['subject_failures']+1:continue
            if index in [1,3] and abs(b['day_matches']-a['day_matches'])!=1:continue
            for m in MODELS:
                x,y=by[a['case_id'],m],by[b['case_id'],m]
                if x['risk_score'] is None or y['risk_score'] is None:continue
                item=per[m];d=float(y['risk_score']-x['risk_score']);flip=x['decision']!=y['decision']
                item['edges']+=1;item['score_changes']+=d!=0;item['decision_flips']+=flip
                item['flips_guard_unchanged']+=flip and x['mandatory']==y['mandatory'];item['absolute_delta'].append(abs(d))
                violation=monotonicity_violation(a,b,d,name)
                if violation is not None:item['monotonicity_violations']+=violation
        for m,item in per.items(): item['absolute_delta']=distribution(item['absolute_delta'])
        sensitivity[name]=per
    assert all(v['monotonicity_violations']==0 for name,group in sensitivity.items() if name!='combined_day_counter' for v in group.values())
    summary['controlled_coordinate_sensitivity']=sensitivity
    summary['TTL_simulation']={'elapsed_seconds':[898,899,900,901],'counts':[counter_at(t) for t in [898,899,900,901]],
        'scope':'Fixed first-increment window simulation; does not execute Redis Lua or prove distributed timing.',
        'example':{m:[{'score':str(by[groups['evaluation-counter_ttl-00'][v]['case_id'],m]['risk_score']),
                      'decision':by[groups['evaluation-counter_ttl-00'][v]['case_id'],m]['decision']} for v in range(4)] for m in ['B0','B1']}}
    old=ROOT/'risk-scoring-service/target/research/b1-evaluation-20261029'
    legacy=json.loads((old/'metrics.json').read_text())
    assert digest((old/'deny-to-mfa-42.csv').read_bytes())=='3f1fec7de2f001adacd8005c4fce336f19b97532f28f02ad9217ceef95ebbf46'
    summary['legacy_reused']={k:legacy[k] for k in ['dataset_sha256','cases','matrix','attribution','normalization_ablations','invariants_on_complete_grid']}
    summary['legacy_reused']['new_Java_replay_executed']=False
    benchmark=[]
    for fork in [1,2,3]:benchmark.append(json.loads((OUT/f'benchmark-fork-{fork}.json').read_text()))
    assert len({(b['java_version'],b['vm'],b['os'],b['arch'],b['warmup_per_model_per_scope']) for b in benchmark})==1
    assert all(b['case_ids']==benchmark[0]['case_ids'] for b in benchmark)
    performance={}
    for scope in sorted({s['scope'] for b in benchmark for s in b['samples']}):
        performance[scope]={}
        for m in ['B0','B1']:
            samples=[s for b in benchmark for s in b['samples'] if s['model']==m and s['scope']==scope]
            ns=[t for s in samples for t in s['per_operation_ns']]
            performance[scope][m]={'per_operation_us':distribution([t/1000 for t in ns]),
                'batch_mean_us':distribution([s['batch_elapsed_ns']/len(s['per_operation_ns'])/1000 for s in samples]),
                'fork_medians_us':[statistics.median(t/1000 for s in b['samples'] if s['model']==m and s['scope']==scope for t in s['per_operation_ns']) for b in benchmark]}
    summary['performance']={'method':'3 sequential fresh JVM forks; 6000 warmup/model/scope; 24 batches of 24 operations/model/scope/fork; alternating randomized model order.',
        'scope_limits':'Same source, synthetic in-memory read boundaries; includes RiskEvaluation allocation/UUID/clock. Pipeline adds trace serialization but no log I/O. No HTTP/DB/Redis/Browser latency. Non-JMH exploratory Windows host; no real-time or tail-latency guarantee.',
        'java':{k:benchmark[0][k] for k in ['java_version','vm','os','arch','processors','max_heap_bytes']},'scopes':performance}
    # Derived analysis is separate from immutable raw fixtures/results and historical evidence.
    write_once(OUT/'study-summary-v2.json',json.dumps(summary,indent=2,ensure_ascii=False).encode()+b'\n')
    print(json.dumps({'oracle_matches':len(actual),'held_out':summary['splits']['evaluation'],'sensitivity':sensitivity,'performance':summary['performance']},ensure_ascii=False,indent=2))
    return summary


def plots():
    try:
        import matplotlib
    except ModuleNotFoundError:
        # Optional plotting dependencies are artifacts, not a virtualenv/shared Python change.
        local=OUT.parent/'plotting-deps'
        if local.is_dir(): sys.path.insert(0,str(local))
        import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    s=json.loads((OUT/'study-summary-v2.json').read_text());held=s['splits']['evaluation']
    destination=ROOT/'docs/research/trust-score-b1/figures';destination.mkdir(parents=True,exist_ok=True)
    plt.rcParams.update({'svg.hashsalt':'controlled-b1-v1','svg.fonttype':'none','font.size':10})
    fig,axes=plt.subplots(1,2,figsize=(10,4),layout='constrained')
    matrix=np.array([[held['matrix'][a][b] for b in ACTIONS] for a in ACTIONS])
    axes[0].imshow(matrix,cmap='Blues');axes[0].set(xticks=range(3),yticks=range(3),xticklabels=['ALLOW','MFA','DENY'],yticklabels=['ALLOW','MFA','DENY'],xlabel='B1 action',ylabel='B0 action',title=f'Controlled synthetic evaluation (n={held["n"]})')
    for i in range(3):
        for j in range(3):axes[0].text(j,i,str(matrix[i,j]),ha='center',va='center',color='white' if matrix[i,j]>matrix.max()/2 else 'black')
    x=np.arange(4)
    for i,action in enumerate(ACTIONS):axes[1].bar(x+(i-1)*.23,[held['models'][m]['actions'].get(action,0) for m in MODELS],width=.23,label=action.replace('STEP_UP_MFA','MFA'))
    axes[1].set(xticks=x,xticklabels=['B0','T only','H only','B1'],ylabel='Snapshots',title='Real-component ablations, same inputs')
    axes[1].legend(loc='upper center',bbox_to_anchor=(.5,-.12),ncol=3)
    fig.savefig(destination/'controlled-decisions.svg',metadata={'Date':None});fig.savefig(OUT/'decision-preview.png',dpi=140);plt.close(fig)
    forks=[json.loads((OUT/f'benchmark-fork-{i}.json').read_text()) for i in [1,2,3]]
    scopes=list(s['performance']['scopes']);fig,axes=plt.subplots(1,2,figsize=(10,4),layout='constrained')
    for ax,scope,title in zip(axes,scopes,['In-memory pipeline + trace JSON','Temporal / history / scorer']):
        data=[[t/1000 for b in forks for r in b['samples'] if r['scope']==scope and r['model']==m for t in r['per_operation_ns']] for m in ['B0','B1']]
        ax.boxplot(data,tick_labels=['B0','B1'],showfliers=False);ax.set(yscale='log',ylabel='Microseconds per operation',title=title)
        ax.text(.5,-.16,'3 forks; local synthetic computation; fliers hidden',transform=ax.transAxes,ha='center',fontsize=8)
    fig.savefig(destination/'controlled-latency.svg',metadata={'Date':None});fig.savefig(OUT/'latency-preview.png',dpi=140);plt.close(fig)
    # Matplotlib splits SVG path attributes across lines with trailing spaces.
    # Newlines remain XML whitespace separators; normalize text without changing geometry.
    for name in ['controlled-decisions.svg','controlled-latency.svg']:
        path=destination/name
        path.write_text('\n'.join(line.rstrip() for line in path.read_text(encoding='utf-8').splitlines())+'\n',encoding='utf-8')


class ToolTests(unittest.TestCase):
    def test_labels_and_splits_are_deterministic(self):
        s=json.loads(SPEC.read_text()); a=dataset(s); b=dataset(s)
        self.assertEqual(encoded(a),encoded(b)); self.assertEqual(len(a),1008)
        self.assertEqual(len({r['case_id'] for r in a}),len(a))
        histories={split:{digest(encoded(r['history'])) for r in a if r['split']==split and r['history']} for split in s['splits']}
        self.assertFalse(histories['calibration'] & histories['evaluation'])

    def test_window_and_counter_simulation_boundaries(self):
        self.assertEqual([counter_at(t) for t in [898,899,900,901]],[5,6,0,0])
        self.assertEqual(cents(F(7999,200)),4000)
        self.assertEqual(cents(F(14999,200)),7500)

    def test_oracle_priority_and_missingness_are_not_numeric_scores(self):
        row=dataset(json.loads(SPEC.read_text()))[0]
        for model in MODELS:
            p=oracle(dict(row,blocked_ip=True,temporal_unavailable=True),model)
            self.assertEqual((p['score_cents'],p['decision'],p['source']),(None,'DENY','PRIORITY_RULE'))
            m=oracle(dict(row,failed_counter=1),model)
            self.assertEqual((m['score_cents'],m['decision']),(None,'STEP_UP_MFA'))

    def test_policy_drift_is_rejected_before_generation(self):
        s=json.loads(SPEC.read_text());s['policy']['high']='70'
        with self.assertRaises(ValueError):dataset(s)

    def test_selected_histories_do_not_cross_splits(self):
        rows=dataset(json.loads(SPEC.read_text()));histories=defaultdict(set)
        for r in rows:
            if selected(r):histories[r['split']].add(digest(encoded([t.isoformat() for t in selected(r)])))
        self.assertFalse(histories['calibration'] & histories['evaluation'])

    def test_combined_perturbation_does_not_claim_monotonicity(self):
        self.assertIsNone(monotonicity_violation({'day_matches':0},{'day_matches':1},1,'combined_day_counter'))
        self.assertFalse(monotonicity_violation({}, {},1,'subject_counter'))
        self.assertTrue(monotonicity_violation({'day_matches':0},{'day_matches':1},1,'day_count'))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--generate',action='store_true');p.add_argument('--self-test',action='store_true')
    p.add_argument('--analyze',action='store_true');p.add_argument('--plots',action='store_true')
    args=p.parse_args()
    if args.self_test:
        if not unittest.main(argv=['controlled_study'],exit=False).result.wasSuccessful():
            raise SystemExit(1)
    if args.generate: generate()
    if args.analyze: analyze()
    if args.plots: plots()
