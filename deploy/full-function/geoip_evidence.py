"""Read sanitized GeoIP receipts/log traces; assert joins without repeating tests."""
import datetime as dt
from decimal import Decimal,ROUND_HALF_UP
import json
import geoip_lane as lane


def main():
    out=lane.OUT
    first=json.loads((out/'risk-traces-first-attempt.json').read_text())
    labels=['mandatory-new-device','real-public-country','same-policy-public','real-public-ipv6','country-missing',
        'no-record','private','loopback','loopback-v6','ula-v6','reserved-v6','declared-trusted-cidr','declared-high-cidr']
    ips=['8.8.8.8','8.8.8.8','8.8.4.4','2001:4860:4860::8888','1.1.1.1','192.0.2.44','10.2.3.4','127.0.0.1',
        '::1','fd00::1','2001:db8::1','198.51.100.22','203.0.113.3']
    assert len(first)>=15 # reached the second browser after all service assertions
    rows=[]
    for label,ip,r in zip(labels,ips,first):
        features=r['features'];n=features['network']
        assert all(Decimal(str(f['weight']))==Decimal('.25') for f in features.values())
        if r['data_status']=='COMPLETE':
            total=sum(Decimal(str(f['contribution'])) for f in features.values()).quantize(Decimal('.01'),rounding=ROUND_HALF_UP)
            assert total==Decimal(str(r['risk_score']))
        else:assert r['risk_score'] is None and r['decision']=='STEP_UP_MFA'
        rows.append({'case':label,'test_ip':ip,'evaluation_id':r['evaluation_id'],'network':n,
            'other_factors':{k:features[k]['score'] for k in ('device','temporal','authentication_history')},
            'risk_score':r['risk_score'],'decision':r['decision'],'data_status':r['data_status'],
            'mandatory_step_up_reason':r['mandatory_step_up_reason']})
    assert all(first[i]['features']['network']['source']=='GEOIP' for i in (0,1,2,3))
    assert all(first[i]['risk_score']==12.5 for i in (1,2,3))
    assert all(rows[i]['other_factors']==rows[1]['other_factors'] for i in range(1,13))
    assert first[1]['features']['network']['inputs']['asn']==15169
    assert first[1]['features']['network']['inputs']['country_code']=='US'
    assert first[4]['features']['network']['inputs']['geoip_status']=='COUNTRY_MISSING'
    assert first[5]['features']['network']['inputs']['geoip_status']=='NOT_FOUND'
    lane.save('network-evidence.json',{'status':'PASS','cases':rows,'fixed_other_factors':True,
        'service_identity':'zerotrust-risk-caller, authenticated TLS/service JWT; declared evaluation payload, not browser peer spoofing',
        'arithmetic':'B0 .25 each, HALF_UP scale2, thresholds40/75 unchanged',
        'country_lists':'empty in both effective legacy and Full-Function configurations',
        'original_failure_retained':'failure-full.json; service assertions and first browser succeeded before CORS-only second-browser failure'})
    # Join the new successful spoof test's actual browser interval to the two
    # independently emitted service/SPI traces by exact evaluation_id.
    browser=json.loads((out/'service-browser.json').read_text())
    traces=json.loads((out/'risk-traces-browser.json').read_text())
    kc=lane.full.run('docker','logs',lane.RESTORE+'-keycloak-1')
    spi=[]
    for line in (kc.stdout+kc.stderr).splitlines():
        if 'ZEROTRUST_RISK_TRACE ' in line:spi.append(json.loads(line.split('ZEROTRUST_RISK_TRACE ',1)[1]))
    joined=[]
    for b in browser['browser']:
        lo=dt.datetime.fromisoformat(b['start']);hi=dt.datetime.fromisoformat(b['end'])
        matched=[r for r in traces if lo<=dt.datetime.fromisoformat(r['at'])<=hi]
        assert len(matched)==1
        r=matched[0];n=r['features']['network'];assert n['inputs']['address_scope']=='NON_PUBLIC'
        assert n['inputs']['geoip_status']=='SKIPPED_NON_PUBLIC' and n['inputs']['country_code'] is None
        assert n['score']==50 and n['contribution']==12.5 and r['decision']=='STEP_UP_MFA'
        links=[s for s in spi if s.get('evaluation_id')==r['evaluation_id']]
        assert any(s.get('stage')=='RISK_EVALUATION' and s.get('decision')=='STEP_UP_MFA' for s in links)
        assert any(s.get('stage')=='KEYCLOAK_ENFORCEMENT' and s.get('outcome')=='STEP_UP_REQUIRED' for s in links)
        assert any(s.get('stage')=='AUTHENTICATION_EVENT' and s.get('mfa_execution')=='OTP_EXECUTION_SUCCESS' for s in links)
        joined.append({'browser':b,'risk_trace':r,'matching_SPI_traces':links})
    lane.save('browser-joined.json',{'status':'PASS_LOCAL_BOUNDARY','cases':joined,
        'public_browser_geoip':'NOT_VERIFIED: actual Docker peer is private; public-header spoof rejected',
        'network_participation':'real browser N50 contributes12.50 under unchanged nonpublic default, SPI applies step-up before OTP/code'})
    life=json.loads((out/'lifecycle.json').read_text())
    assert len(life)>=8
    for mode in ('restart','update','rollback','corrupt'):
        r=json.loads((out/('service-'+mode+'.json')).read_text());assert r['status']=='PASS' and r['V5']==661092940
    preserved=json.loads((out/'preservation.json').read_text());assert preserved['status']=='PASS'
    gates={
        'GEOIP_DATABASE':('PASS',['acquisition.json','transport-boundary.json']),
        'CLIENT_IP_INTEGRITY':('PASS',['browser-joined.json']),
        'NETWORK_FEATURE_EXTRACTION':('PASS',['network-evidence.json']),
        'NETWORK_RISK_CONTRIBUTION':('PASS',['network-evidence.json']),
        'ADAPTIVE_AUTH_GEOIP_E2E':('PARTIAL',['browser-joined.json']),
        'GEOIP_UPDATE_LIFECYCLE':('PASS',['lifecycle.json','service-restart.json','service-update.json','service-rollback.json','service-corrupt.json']),
        'GEOIP_LEGACY_PARITY':('PARTIAL',['policy-corrected.json','preservation.json'])}
    lane.save('acceptance-gates.json',{'gates':{k:{'status':v[0],'evidence':v[1]} for k,v in gates.items()},
        'overall':'PARTIAL','active_profile_geoip_enabled':False,'isolated_candidate_geoip_enabled':True,
        'newer_vendor_build_tested':False,'D17':'PENDING','G8':'INTERNET_NO_GO',
        'remaining':['Real public-peer browser GeoIP not observable in local Docker/NAT lane',
            'Owner review of network policy and Risk locking/GeoIP candidate promotion',
            'Freshness checked by operator preflight/status; no unattended monitoring/job installed',
            'Actual newer vendor-build update not claimed; verified same-build release replacement/rollback exercised']})
    print('PASS joined real MMDB/B0/browser-SPI/lifecycle evidence; overall PARTIAL, no release promotion',flush=True)


if __name__=='__main__':main()
