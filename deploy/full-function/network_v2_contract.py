"""Pure deterministic candidate configuration shared by binding, preflight and create.
No Docker mutations, credentials output, signing or runtime policy decisions.
"""
import copy
import json
import shlex
import risk_promotion as r

JSON_ENV='SPRING_APPLICATION_JSON'
DYNAMIC_LABELS={'io.zerotrust.scope','io.zerotrust.role','io.zerotrust.shadow.manifest','io.zerotrust.operation'}


def canonical_json(value):
    try:return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
    except (ValueError,TypeError):raise r.Rejected('CANDIDATE_JSON_NOT_CANONICALIZABLE') from None


def strict_json(text):
    def pairs(items):
        result={}
        for key,value in items:
            r.need(key not in result,'CANDIDATE_DUPLICATE_JSON_KEY');result[key]=value
        return result
    def constant(value):raise ValueError()
    try:
        value=json.loads(text,object_pairs_hook=pairs,parse_constant=constant)
        r.need(type(value) is dict,'CANDIDATE_JSON_MUST_BE_OBJECT')
        canonical_json(value);return value
    except r.Rejected:raise
    except (ValueError,TypeError,RecursionError):raise r.Rejected('CANDIDATE_INVALID_JSON') from None


def normalized_environment(items):
    result={}
    for item in items:
        r.need(type(item) is str and '=' in item and not any(c in item for c in ('\0','\r','\n')),'CANDIDATE_INVALID_ENV')
        key,value=item.split('=',1)
        r.need(key and key not in result,'CANDIDATE_DUPLICATE_OR_EMPTY_ENV_KEY')
        result[key]=canonical_json(strict_json(value)) if key==JSON_ENV else value
    return [key+'='+result[key] for key in sorted(result)]


def environment_hash(items):return r.sha(canonical_json(normalized_environment(items)).encode())


def health_contract(cfg):
    value=cfg.get('Healthcheck')
    if not value:return None
    return {'Test':value['Test'],**{key:value.get(key,0) for key in ('Interval','Timeout','Retries','StartPeriod','StartInterval')}}


def public_contract(row):
    value=r.container_witness(row);value.pop('id')
    value['environment_sha256']=environment_hash(row['Config'].get('Env') or [])
    for name in ('entrypoint','cmd'):value[name+'_sha256']=r.sha(canonical_json(value.pop(name)).encode())
    value['healthcheck']=health_contract(row['Config'])
    value['working_dir']=row['Config'].get('WorkingDir') or None
    value['stop_signal']=row['Config'].get('StopSignal') or None
    value['image_labels_sha256']=r.sha(canonical_json({k:v for k,v in (row['Config'].get('Labels') or {}).items() if k not in DYNAMIC_LABELS}).encode())
    value['namespaces']={key:row['HostConfig'].get(key) for key in ('PidMode','UTSMode','IpcMode','CgroupnsMode')}
    return value


def expected_spec(role,baseline,image,m,project,core):
    """Project actual Docker defaults plus the exact options used by create_args."""
    r.need(role in ('risk','keycloak') and image['Id']==m['release']['new_images'][role]
           and image['Os']=='linux' and image['Architecture']=='amd64','CANDIDATE_IMAGE_PLATFORM_OR_PIN')
    cfg=baseline['Config'];icfg=image['Config'];host=baseline['HostConfig']
    env=[v for v in cfg['Env'] if not (role=='risk' and v.startswith(JSON_ENV+'='))]
    if role=='risk':env+=[JSON_ENV+'='+canonical_json(m['release']['risk_override'])]
    env=normalized_environment(env)
    expected_entry=cfg.get('Entrypoint');expected_cmd=m['release']['keycloak_cmd'] if role=='keycloak' else cfg.get('Cmd')
    actual_cmd=expected_cmd if expected_cmd else icfg.get('Cmd')
    r.need(icfg.get('Entrypoint')==expected_entry and actual_cmd==expected_cmd,'CANDIDATE_IMAGE_ENTRYPOINT_OR_DEFAULT_CMD_DRIFT')
    # Docker retains image Env keys not overridden by --env-file. Unexpected
    # image defaults must therefore be rejected before creating any container.
    merged=dict(v.split('=',1) for v in normalized_environment(icfg.get('Env') or []))
    merged.update(dict(v.split('=',1) for v in env))
    r.need(environment_hash([k+'='+v for k,v in merged.items()])==environment_hash(env),'CANDIDATE_UNEXPECTED_IMAGE_ENV')
    mounts=copy.deepcopy(baseline['Mounts'])
    destinations={'/run/demo','/geoip'} if role=='risk' else {'/run/secrets'}
    r.need({v['Destination'] for v in mounts}==destinations and all(not v['RW'] for v in mounts),'CANDIDATE_BASE_MOUNTS')
    r.need(not (set(icfg.get('Volumes') or {})-destinations),'CANDIDATE_UNEXPECTED_IMAGE_VOLUME')
    config=next(v for v in mounts if v['Destination']==('/run/demo' if role=='risk' else '/run/secrets'))
    r.need(config.get('Name')==project+'_'+role+'-config','CANDIDATE_CONFIG_VOLUME')
    memory=640*1024**2 if role=='risk' else host['Memory']
    projected={'Id':'OFFLINE','Image':image['Id'],'Mounts':mounts,'NetworkSettings':{'Networks':{core:{}}},
        'Config':{**icfg,'Env':env,'User':'10001:10001' if role=='risk' else '65532:65532','Cmd':expected_cmd},
        'HostConfig':{**host,'PortBindings':{},'ReadonlyRootfs':True if role=='risk' else host['ReadonlyRootfs'],
            'Privileged':False,'CapAdd':None,'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],
            'RestartPolicy':{'Name':'unless-stopped','MaximumRetryCount':0},'Memory':memory,
            'Tmpfs':{'/tmp':'mode=1777'} if role=='risk' else None,'Binds':None,'Devices':[], 'NetworkMode':core}}
    if role=='keycloak':
        health=cfg.get('Healthcheck',{}).get('Test',[])
        r.need(health and health[0]=='CMD','CANDIDATE_KEYCLOAK_HEALTH_CONTRACT')
        projected['Config']['Healthcheck']={**(icfg.get('Healthcheck') or {}),'Test':['CMD-SHELL',shlex.join(health[1:])],
                                           'Interval':5000000000,'Timeout':5000000000,'Retries':40}
    # Docker merges immutable image labels with four explicit ownership labels.
    projected['Config']['Labels']=dict(icfg.get('Labels') or {})
    return {'role':role,'image':image['Id'],'env':env,'cmd':expected_cmd,'projected':projected,'contract':public_contract(projected)}


def create_args(spec,name,operation,digest,project,core,envfile,geo_host):
    role=spec['role'];p=spec['projected'];h=p['HostConfig'];cfg=p['Config']
    args=['docker','create','--name',name,'--label','io.zerotrust.scope='+project,'--label','io.zerotrust.role='+role,
          '--label','io.zerotrust.shadow.manifest='+digest,'--label','io.zerotrust.operation='+operation,
          '--network',core,'--network-alias',role,'--user',cfg['User'],'--cap-drop','ALL','--security-opt','no-new-privileges',
          '--restart','unless-stopped','--memory',str(h['Memory']),'--env-file',str(envfile),
          '--mount','type=volume,source='+project+'_'+role+'-config,target='+('/run/demo' if role=='risk' else '/run/secrets')+',readonly']
    if h['ReadonlyRootfs']:args+=['--read-only']
    if role=='risk':args+=['--tmpfs','/tmp:mode=1777','--mount','type=bind,source='+str(geo_host)+',target=/geoip,readonly']
    else:
        args+=['--health-cmd',cfg['Healthcheck']['Test'][1],'--health-interval','5s','--health-timeout','5s','--health-retries','40']
    args+=[spec['image']]
    if spec['cmd']:args+=spec['cmd']
    return args


def verify_contract(row,expected):
    actual=public_contract(row)
    changed=sorted(key for key in set(actual)|set(expected) if actual.get(key)!=expected.get(key))
    r.need(not changed,'CANDIDATE_FULL_CONFIGURATION_DRIFT:'+','.join(changed))
