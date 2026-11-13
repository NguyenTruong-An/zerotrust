"""Fail-closed maintenance sequence; authority remains in the scoped executor.

No independent mutating CLI or active-project approval is supplied by this file.
Ingress stays stopped while direct TLS/CRL and scoped service JWT checks run.
"""

WRITERS=('ingress','gateway','frontend','backend','risk','keycloak')


def consistent_intent(running):
    from risk_promotion import need
    need(not running['ingress'] or all(running.values()),'INGRESS_RUNNING_WITH_STOPPED_DEPENDENCY_REJECTED')


def review_active():
    """Read-only exact active binding. This never constructs mutation authority."""
    import risk_promotion as r
    manifest=r.json_bytes(r.DEFAULT_MANIFEST.read_bytes())
    validation=r.inspect_manifest(manifest)
    runtime=manifest['baseline_runtime']
    r.need(runtime['ingress']['ports']=={'39443/tcp':[{'HostIp':'127.0.0.1','HostPort':'39443'}]},'ACTIVE_INGRESS_PORT_DRIFT')
    r.need(all(not v['ports'] for s,v in runtime.items() if s not in ('ingress','crl')),'ACTIVE_PRIVATE_PORT_EXPOSED')
    return {'kind':'PROPOSED_ACTIVE_MAINTENANCE_BINDING_NOT_AUTHORIZATION','project':r.PROJECT,
        'proposal_sha256':r.sha_file(r.DEFAULT_MANIFEST),'approval_status':'PENDING','execution_enabled':False,
        'identities':{s:{'id':v['id'],'image':v['image'],'contract_sha256':r.sha(__import__('json').dumps(v,sort_keys=True,separators=(',',':')).encode())} for s,v in runtime.items()},
        'ingress_ports':runtime['ingress']['ports'],'crl_ports':runtime['crl']['ports'],
        'maintenance':{'writers':list(WRITERS),'ingress':'stop first; no replacement or port publication',
            'verify':'internal service TLS/CRL/JWT/V5/GeoIP while ingress remains stopped',
            'resume':'exact running_before; ingress last after verified durable selection',
            'backup':'stop Redis; single consistent three-schema dump; encrypted configs/runtime/dataset references',
            'lock':'exclusive project lock shared by backup/apply/rollback/restart/stop/recover',
            'failure':'retain ingress closed and authenticated journal; new scoped recover request'},
        'validation':validation,'requires_owner_authority':True,'active_checkpoint':'NOT_CREATED'}


class Maintenance:
    def __init__(self,executor):self.e=executor
    def checked(self,service,risk=None):
        e=self.e
        # A maintenance adapter is not an alternative authorization path.
        if callable(getattr(type(e),'scope_check',None)):e.scope_check()
        else:
            from promotion_executor import scoped
            scoped(e.m['project'])
        name=(risk or e.current()) if service=='risk' else e.name(service)
        row=e.d.owned(name)
        if service=='risk' and name!=e.name('risk'):e.verify_new(name)
        else:
            from risk_promotion import need
            need(row['Id']==e.m['services'][service]['id'],'MAINTENANCE_CONTAINER_ID_DRIFT')
        return name,row
    def stop(self,service,risk=None):
        name,_=self.checked(service,risk);self.e.d.stop(name)
        from risk_promotion import need
        need(not self.e.d.owned(name)['State']['Running'],'MAINTENANCE_STOP_NOT_CONFIRMED')
    def enter(self,j,include_redis=False):
        e=self.e;e.stage(j,'QUIESCING',maintenance_verified=False)
        for service in WRITERS:self.stop(service)
        if include_redis:self.stop('redis')
        e.stage(j,'QUIESCED')
    def start_internal(self,j,risk):
        from risk_promotion import need,NEW
        e=self.e
        need(not self.checked('ingress')[1]['State']['Running'],'INGRESS_MUST_REMAIN_CLOSED')
        # Manifest iteration order is not a dependency order.
        from promotion_executor import SERVICES
        for service in SERVICES:
            if service!='ingress' and j['running_before'].get(service):
                name,row=self.checked(service,risk);e.d.start(name)
                e.d.health(name,service=='risk' and row['Image']==NEW)
    def verified(self,j):
        from risk_promotion import need
        need(not self.checked('ingress')[1]['State']['Running'],'INGRESS_OPEN_BEFORE_VERIFICATION')
        self.e.stage(j,'MAINTENANCE_VERIFIED',maintenance_verified=True)
    def resume(self,j,risk):
        from risk_promotion import need
        e=self.e
        need(j.get('maintenance_verified') is True,'MAINTENANCE_VERIFICATION_REQUIRED')
        # Deliberately stopped services must remain stopped. Never resume all.
        from promotion_executor import STOP_ORDER
        try:
            for service in STOP_ORDER:
                if not j['running_before'].get(service):self.stop(service,risk)
            if j['running_before'].get('ingress'):
                name,_=self.checked('ingress');e.d.start(name);e.d.health(name)
            actual={s:self.checked(s,risk)[1]['State']['Running'] for s in j['running_before']}
            need(actual==j['running_before'],'PRE_MAINTENANCE_RUNNING_STATE_NOT_RESTORED')
        except Exception:
            self.stop('ingress');e.stage(j,'RESUME_FAILED_INGRESS_CLOSED');raise
        e.stage(j,'TRAFFIC_RESUMED')
