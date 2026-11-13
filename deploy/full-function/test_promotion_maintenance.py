"""Changed maintenance controller only: no Docker commands or real data writes."""
import copy
import unittest
from unittest import mock
import promotion_executor as x
import promotion_maintenance as m
import risk_promotion as r


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.rows={s:{'Id':s,'Image':r.OLD,'State':{'Running':True}} for s in x.SERVICES}
        self.events=[];self.e=mock.Mock()
        self.e.m={'project':x.LANE,'services':{s:{'id':s} for s in x.SERVICES}}
        self.e.name.side_effect=lambda s:s;self.e.current.return_value='risk'
        self.e.d.owned.side_effect=lambda n:self.rows[n]
        self.e.d.stop.side_effect=lambda n:(self.events.append(('stop',n)),self.rows[n]['State'].update(Running=False))
        self.e.d.start.side_effect=lambda n:(self.events.append(('start',n)),self.rows[n]['State'].update(Running=True))
        self.e.stage.side_effect=lambda j,s,**kw:j.update(stage=s,**kw)
        self.j={'running_before':dict.fromkeys(x.SERVICES,True)};self.a=m.Maintenance(self.e)
    def test_ingress_closed_first_and_redis_quiesced(self):
        self.a.enter(self.j,True)
        self.assertEqual(self.events[0],('stop','ingress'))
        self.assertTrue(all(not self.rows[s]['State']['Running'] for s in (*m.WRITERS,'redis')))
    def test_unverified_operation_cannot_reopen_ingress(self):
        self.a.enter(self.j)
        with self.assertRaisesRegex(r.Rejected,'VERIFICATION_REQUIRED'):self.a.resume(self.j,'risk')
        self.assertFalse(self.rows['ingress']['State']['Running'])
    def test_internal_start_never_opens_ingress(self):
        self.a.enter(self.j);self.a.start_internal(self.j,'risk')
        self.assertNotIn(('start','ingress'),self.events)
    def test_preserves_deliberately_stopped_frontend(self):
        for s in ('frontend','ingress'):
            self.rows[s]['State']['Running']=False;self.j['running_before'][s]=False
        self.a.enter(self.j);self.a.start_internal(self.j,'risk');self.a.verified(self.j);self.a.resume(self.j,'risk')
        self.assertFalse(self.rows['frontend']['State']['Running'])
        self.assertFalse(self.rows['ingress']['State']['Running'])
    def test_internal_health_failure_leaves_ingress_closed(self):
        self.a.enter(self.j)
        self.e.d.health.side_effect=r.Rejected('DECLARED_HEALTH_FAILURE')
        with self.assertRaisesRegex(r.Rejected,'HEALTH_FAILURE'):self.a.start_internal(self.j,'risk')
        self.assertFalse(self.rows['ingress']['State']['Running'])
    def test_identity_drift_stops_before_mutation(self):
        self.rows['ingress']['Id']='foreign'
        with self.assertRaisesRegex(r.Rejected,'ID_DRIFT'):self.a.enter(self.j)
        self.e.d.stop.assert_not_called()
    def test_active_project_is_not_authorized_by_adapter(self):
        self.e.m['project']=r.PROJECT
        with self.assertRaisesRegex(r.Rejected,'SCOPE_CEILING'):self.a.enter(self.j)
        self.e.d.stop.assert_not_called()
    def test_inconsistent_intent_rejected(self):
        self.j['running_before']['frontend']=False
        with self.assertRaisesRegex(r.Rejected,'STOPPED_DEPENDENCY'):m.consistent_intent(self.j['running_before'])
    def test_resume_health_failure_closes_ingress(self):
        self.a.enter(self.j);self.a.start_internal(self.j,'risk');self.a.verified(self.j)
        self.e.d.health.side_effect=r.Rejected('DECLARED_HEALTH_FAILURE')
        with self.assertRaisesRegex(r.Rejected,'HEALTH_FAILURE'):self.a.resume(self.j,'risk')
        self.assertFalse(self.rows['ingress']['State']['Running'])
    def test_final_state_drift_closes_ingress(self):
        self.a.enter(self.j);self.a.start_internal(self.j,'risk');self.a.verified(self.j)
        normal=self.e.d.start.side_effect
        def changed(name):
            normal(name)
            if name=='ingress':self.rows['risk']['State']['Running']=False
        self.e.d.start.side_effect=changed
        with self.assertRaisesRegex(r.Rejected,'STATE_NOT_RESTORED'):self.a.resume(self.j,'risk')
        self.assertFalse(self.rows['ingress']['State']['Running'])


class ResourceAndRestartTests(unittest.TestCase):
    def test_storage_floor_rejected(self):
        with mock.patch.object(x.shutil,'disk_usage',return_value=mock.Mock(free=14*1024**3)):
            with self.assertRaisesRegex(r.Rejected,'STORAGE_BELOW_15'):x.storage_guard()
    def test_storage_warning_threshold(self):
        with mock.patch.object(x.shutil,'disk_usage',return_value=mock.Mock(free=19*1024**3)):
            with self.assertWarns(RuntimeWarning):self.assertTrue(x.storage_guard()['warning_below_20_GiB'])
    def test_reuse_requires_authenticated_creation_journal(self):
        e=x.Executor(docker=mock.Mock());origin='a'*32;candidate=x.LANE+'-phase23a-risk-declared-unit'
        e.d.rows.return_value=[{'Name':'/'+candidate,'Id':'declared-id','State':{'Running':False},
            'Config':{'Labels':{'io.zerotrust.promotion.manifest':e.digest,'io.zerotrust.operation':origin}}}]
        e.journal=mock.Mock(return_value=x.MANIFEST);e.verify_new=mock.Mock();e.stage=mock.Mock()
        with mock.patch.object(x,'sealed_read',return_value={'status':'DONE','operation':'apply','new_id':'declared-id','manifest':e.digest}):
            self.assertEqual(e.create_new({'id':'b'*32}),candidate)
        e.verify_new.assert_called_once_with(candidate,origin);e.d.raw.assert_not_called()
    def test_restart_from_stopped_uses_recorded_intent(self):
        e=x.Executor(docker=mock.Mock());intent=dict.fromkeys(x.SERVICES,True);intent['frontend']=False
        j={'running_before':dict.fromkeys(x.SERVICES,False)}
        e.new_operation=mock.Mock(return_value=j);e.current=mock.Mock(return_value='risk')
        e.state=mock.Mock(return_value={'running_intent':intent});e.stage=mock.Mock();e.resume_verified=mock.Mock()
        e.save_state=mock.Mock();e.finish=mock.Mock()
        with mock.patch.object(x,'ProjectLock'):e.restart({})
        self.assertEqual(j['running_before'],intent);e.resume_verified.assert_called_once_with(j,'risk')


if __name__=='__main__':unittest.main(verbosity=2)
