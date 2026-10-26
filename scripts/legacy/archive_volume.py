"""For approved isolated backup/restore only; invoked in a networkless helper container."""
import inspect,pathlib,sys,tarfile
mode,source,target=sys.argv[1:]
if mode=='pack':
    assert source=='/source' and target.startswith('/backup/')
    with tarfile.open(target,'w:gz') as archive:archive.add(source,arcname='data',recursive=True)
elif mode in ['unpack','unpack-keycloak']:
    assert source.startswith('/backup/') and target=='/target'
    root=pathlib.Path(target).resolve()
    assert root.is_dir() and not any(root.iterdir()),'RESTORE_TARGET_NOT_EMPTY'
    with tarfile.open(source,'r:*') as archive:
        members=archive.getmembers()
        if mode=='unpack-keycloak':
            members=[m for m in members if m.name.lstrip('./')=='opt/keycloak/data' or m.name.lstrip('./').startswith('opt/keycloak/data/')]
            assert members,'KEYCLOAK_DATA_MISSING'
        # MySQL's stale runtime socket link is recreated by mysqld. Preserve it
        # in the immutable backup, but never materialize its absolute link on restore.
        members=[m for m in members if not (m.name=='data/mysql.sock' and m.issym() and m.linkname=='/var/run/mysqld/mysqld.sock')]
        for member in members:
            prefix='data' if mode=='unpack' else 'opt/keycloak/data'
            member.name=member.name.lstrip('./')
            assert member.name==prefix or member.name.startswith(prefix+'/')
            assert not member.issym() and not member.islnk()
            assert member.isdir() or member.isfile()
            relative=pathlib.PurePosixPath(member.name).relative_to(prefix)
            assert root.joinpath(*relative.parts).resolve().is_relative_to(root)
            member.name=str(relative) if str(relative)!='.' else '.'
        kwargs={'filter':'fully_trusted'} if 'filter' in inspect.signature(archive.extractall).parameters else {}
        archive.extractall(root,members=members,**kwargs)
else:raise ValueError('Unsupported operation')
