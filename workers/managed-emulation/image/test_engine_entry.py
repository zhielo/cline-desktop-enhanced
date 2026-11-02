"""Entry policy unit tests. Real privilege dropping is required in guest boots."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import engine_entry as entry


class EntryTests(unittest.TestCase):
    def test_initial_identity_and_extra_arguments_refuse_before_effects(self):
        for uid,gid,args in [((1,1,1),(0,0,0),['entry']),((0,0,1),(0,0,0),['entry']),((0,0,0),(1,1,1),['entry']),((0,0,0),(0,0,0),['entry','anything'])]:
            with self.subTest(uid=uid,gid=gid,args=args), patch.object(entry.os,'getresuid',return_value=uid),patch.object(entry.os,'getresgid',return_value=gid),patch.object(entry.sys,'argv',args),patch.object(entry,'no_new_privileges') as nnp,patch.object(entry.os,'execve') as execute:
                with self.assertRaises(ValueError):entry.main()
                nnp.assert_not_called();execute.assert_not_called()

    def test_no_new_privileges_set_and_readback_are_required(self):
        for codes in [(0,1),(-1,1),(0,0),(0,-1)]:
            libc=MagicMock();libc.prctl.side_effect=list(codes)
            with self.subTest(codes=codes),patch.object(entry.ctypes,'CDLL',return_value=libc):
                if codes == (0,1):entry.no_new_privileges()
                else:
                    with self.assertRaises(ValueError):entry.no_new_privileges()

    def test_saved_ids_groups_and_irreversible_flag_are_checked(self):
        uid=(65534,)*3
        for observed,groups,flag in [(uid,[],1),((65534,65534,0),[],1),(uid,[0],1),(uid,[],0)]:
            libc=MagicMock();libc.prctl.return_value=flag
            with self.subTest(uid=observed,groups=groups,flag=flag),patch.object(entry.os,'getresuid',return_value=observed),patch.object(entry.os,'getresgid',return_value=uid),patch.object(entry.os,'getgroups',return_value=groups),patch.object(entry.ctypes,'CDLL',return_value=libc),patch.object(entry,'private_marker_unreadable'),patch.object(entry,'no_capabilities'):
                if (observed,groups,flag)==(uid,[],1):self.assertEqual(entry.verify_identity(),entry.IDENTITY)
                else:
                    with self.assertRaises(ValueError):entry.verify_identity()

    def test_drop_order_fixed_exec_and_environment_have_no_caller_overrides(self):
        order=[]
        with patch.object(entry.sys,'argv',['entry']),patch.object(entry.os,'getresuid',return_value=(0,0,0)),patch.object(entry.os,'getresgid',return_value=(0,0,0)),patch.object(entry,'no_new_privileges',side_effect=lambda:order.append('nnp')),patch.object(entry.resource,'setrlimit',side_effect=lambda *a:order.append('core')),patch.object(entry,'provision_private_marker',side_effect=lambda:order.append('private')),patch.object(entry.os,'setgroups',side_effect=lambda *a:order.append(('groups',a))),patch.object(entry.os,'setresgid',side_effect=lambda *a:order.append(('gid',a))),patch.object(entry.os,'setresuid',side_effect=lambda *a:order.append(('uid',a))),patch.object(entry,'verify_identity',side_effect=lambda:order.append('verify')),patch.object(entry.os,'chdir',side_effect=lambda *a:order.append('cwd')),patch.object(entry.os,'execve',side_effect=RuntimeError('owned exec intercepted')) as execute,patch.dict(entry.os.environ,{'CLINE_WORKER_KEY':'not forwarded','PYTHONPATH':'not forwarded'}):
            with self.assertRaisesRegex(RuntimeError,'owned exec intercepted'):entry.main()
            self.assertEqual(order,['nnp','core','private',('groups',([],)),('gid',(65534,)*3),('uid',(65534,)*3),'verify','cwd'])
            program,args,env=execute.call_args.args
            self.assertEqual(program,entry.PYTHON)
            self.assertEqual(args,[entry.PYTHON,'-B','-I',entry.SELFTEST])
            self.assertNotIn('CLINE_WORKER_KEY',env);self.assertNotIn('PYTHONPATH',env)

    def test_capability_observation_requires_all_four_empty_sets(self):
        clean = b'Name:\towned\n'+b''.join(key+b':\t'+b'0'*16+b'\n' for key in [b'CapInh',b'CapPrm',b'CapEff',b'CapAmb'])
        for raw in [clean,clean.replace(b'CapPrm',b'Missing'),clean+clean,clean.replace(b'0'*16,b'0'*15+b'1',1),b'x'*16385]:
            with self.subTest(raw=raw[:30]),patch('builtins.open',mock_open(read_data=raw)):
                if raw==clean:entry.no_capabilities()
                else:
                    with self.assertRaises(ValueError):entry.no_capabilities()

    def test_private_file_absence_or_readability_is_not_permission_denial(self):
        with patch.object(entry.os,'open',side_effect=PermissionError):entry.private_marker_unreadable()
        with patch.object(entry.os,'open',side_effect=FileNotFoundError),self.assertRaises(FileNotFoundError):entry.private_marker_unreadable()
        with patch.object(entry.os,'open',return_value=123),patch.object(entry.os,'close') as close:
            with self.assertRaises(ValueError):entry.private_marker_unreadable()
            close.assert_called_once_with(123)

    def test_failed_drop_never_imports_or_executes_an_engine(self):
        with patch.object(entry.sys,'argv',['entry']),patch.object(entry.os,'getresuid',return_value=(0,0,0)),patch.object(entry.os,'getresgid',return_value=(0,0,0)),patch.object(entry,'no_new_privileges'),patch.object(entry.resource,'setrlimit'),patch.object(entry,'provision_private_marker'),patch.object(entry.os,'setgroups',side_effect=PermissionError),patch.object(entry.os,'execve') as execute:
            with self.assertRaises(PermissionError):entry.main()
            execute.assert_not_called()


if __name__ == '__main__':unittest.main()
