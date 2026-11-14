"""Execute the real role assertion without configuring services or backups."""
import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import yaml

ROLE=Path(__file__).resolve().parents[2]/'roles/postgres_backup_restore'


class LegacyCaptureTests(unittest.TestCase):
    def invoke(self,value):
        tasks=yaml.safe_load((ROLE/'tasks/assert.yml').read_text())
        task=next(t for t in tasks if t['name']=='Reject retired custom scheduled backup log capture')
        with tempfile.TemporaryDirectory() as temporary:
            playbook=Path(temporary)/'test.yml'
            playbook.write_text(yaml.safe_dump([dict(name='Check retired capture input',hosts='localhost',
                connection='local',gather_facts=False,vars=dict(postgres_backup_restore_action='schedule',
                postgres_backup_restore_schedule_state='present',postgres_backup_restore_schedule_log_config=value),
                tasks=[copy.deepcopy(task)])]))
            executable=shutil.which('ansible-playbook')
            self.assertIsNotNone(executable,'Use the pinned development EE')
            env=dict(os.environ,ANSIBLE_LOCAL_TEMP=str(Path(temporary)/'local'))
            return subprocess.run([executable,'-i','localhost,',str(playbook)],env=env,
                capture_output=True,text=True,timeout=30)

    def test_direct_worker_configuration_accepts_empty_legacy_input(self):
        result=self.invoke('')
        self.assertEqual(result.returncode,0,result.stderr)

    def test_nonempty_legacy_policy_is_rejected_before_services_are_configured(self):
        result=self.invoke('/etc/podman-component-logs/postgres.json')
        self.assertEqual(result.returncode,2)
        self.assertIn('Custom log capture is retired',result.stdout)
