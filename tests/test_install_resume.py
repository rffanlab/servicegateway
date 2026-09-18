import subprocess
from pathlib import Path


MODULE = Path(__file__).parents[1] / "deploy/bootstrap.py"


def test_installer_absent_current_is_not_mistaken_for_old_release(tmp_path):
    script=(MODULE.parent/'install.sh').read_text()
    part=script[script.index('old=""'):script.index('if [[ ! -f "$CFG/app.env" ]]')]
    result=subprocess.run(['/bin/bash','-c',part+'\nprintf "%s" "$old"'],env={'BASE':str(tmp_path)},capture_output=True,text=True)
    assert result.returncode==0 and result.stdout==''
    (tmp_path/'current').symlink_to(tmp_path/'missing-release')
    result=subprocess.run(['/bin/bash','-c',part],env={'BASE':str(tmp_path)},capture_output=True,text=True)
    assert result.returncode!=0
