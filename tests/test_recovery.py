from pathlib import Path
from servicegateway import recovery
from servicegateway import agent


def test_interrupted_candidate_is_replaced_with_last_good_config(tmp_path,monkeypatch):
    monkeypatch.setattr(recovery,'JOURNAL',tmp_path/'pending.json')
    monkeypatch.setattr(recovery,'BACKUP',tmp_path/'rollback.conf')
    monkeypatch.setattr(agent,'CONFIG',tmp_path/'nginx.conf')
    monkeypatch.setattr(agent,'root_file',lambda p:Path(p))
    agent.CONFIG.write_text('old-config')
    recovery.begin('old-config','a'*64,'old-generation')
    agent.CONFIG.write_text('uncommitted-config')
    state=recovery.restore_disk()
    assert state=={'digest':'a'*64,'generation':'old-generation'}
    assert agent.CONFIG.read_text()=='old-config'
    assert recovery.JOURNAL.exists()
    recovery.finish()
    assert recovery.pending() is None


def test_existing_pending_prevents_overwriting_rollback_evidence(tmp_path,monkeypatch):
    import pytest
    monkeypatch.setattr(recovery,'JOURNAL',tmp_path/'pending.json')
    monkeypatch.setattr(recovery,'BACKUP',tmp_path/'rollback.conf')
    recovery.begin('original','a'*64,'generation')
    with pytest.raises(ValueError):recovery.begin('new','b'*64,'other')
    assert recovery.BACKUP.read_text()=='original'
