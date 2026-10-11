"""kredent.store izin-yardimci dal-kesen testleri (LEED).

Kural-1: mevcut dosyalara DOKUNULMADI, SADECE bu yeni dosya eklendi.
Kural-4: saf in-memory (tmp_path + duck-typed fake Path + pathlib.Path.chmod
sinif-seviyesi monkeypatch — network/subprocess/gercek-anahtar deposu YOK).
Kural-5: TEST beklentileri uretime GORE yazildi; once `python3 -c` ile PROBE edildi.

Hedef: _restrict_permissions (module-level, col_offset==0, try/except OSError).
Senaryo: POSIX basarili chmod 0600 + except OSError sessiz yutma.

ORTAM-OGRENDI-0: Python 3.14'de PosixPath ORNEKLERININ __dict__'i YOKTUR
(hasattr(PosixPath('x'), '__dict__') == False), bu yuzden monkeypatch.setattr(
path, 'chmod', ...) AttributeError verir. chmod-basarisizlik senaryolari
duck-typed _FakePath nesneleri VEYA pathlib.Path.chmod SINIF-seviyesi
monkeypatch ile yazildi.
"""
import os
import pathlib
import stat
import sys

import pytest

sys.path.insert(0, ".")
from kredent import store  # noqa: E402
from kredent.store import _restrict_permissions  # noqa: E402


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class _FakePath:
    """Duck-typed Path: _restrict_permissions yalnizca path.chmod(0o600) cagirir.

    ORNEK-seviyesi monkeypatch'in mumkun olmadigi Python 3.14 icin chmod
    basarisizliklarini enjekte eder; uretim koduna HIC DOKUNULMAZ.
    """

    def __init__(self, chmod_error=None):
        self.calls = []
        self._chmod_error = chmod_error

    def chmod(self, mode):
        self.calls.append(mode)
        if self._chmod_error is not None:
            raise self._chmod_error


# == basarili chmod dalı ==============================================================================

@pytest.mark.parametrize("start_mode", [0o000, 0o644, 0o666, 0o755, 0o777, 0o600, 0o400])
def test_restrict_permissions_sets_0600(tmp_path, start_mode):
    """ORTAM-ANATOMI: path.chmod(0o600) — hangi moddan baslarsa basilsin 0600 olur."""
    p = tmp_path / "seed.json"
    p.write_text("{}")
    os.chmod(p, start_mode)
    _restrict_permissions(p)
    assert _mode(p) == 0o600


def test_restrict_permissions_idempotent(tmp_path):
    """ORTAM: zaten 0600 iken tekrar cagirmak ayni kalir."""
    p = tmp_path / "seed.json"
    p.write_text("{}")
    _restrict_permissions(p)
    _restrict_permissions(p)
    assert _mode(p) == 0o600


def test_restrict_permissions_returns_none(tmp_path):
    """ORTAM-ANATOMI: donus degeri None (best-effort, sonuc bildirmez)."""
    p = tmp_path / "seed.json"
    p.write_text("{}")
    assert _restrict_permissions(p) is None


def test_restrict_permissions_preserves_content(tmp_path):
    """ORTAM: chmod dosya ICERIGINI degistirmez."""
    p = tmp_path / "seed.json"
    p.write_text('{"seed_hex": "ab"}')
    _restrict_permissions(p)
    assert p.read_text() == '{"seed_hex": "ab"}'


def test_restrict_permissions_applies_to_directory(tmp_path):
    """ORTAM: hedef bir dizin olabilir (chmod 0600 dizine uygulanir)."""
    d = tmp_path / "subdir"
    d.mkdir()
    os.chmod(d, 0o755)
    try:
        _restrict_permissions(d)
        assert _mode(d) == 0o600
    finally:
        os.chmod(d, 0o755)  # temizlik icin geri ac


def test_restrict_permissions_calls_chmod_with_exactly_0600():
    """ORTAM-ANATOMI: cagri tam olarak `path.chmod(0o600)` argümani ile yapilir."""
    fake = _FakePath()
    _restrict_permissions(fake)
    assert fake.calls == [0o600]


# == except OSError dalı (sessiz yutma) ================================================================

def test_restrict_permissions_swallows_missing_path(tmp_path):
    """ORTAM-ANATOMI: olmayan dosya -> OSError -> except PASIF (warn-free degradation).

    _restrict_permissions olmayan bir Path'e chmod yapmaya calisir; OSError
    yakalanir ve yutulur. Bu 'best-effort' tasarimin kalbidir.
    """
    missing = tmp_path / "ghost.json"
    assert not missing.exists()
    _restrict_permissions(missing)  # hata firlatMAMALI
    assert not missing.exists()


@pytest.mark.parametrize("err", [
    OSError(1, "Operation not permitted"),
    OSError(13, "Permission denied"),
    OSError(30, "Read-only file system"),
    OSError(28, "No space left on device"),
])
def test_restrict_permissions_swallows_oserrors(err):
    """ORTAM-ANATOMI: HER türlü OSError yutulur (except OSError genis yakalama)."""
    fake = _FakePath(chmod_error=err)
    _restrict_permissions(fake)  # hata firlatmaz
    assert fake.calls == [0o600]


@pytest.mark.parametrize("exc_type", [
    FileNotFoundError, PermissionError, IsADirectoryError, BlockingIOError, TimeoutError,
])
def test_restrict_permissions_catches_oserror_subclasses(exc_type):
    """ORTAM-ANATOMI: OSError alt-siniflari da except OSError tarafindan yakalanir.

    ORTAM-OGRENDI-1: FileNotFoundError/PermissionError/IsADirectoryError/
    BlockingIOError/TimeoutError'in hepsi OSError'dan miras alir, bu yuzden
    hepsi sessizce yutulur.
    """
    assert issubclass(exc_type, OSError)
    fake = _FakePath(chmod_error=exc_type("subclass error"))
    _restrict_permissions(fake)
    assert fake.calls == [0o600]


@pytest.mark.parametrize("exc", [
    RuntimeError("unexpected"),
    ValueError("bad mode"),
    TypeError("wrong type"),
    KeyError("missing key"),
    Exception("generic"),
])
def test_restrict_permissions_does_not_swallow_non_oserrors(exc):
    """ORTAM-ANATOMI: except YALNIZCA OSError yakalar — digerleri DISARI sizar.

    Bu, except-tümünü-yakalama anti-kalıbı OLMADIGININ kanıtıdır.
    """
    fake = _FakePath(chmod_error=exc)
    with pytest.raises(type(exc)):
        _restrict_permissions(fake)
    assert fake.calls == [0o600]  # cagri yapildi ama hata yutulmadi


def test_restrict_permissions_chmod_called_before_error():
    """ORTAM-ANATOMI: chmod cagrisi yapILIR, sonra hata yutulur (cagri atlanmaz)."""
    fake = _FakePath(chmod_error=OSError(1, "boom"))
    _restrict_permissions(fake)
    assert len(fake.calls) == 1


# == store entegrasyonu: _restrict_permissions store_identity tarafindan cagrilir ========================

def test_store_identity_calls_restrict_permissions(tmp_path, monkeypatch):
    """ORTAM-ANATOMI: store_identity kayittan sonra _restrict_permissions cagirir."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    from kredent.crypto import generate_seed

    calls = []
    orig = store._restrict_permissions
    monkeypatch.setattr(
        store, "_restrict_permissions",
        lambda path: calls.append(path) or orig(path),
    )
    stored = store.store_identity("perm-agent", generate_seed())
    assert len(calls) == 1
    assert calls[0].exists()
    assert _mode(calls[0]) == 0o600
    assert stored.name == "perm-agent"


def test_stored_file_has_0600_mode(tmp_path, monkeypatch):
    """ORTAM: diske yazilan kimlik dosyasi gercekten 0600 izniyle durur."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    from kredent.crypto import generate_seed

    store.store_identity("mode-agent", generate_seed())
    path = store.identities_dir() / "mode-agent.json"
    assert _mode(path) == 0o600


def test_store_identity_survives_chmod_failure(tmp_path, monkeypatch):
    """ORTAM-OGRENDI-2: chmod basarisiz olsa bile store_identity BASARILI olur.

    _restrict_permissions OSError'u yuttugu icin store_identity asla chmod
    hatasi gormez. Bu, pathlib.Path.chmod SINIF-seviyesi monkeypatch ile
    gercek entegrasyon uzerinden dogrulanir (ornek-seviyesi 3.14'de read-only).
    """
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    from kredent.crypto import generate_seed

    def boom(self, mode):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(pathlib.Path, "chmod", boom)
    stored = store.store_identity("ro-agent", generate_seed())
    assert stored.name == "ro-agent"
    path = store.identities_dir() / "ro-agent.json"
    assert path.exists()
    assert path.read_text()  # icerik yazildi


def test_chmod_failure_leaves_file_unrestricted(tmp_path, monkeypatch):
    """ORTAM-OGRENDI-3: chmod basarısız olursa dosya 0644 (varsayilan) olarak kalir.

    Yutulan hata iznin ZORLANMADIGINI gosterir — dosya yine de yazilir, sadece
    0600'a dustugu GARANTI DEGILDIR. Bu 'best-effort' sozlesmesidir.
    """
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    from kredent.crypto import generate_seed

    def boom(self, mode):
        raise OSError(30, "Read-only")

    monkeypatch.setattr(pathlib.Path, "chmod", boom)
    store.store_identity("loose-agent", generate_seed())
    path = store.identities_dir() / "loose-agent.json"
    assert _mode(path) == 0o644  # chmod yapilmadi, umask varsayilani


def test_load_identity_still_works_after_chmod_failure(tmp_path, monkeypatch):
    """ORTAM: 0600'a dusturulemeyen bir kimlik yine de yuklenebilir."""
    monkeypatch.setenv("KREDENT_HOME", str(tmp_path / "kh"))
    from kredent.crypto import generate_seed

    seed = generate_seed()
    monkeypatch.setattr(pathlib.Path, "chmod", lambda self, mode: (_ for _ in ()).throw(
        OSError(13, "denied")
    ))
    store.store_identity("loadable", seed)
    loaded = store.load_identity("loadable")
    assert loaded.seed == seed
