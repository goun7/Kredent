# MCP Registry Kayıt Rehberi — Kredent

**Durum:** dosyalar HAZIR. **Kayıt YAPILMADI** — kullanıcı onayı bekleniyor.
Maliyet: **$0** (yalnızca ücretsiz tier'lar).

---

## 1. Smithery (öncelik)

Smithery, Arcade.dev'e katıldı (2026):
<https://arcade.dev/blog/smithery-joins-arcade>

**İki yayın yolu** (<https://smithery.ai/docs/build/publish>):

### A) Local — MCPB Bundle (bizim için uygun, stdio server)
```bash
npm install -g smithery@latest          # Node.js 20+
smithery auth login
smithery mcp publish ./kredent.mcpb -n <org>/kredent
```
- Yapılandırma hazırdır: [`smithery.yaml`](smithery.yaml)
- Manifest: [`mcp.json`](mcp.json)
- Giriş noktası: `kredent-mcp` console script (`pip install "kredent[mcp]"`).

### B) URL — Streamable HTTP + OAuth (kendi host'unuz)
```bash
# 1) Kredent'i HTTP uç noktası olarak yayınla
# 2) https://smithery.ai/new → HTTPS URL gir → yayınlama akışını tamamla
```
- Tarama başarısız olursa statik kart: `/.well-known/mcp/server-card.json`

**Yerel deneme (kayıtsız):**
```bash
smithery mcp add ./mcp/kredent_mcp.py --id kredent
smithery tool list kredent
smithery tool call kredent reputation '{"agent_id":"did:key:z6Mk..."}'
```

### Smithery'de konum (kanıt)
Glama'da `agent identity` aramasında rakipler VAR (Agent Identity MCP Server,
AIP, ZeroID, agent-identity-control-plane) — ama çoğu SaaS trust-score veya
OAuth katmanı. Kredent'in nişi: **did:key self-resolving + offline Ed25519
attestation + recomputable reputation formülü** (üçü birlikte).
Detay: Sester repo `docs/arastirma/mcp-pazari.md` §3.

---

## 2. Glama.ai

- Directory: <https://glama.ai/mcp/servers> (**93,546 server**, 2026-09-28)
- **"Add Server"** formu ile GitHub repo URL'si; README taranır.
- Kategoriler (önerilen): `Security & IAM`, `Autonomous Agents`,
  `Developer Tools`

---

## 3. mcp.so

- Submit: <https://mcp.so/submit?type=server>
- **Ücretsiz tier:** form → review. **$39 ödeme YAPILMAYACAK** (opsiyonel
  hızlandırma; ücretsiz tier'da da listelenir).

---

## 4. Punkpeye awesome-mcp-servers

- Repo: <https://github.com/punkpeye/awesome-mcp-servers>
- Kayıt = **PR açmak** (ücretsiz):
  `- [Kredent](https://github.com/goun7/Kredent) - did:key identity, offline-verifiable Ed25519 attestations, auditable reputation.`

---

## 5. Manuel stdio config (yayın öncesi)

```json
{
  "mcpServers": {
    "kredent": {
      "command": "kredent-mcp"
    }
  }
}
```

Checkout'tan çalıştırma: `command: python, args: ["mcp/kredent_mcp.py"]`

---

## 6. Kayıt Öncesi Checklist

- [x] MCP server stdio'da çalışıyor (initialize + tools/list + tools/call)
- [x] `mcp/smithery.yaml` hazır
- [x] `mcp/mcp.json` hazır
- [ ] `mcp/README.md` (kurulum + tool listesi + örnek) — README.md MCP bölümü
      mevcut; mcp/README.md eklenebilir
- [x] README.md'de MCP bölümü var
- [ ] **Kullanıcı onayı** → Smithery publish
- [ ] **Kullanıcı onayı** → Glama "Add Server"
- [ ] **Kullanıcı onayı** → mcp.so submit (ücretsiz tier)
- [ ] **Kullanıcı onayı** → Punkpeye PR
- [ ] Yayın sonrası: README'lere registry linkleri ekle

**Not:** API anahtarları bu dokümanda YOK. `create_identity` seed'ler
yalnızca `persist=false` açıkça istenirse döner ve asla ekrana yazılmaz.
