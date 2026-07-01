# Prompt : Open Go Dig - Interface web de requetes DNS

## Contexte

Je veux creer un projet Go appele **OpenGoDig** : une interface web pour effectuer des requetes DNS (similaire a la commande `dig`), avec une API JSON. Le projet doit **respecter exactement** l'architecture, les patterns et le design visuel d'un projet de reference (OpenGoRDAP) decrit ci-dessous.

---

## 1. Architecture du projet

### Arborescence cible

```
open-go-dig/
├── main.go                          # Point d'entree, serveur HTTP, routing, middleware
├── go.mod
├── go.sum
├── Makefile                         # Build debug/release multi-plateforme
├── README.md
├── COPYING                          # Licence WTFPL
├── internal/
│   ├── config/
│   │   └── config.go                # Struct de configuration (YAML + env vars)
│   ├── handler/
│   │   ├── handler.go               # App state, sanitization, lookup logic, template helpers
│   │   ├── index.go                 # GET / → page d'accueil
│   │   ├── lookup.go                # GET /lookup?query=... → resultat HTML
│   │   ├── api.go                   # GET /api/lookup?query=... → resultat JSON
│   │   ├── about.go                 # GET /about → page a propos
│   │   └── status.go                # GET /api/status → statut des resolvers (JSON)
│   ├── dns/
│   │   └── dns.go                   # Client DNS : resolution multi-types (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA, DNSKEY, DS, TLSA)
│   ├── model/
│   │   └── model.go                 # Modeles de donnees (DNSResult, RecordInfo, APIResponse)
│   ├── query/
│   │   └── query.go                 # Detection du type de requete (domaine, IP pour reverse DNS)
│   ├── middleware/
│   │   ├── ratelimit.go             # Rate limiting par IP (token bucket)
│   │   ├── cors.go                  # CORS + security headers
│   │   ├── ip.go                    # Extraction IP client (trusted proxies)
│   │   └── link.go                  # HTTP Link header (preload hints)
│   └── i18n/
│       ├── i18n.go                  # Systeme de detection de langue + traduction
│       ├── lang_en.go               # Anglais (defaut)
│       └── lang_fr.go               # Francais (+ autres langues a ajouter)
├── templates/
│   ├── index.html                   # Page de recherche
│   ├── result.html                  # Page de resultats
│   └── about.html                   # Page a propos
├── static/
│   ├── css/main.css                 # Design system custom (dark theme)
│   ├── js/
│   │   ├── index.js                 # Exemples cliquables
│   │   └── result.js                # Toggle raw data
│   ├── fonts/                       # Syne + Space Mono (WOFF2)
│   └── img/                         # Favicon, icones, manifest
└── docs/examples/
    ├── open-go-dig.service          # Unite systemd
    └── open-go-dig.nginx.conf       # Reverse proxy nginx
```

### Regles strictes

- **Go 1.25+**, `net/http` standard uniquement (pas de framework : ni gin, ni echo, ni chi)
- **`http.NewServeMux`** pour le routing avec la syntaxe `"GET /path"` de Go 1.22+
- **`embed.FS`** pour embarquer templates et fichiers statiques dans le binaire
- Seule dependance externe autorisee : `github.com/ilyakaznacheev/cleanenv` (config YAML/env)
- Pour le DNS : utiliser `github.com/miekg/dns` (la reference Go pour les requetes DNS)
- Zero framework CSS/JS : tout est custom

---

## 2. Configuration (`internal/config/config.go`)

Reproduire exactement ce pattern :

```go
package config

type Config struct {
    Server struct {
        Host           string   `yaml:"host" env:"OGD_HOST"`
        Port           int      `yaml:"port" env:"OGD_PORT" env-default:"8080"`
        RateLimit      int      `yaml:"rate_limit" env:"OGD_RATE_LIMIT" env-default:"20"`
        TrustedProxies []string `yaml:"trusted_proxies" env:"OGD_TRUSTED_PROXIES"`
    } `yaml:"server"`

    DNS struct {
        Resolvers []string `yaml:"resolvers" env:"OGD_RESOLVERS"`
        // Resolvers DNS par defaut si non configure: ["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"]
        Timeout   int `yaml:"timeout" env:"OGD_DNS_TIMEOUT" env-default:"5"`
        // Timeout en secondes par requete DNS
    } `yaml:"dns"`

    Cors struct {
        Origin string `yaml:"origin" env:"OGD_CORS_ORIGIN"`
    } `yaml:"cors"`

    LogLevel string `yaml:"log_level" env:"OGD_LOG_LEVEL" env-default:"info"`
}

func (c *Config) IsDebug() bool {
    return c.LogLevel == "debug"
}
```

Prefixe des variables d'environnement : **`OGD_`** (Open Go Dig).

---

## 3. Point d'entree (`main.go`)

Reproduire exactement ce pattern :

```go
package main

import (
    "context"
    "embed"
    "errors"
    "flag"
    "fmt"
    "io/fs"
    "log"
    "net/http"
    "os"
    "os/signal"
    "strconv"
    "syscall"
    "time"

    "github.com/ilyakaznacheev/cleanenv"

    "open-go-dig/internal/config"
    "open-go-dig/internal/handler"
    "open-go-dig/internal/middleware"
)

var (
    version = "develop"
    appName = "OpenGoDig"
)

//go:embed static
var staticFiles embed.FS

//go:embed templates
var templateFiles embed.FS

// ... ProcessArgs identique au projet de reference ...

func main() {
    var cfg config.Config
    args := ProcessArgs(&cfg)

    // Lecture config fichier YAML OU variables d'env
    // ...

    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Initialiser le client DNS avec les resolvers configures
    dnsCl := dns.NewClient(cfg.DNS.Resolvers, cfg.DNS.Timeout)
    dnsCl.Debug = cfg.IsDebug()

    // Sous-systeme de templates (embed.FS)
    tmplFS, _ := fs.Sub(templateFiles, "templates")

    a := &handler.App{
        DNSClient:  dnsCl,
        TemplateFS: tmplFS,
        Debug:      cfg.IsDebug(),
    }
    a.InitTemplates()

    limiter := middleware.NewRateLimiter(ctx, cfg.Server.RateLimit)

    mux := http.NewServeMux()
    mux.HandleFunc("GET /{$}", a.IndexHandler)
    mux.HandleFunc("GET /about", a.AboutHandler)
    mux.HandleFunc("GET /lookup", a.LookupHandler)
    mux.HandleFunc("GET /api/lookup", a.ApiHandler)
    mux.HandleFunc("GET /api/status", a.StatusHandler)

    // Fichiers statiques embarques
    staticSub, _ := fs.Sub(staticFiles, "static")
    mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

    // Chaine de middleware : Cors → RateLimit → Link → Mux
    middleware.SetTrustedProxies(cfg.Server.TrustedProxies)
    srv := &http.Server{
        Addr: host + ":" + port,
        Handler: middleware.Cors(cfg.Cors.Origin)(
            middleware.RateLimit(limiter)(
                middleware.Link()(mux),
            ),
        ),
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    // Graceful shutdown avec signal + contexte 15s
    // ... (identique au projet de reference)
}
```

---

## 4. Middleware (`internal/middleware/`)

Reprendre **exactement** les 4 fichiers middleware du projet de reference. Le type `Middleware` est :

```go
type Middleware func(http.Handler) http.Handler
```

### 4.1 `ratelimit.go`
- Token bucket par IP client, reinitialise chaque minute
- `maxVisitors = 10000` avec cleanup agressif en cas de saturation
- Les requetes `/static/*` **bypass** le rate limiting
- Goroutine de cleanup toutes les 5 minutes, liee au `context.Context`
- Reponse 429 en JSON avec message i18n

### 4.2 `cors.go`
- Security headers : `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`
- CSP : `default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'`
- CORS conditionnel (seulement si `origin` configure)
- Short-circuit OPTIONS

### 4.3 `ip.go`
- Variable de package `trustedProxies []*net.IPNet`
- `SetTrustedProxies([]string)` : accepte IPs brutes ou CIDR
- `ExtractIP(r)` : X-Forwarded-For (1er IP) → X-Real-IP → RemoteAddr

### 4.4 `link.go`
- Header HTTP `Link` pour preload des CSS et fonts critiques

---

## 5. Handlers (`internal/handler/`)

### 5.1 `handler.go` - State applicatif et logique centrale

```go
type App struct {
    DNSClient  *dns.Client
    indexTmpl  *template.Template
    resultTmpl *template.Template
    aboutTmpl  *template.Template
    TemplateFS fs.FS
    Debug      bool
}
```

**Pattern de lookup :**
1. Sanitiser l'input (trim, lowercase, supprimer protocole/www/slash)
2. Detecter le type de requete (domaine ou IP pour reverse DNS)
3. Si le domaine contient un type de record explicite (ex: `MX:google.com`), l'extraire
4. Appeler `dns.Client.Lookup(ctx, domain, recordTypes)` avec les types selectionnes
5. Retourner `*model.DNSResult`

**Template FuncMap** (clonable par langue, identique au pattern du projet de reference) :
- `T` : fonction de traduction i18n
- `rawHTML` : bypass escaping pour les traductions contenant du markup controle
- `lang` : retourne le code langue courant
- `recordTypeClass` : retourne une classe CSS par type de record (A → vert, MX → bleu, etc.)
- `isReverseDNS` : detecte une requete PTR
- `formatTTL` : formate un TTL en duree lisible (ex: 3600 → "1h")

**Template rendering** : `renderLocalized` identique au projet de reference (clone + FuncMap par langue, buffer, Vary: Accept-Language).

### 5.2 Handlers individuels

- **`index.go`** : `IndexHandler` → render `index.html` (pas de data)
- **`about.go`** : `AboutHandler` → render `about.html` (pas de data)
- **`lookup.go`** : `LookupHandler` → sanitize query param, lookup DNS, render `result.html` avec DNSResult. Code HTTP 200 si OK, 502 si erreur.
- **`api.go`** : `ApiHandler` → meme logique mais retourne JSON (`DNSResult.ToAPIResponse()`). 400 si query vide.
- **`status.go`** : `StatusHandler` → retourne en JSON l'etat des resolvers (lesquels sont configures, latence du dernier check, etc.)

---

## 6. Client DNS (`internal/dns/dns.go`)

Utiliser `github.com/miekg/dns` pour effectuer les requetes DNS.

### Types de records a supporter

| Type | Description |
|------|-------------|
| A | Adresse IPv4 |
| AAAA | Adresse IPv6 |
| MX | Serveurs mail |
| NS | Serveurs de noms |
| TXT | Enregistrements texte (SPF, DKIM, etc.) |
| CNAME | Alias |
| SOA | Start of Authority |
| PTR | Reverse DNS (pour les IPs) |
| SRV | Service records |
| CAA | Certification Authority Authorization |
| DNSKEY | Cles DNSSEC |
| DS | Delegation Signer (DNSSEC) |
| TLSA | DANE/TLSA |

### Comportement

```go
type Client struct {
    Resolvers []string // ["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"]
    Timeout   time.Duration
    Debug     bool
}

func NewClient(resolvers []string, timeoutSec int) *Client

// Lookup effectue les requetes DNS pour les types demandes.
// Si recordTypes est vide, interroger les types courants : A, AAAA, MX, NS, TXT, CNAME, SOA, CAA.
// Pour un reverse DNS (IP en entree), faire un PTR.
func (c *Client) Lookup(ctx context.Context, name string, recordTypes []uint16) (*model.DNSResult, error)
```

**Logique :**
1. Pour chaque type de record demande, envoyer une requete DNS UDP (fallback TCP si tronque)
2. Essayer le premier resolver ; si timeout, essayer le suivant (round-robin failover)
3. Collecter toutes les reponses dans un `DNSResult`
4. Extraire le RCODE, les flags (AA, RD, RA, AD, CD), le temps de requete
5. Pour le reverse DNS : convertir l'IP en nom PTR (`4.3.2.1.in-addr.arpa.` pour IPv4, nibble format pour IPv6)

---

## 7. Modeles (`internal/model/model.go`)

```go
package model

type QueryType string

const (
    QueryForward QueryType = "forward"
    QueryReverse QueryType = "reverse"
)

// DNSResult contient toutes les donnees d'une resolution DNS.
type DNSResult struct {
    Query       string        // Domaine ou IP interroge
    QueryType   QueryType
    Server      string        // Resolver utilise
    Records     []RecordGroup // Records groupes par type
    Flags       DNSFlags      // Flags de la reponse
    Rcode       string        // NOERROR, NXDOMAIN, SERVFAIL, etc.
    QueryTime   time.Duration // Temps de resolution
    Error       string
    Warnings    []string
    RawResponse string        // Reponse brute DNS (format dig-like)
}

type RecordGroup struct {
    Type    string       // "A", "AAAA", "MX", etc.
    Records []RecordInfo
}

type RecordInfo struct {
    Name     string // Nom du record
    TTL      uint32 // Time to live
    Class    string // IN, CH, etc.
    Type     string // A, AAAA, MX, etc.
    Value    string // Valeur (IP, hostname, texte, etc.)
    Priority uint16 // Pour MX et SRV uniquement
}

type DNSFlags struct {
    Authoritative      bool // AA
    RecursionDesired   bool // RD
    RecursionAvailable bool // RA
    AuthenticData      bool // AD (DNSSEC)
    CheckingDisabled   bool // CD
    Truncated          bool // TC
}

// APIResponse est la representation JSON exposee par l'API.
type APIResponse struct {
    Query     string        `json:"query"`
    QueryType string        `json:"queryType"`
    Server    string        `json:"server"`
    Rcode     string        `json:"rcode"`
    Flags     DNSFlags      `json:"flags"`
    QueryTime string        `json:"queryTime"`
    Records   []RecordGroup `json:"records,omitzero"`
    Warnings  []string      `json:"warnings,omitzero"`
    Error     string        `json:"error,omitzero"`
}

func (d *DNSResult) ToAPIResponse() APIResponse { /* ... */ }
```

---

## 8. Detection de requete (`internal/query/query.go`)

```go
type Type int

const (
    TypeDomain Type = iota
    TypeIPv4        // → reverse DNS (PTR)
    TypeIPv6        // → reverse DNS (PTR)
)

// Detect determine si l'input est un domaine ou une IP (pour reverse DNS).
func Detect(input string) Type
```

En complement, supporter la syntaxe `TYPE:domaine` pour specifier le type de record :
- `MX:google.com` → requete MX pour google.com
- `AAAA:cloudflare.com` → requete AAAA pour cloudflare.com
- `google.com` (sans prefixe) → tous les types courants

---

## 9. Internationalisation (`internal/i18n/`)

Reprendre **exactement** le systeme du projet de reference :

```go
type Lang string
const (
    En Lang = "en"
    Fr Lang = "fr"
    // ... autres langues
)

// Detect parse Accept-Language et retourne la meilleure correspondance.
func Detect(acceptLang string) Lang

// T retourne la traduction pour une cle dans une langue. Fallback: langue → anglais → cle.
func T(lang Lang, key string) string

// For retourne une fonction de traduction liee a une langue (pour template FuncMap).
func For(lang Lang) func(string) string
```

Chaque fichier `lang_xx.go` contient une `var xx = Translations{...}` avec les cles.

### Cles de traduction a creer (au minimum en/fr)

```
index.subtitle, index.label, index.placeholder, index.submit, index.examples
index.resolution, index.step1, index.step2, index.step3
index.feat_types, index.feat_dnssec, index.feat_resolvers
result.back, result.search_placeholder, result.error_title
result.query_info, result.records, result.flags, result.no_records
result.raw_response, result.view_json, result.resolver_status
result.rcode_*, result.flag_*, result.record_type_*
about.title, about.subtitle, about.back, about.license_*, about.credits_*
error.internal, error.empty_query, error.missing_query, error.rate_limit
error.dns_failed, error.invalid_input
```

---

## 10. Templates HTML

### 10.1 `index.html` - Page d'accueil

Structure identique au projet de reference :
- `<body class="page-index">` + `<div class="grid"></div>` (grille de fond)
- Logo : tagline "// DNS Intelligence", titre `<h1>OpenGoDig</h1>`, sous-titre i18n
- Badges de protocole : `DNS` (vert), `DNSSEC` (bleu)
- Formulaire de recherche dans un `.card` avec :
  - Label i18n
  - Input avec placeholder i18n
  - Select (ou chips) pour choisir le type de record : ALL, A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA
  - Bouton submit
  - Exemples cliquables : `google.com`, `1.1.1.1`, `cloudflare.com`, `MX:proton.me`
- Section "Comment ca marche" (`.how`) avec les etapes de resolution DNS
- Features grid (3 colonnes) : "Multi-resolvers", "13 Record Types", "DNSSEC Support"
- Footer : liens API status + about

### 10.2 `result.html` - Page de resultats

Structure :
- Header sticky (`.hdr`) avec lien retour, domaine + type d'enregistrement, mini-formulaire de recherche
- Si erreur : bloc `.err` avec icone, titre et detail
- Sinon :
  - **Hero** (`.hero.rh`) : nom de domaine, resolver utilise, RCODE (badge colore), flags DNS (badges), temps de requete
  - **Grid de resultats** (`.igrid`) : une card par groupe de record type :
    - Header de card avec icone + nom du type (ex: "A Records", "MX Records")
    - Tableau/liste de records avec colonnes : Name, TTL (formate), Class, Value, Priority (si applicable)
  - **DNSSEC info** : card avec les flags AD/CD et les records DNSKEY/DS si presents
  - **Section "Raw Response"** : toggle repliant affichant la reponse brute format dig
  - Lien API JSON

### 10.3 `about.html` - Page a propos

Identique au projet de reference : logo, section licence (WTFPL), section credits.

---

## 11. Design CSS (`static/css/main.css`)

Reprendre **exactement** le meme design system :

### Variables CSS

```css
:root {
  --bg:#0a0a0f;
  --surface:#12121a;
  --s2:#15151f;
  --surface2:#15151f;
  --border:#1e1e2e;
  --accent:#00ff9d;      /* Vert neon - couleur principale */
  --a2:#ff3366;          /* Rose - erreurs */
  --a3:#5b6aff;          /* Bleu - secondaire */
  --accent3:#5b6aff;
  --a4:#ffb830;          /* Orange - warnings */
  --text:#e8e8f0;
  --muted:#6b6b8a;
}
```

### Typographie
- **Syne** (400, 600, 800) : titres, boutons, texte display
- **Space Mono** (400, 700) : labels, code, monospace, badges

### Elements de design a reproduire exactement
- Grille de fond fixe (`.grid`) avec lignes de 40px et opacite 0.4
- Gradient radial sur `body::before` (vert en haut, bleu en bas)
- Cards avec bordure gradient en haut (`.card::before`)
- Input avec bordure glow verte au focus
- Bouton principal vert avec hover translate + box-shadow
- Chips d'exemples avec bordure subtile
- Badges de statut colores (`.badge`, `.status-ok`, `.status-lock`, etc.)
- Timeline verticale pour les events
- Section repliable "raw data"
- Responsive : breakpoint 600px
- Header sticky avec backdrop blur

### Specifique au projet DNS

Ajouter des classes pour les types de records :
```css
.rtype-a    { color: var(--accent); }          /* A → vert */
.rtype-aaaa { color: var(--accent); }          /* AAAA → vert */
.rtype-mx   { color: var(--a3); }              /* MX → bleu */
.rtype-ns   { color: var(--a3); }              /* NS → bleu */
.rtype-txt  { color: var(--a4); }              /* TXT → orange */
.rtype-cname{ color: var(--muted); }           /* CNAME → gris */
.rtype-soa  { color: var(--a4); }              /* SOA → orange */
.rtype-ptr  { color: var(--accent); }          /* PTR → vert */
.rtype-caa  { color: var(--a2); }              /* CAA → rose */
.rtype-srv  { color: var(--a3); }              /* SRV → bleu */
```

Badges pour les RCODE :
```css
.rcode-noerror  { /* vert, comme status-ok */ }
.rcode-nxdomain { /* rose, comme status-hold */ }
.rcode-servfail { /* rose, comme status-hold */ }
.rcode-refused  { /* orange, comme status-pending */ }
```

---

## 12. JavaScript minimal

### `static/js/index.js`
```js
function q(d){document.getElementById('query').value=d;document.querySelector('form').submit()}
```

### `static/js/result.js`
```js
function tog(){
  document.getElementById('rb').classList.toggle('open');
  document.getElementById('rd').classList.toggle('v');
  document.getElementById('ra').classList.toggle('r');
}
```

---

## 13. Makefile

```makefile
mkfile_path := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
build_path  := $(mkfile_path)build/
app_name    := open-go-dig
version     := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "develop")
ldflags     := -s -w -X 'main.version=$(version)'

.DEFAULT_GOAL := help
.PHONY: help debug release clean-build build-linux build-darwin build-windows

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

debug: clean-build ## Build a debug version
	@mkdir -p $(build_path)
	@go build -o $(build_path)$(app_name) .
	@echo "Debug build done"

release: clean-build build-linux build-darwin build-windows ## Build the release version
	@echo "Release $(version) done"

clean-build: ## Clean the build directory
	@rm -fr $(build_path)

build-linux: ## Build release for GNU/Linux
	@mkdir -p $(build_path)
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-linux-amd64 .
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-linux-arm64 .
	@CGO_ENABLED=0 GOOS=linux GOARCH=386   go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-linux-386 .

build-darwin: ## Build release for macOS
	@mkdir -p $(build_path)
	@CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-darwin-amd64 .
	@CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-darwin-arm64 .

build-windows: ## Build release for Windows
	@mkdir -p $(build_path)
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-windows-amd64.exe .
	@CGO_ENABLED=0 GOOS=windows GOARCH=386   go build -ldflags="$(ldflags)" -o $(build_path)$(app_name)-$(version)-windows-386.exe .
```

---

## 14. Exemples de deploiement

### systemd (`docs/examples/open-go-dig.service`)

```ini
[Unit]
Description=OpenGoDig - Web DNS Lookup
After=network.target

[Service]
Type=simple
User=open-go-dig
Group=open-go-dig
WorkingDirectory=/opt/open-go-dig
ExecStart=/opt/open-go-dig/open-go-dig -c /opt/open-go-dig/config.yaml
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/opt/open-go-dig

[Install]
WantedBy=multi-user.target
```

### nginx (`docs/examples/open-go-dig.nginx.conf`)

Meme structure que le projet de reference, avec `upstream open-go-dig` sur le port 8080.

---

## 15. Routes HTTP

| Methode | Route | Handler | Description |
|---------|-------|---------|-------------|
| GET | `/{$}` | `IndexHandler` | Page d'accueil |
| GET | `/about` | `AboutHandler` | Page a propos |
| GET | `/lookup` | `LookupHandler` | Resultat HTML (`?query=...&type=A,MX`) |
| GET | `/api/lookup` | `ApiHandler` | Resultat JSON (`?query=...&type=A,MX`) |
| GET | `/api/status` | `StatusHandler` | Statut des resolvers (JSON) |
| GET | `/static/*` | FileServer | Assets embarques |

Le parametre `type` est optionnel. S'il est absent, interroger tous les types courants. S'il est present, n'interroger que les types demandes (separes par virgule).

---

## 16. Contraintes non-fonctionnelles

1. **Binaire unique** : tout est embarque via `//go:embed` (templates, CSS, JS, fonts, images)
2. **Pas de base de donnees** : tout est stateless
3. **Graceful shutdown** : capturer SIGINT/SIGTERM, contexte 15s pour terminer les requetes en cours
4. **Timeouts HTTP** : Read 10s, Write 30s, Idle 120s
5. **Timeout DNS** : configurable, defaut 5s par requete
6. **Rate limiting** : par IP, token bucket, configurable (defaut 20 req/min)
7. **Securite** : CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, trusted proxies
8. **i18n** : detection par Accept-Language, au minimum anglais + francais
9. **Thread safety** : toutes les structures partagees protegees par mutex
10. **Logs** : `log.Printf` standard, mode debug optionnel

---

## 17. Exemples d'utilisation attendus

### Interface web
- Saisir `google.com` → voir les records A, AAAA, MX, NS, TXT, SOA, CAA
- Saisir `1.1.1.1` → reverse DNS (PTR) automatique
- Saisir `MX:proton.me` → uniquement les records MX
- Saisir `2606:4700::1111` → reverse DNS IPv6

### API JSON
```
GET /api/lookup?query=google.com
GET /api/lookup?query=google.com&type=MX,NS
GET /api/lookup?query=1.1.1.1
GET /api/status
```

---

## 18. Resume des dependances Go

```
module open-go-dig

go 1.25.0

require (
    github.com/ilyakaznacheev/cleanenv v1.5.0
    github.com/miekg/dns v1.1.62
)
```

---

## 19. Ce qu'il ne faut PAS faire

- Pas de framework web (gin, echo, fiber, chi, gorilla)
- Pas de framework CSS (Tailwind, Bootstrap)
- Pas de bundler JS (webpack, vite, esbuild)
- Pas de base de donnees
- Pas de cache sophistique (le DNS a deja un systeme de TTL)
- Pas de WebSocket ou SSE
- Pas d'authentification
- Ne pas over-engineerer : garder l'architecture plate et lisible
