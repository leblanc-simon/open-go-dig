#!/usr/bin/env bash
#
# test-dns.sh — batterie de tests fonctionnels contre l'API OpenGoDig.
#
# Balaie une série de domaines couvrant les cas notables (underscore/DKIM/DMARC,
# SRV, CAA, reverse IPv4/IPv6, IDN/punycode, DNSSEC, NXDOMAIN…) et vérifie pour
# chacun le résultat retourné par l'app.
#
# Si la commande `dig` est présente, chaque cas est en plus comparé à `dig` en
# mode différentiel : `dig` interroge LE MÊME résolveur que celui ayant répondu
# à l'app (champ .server de la réponse JSON), ce qui évite les faux écarts dus
# au GeoDNS / anycast. La comparaison porte sur l'ensemble (set) des valeurs,
# normalisées (minuscules, guillemets ôtés, espaces compactés, ordre ignoré).
#
# Sans `dig`, on retombe sur une simple vérification « au moins un
# enregistrement » (ou « aucun » pour NXDOMAIN).
#
# Usage :
#   ./scripts/test-dns.sh [BASE_URL]
#
#   BASE_URL  URL de base de l'API (défaut : http://localhost:8080)
#
# Dépendances : curl, jq (requis) ; dig (optionnel, active la comparaison).
# TEST_DNS_NO_DIG=1 force le mode app-seul même si dig est présent.
#
# Codes de sortie : 0 si tous les cas passent, 1 sinon.

set -u

BASE_URL="${1:-http://localhost:8080}"
API="${BASE_URL%/}/api/lookup"

for bin in curl jq; do
	if ! command -v "$bin" >/dev/null 2>&1; then
		echo "erreur : '$bin' est requis mais introuvable." >&2
		exit 2
	fi
done

HAVE_DIG=false
if command -v dig >/dev/null 2>&1 && [ "${TEST_DNS_NO_DIG:-}" != "1" ]; then
	HAVE_DIG=true
fi

if ! curl -fsS --max-time 5 "${BASE_URL%/}/api/status" >/dev/null 2>&1; then
	echo "erreur : impossible de joindre $BASE_URL (le serveur est-il démarré ?)" >&2
	exit 2
fi

# Normalise un flux de valeurs (une par ligne) : guillemets ôtés, minuscules,
# espaces compactés, lignes vides retirées, puis tri (ordre non significatif).
norm() {
	tr -d '"' | tr 'A-Z' 'a-z' \
		| sed 's/[[:space:]]\{1,\}/ /g; s/^ //; s/ $//' \
		| sed '/^$/d' | LC_ALL=C sort
}

count_lines() { printf '%s' "$1" | grep -c . ; }

# Chaque cas : "libellé|query|type|mode"
#   type  : type d'enregistrement (vide = défauts de l'app ; ou préfixe TYPE: dans query)
#   mode  : exact   → l'ensemble des valeurs app doit égaler celui de dig
#           count   → app et dig doivent tous deux renvoyer au moins un record
#                     (formats non directement comparables : SRV, anycast…)
#           empty   → app et dig doivent tous deux ne rien renvoyer (NXDOMAIN)
CASES=(
	"NS (set stable)|google.com|NS|exact"
	"MX (priorité + hôte)|google.com|MX|exact"
	"SOA|google.com|SOA|exact"
	"CAA|google.com|CAA|exact"
	"TXT DMARC (label _dmarc)|_dmarc.google.com|TXT|exact"
	"TXT DKIM (label _domainkey)|selector1._domainkey.microsoft.com|TXT|exact"
	"TXT (SPF Cloudflare)|cloudflare.com|TXT|exact"
	"SRV (double underscore)|_xmpp-client._tcp.jabber.org|SRV|count"
	"SRV via préfixe TYPE:|SRV:_xmpp-client._tcp.jabber.org||count"
	"A IDN / punycode (münchen.de)|xn--mnchen-3ya.de|A|exact"
	"A anycast (DNSSEC)|cloudflare.com|A|count"
	"NS RFC 2606 réservé|example.com|NS|exact"
	"Reverse IPv4 (PTR)|8.8.8.8|PTR|exact"
	"Reverse IPv4 Cloudflare (PTR)|1.1.1.1|PTR|exact"
	"Reverse IPv6 (PTR)|2606:4700:4700::1111|PTR|exact"
	"NXDOMAIN|nxdomain-xyz-does-not-exist-ogd.example|A|empty"
)

pass=0
fail=0

if $HAVE_DIG; then
	printf '%-38s %-6s %-5s %-5s %s\n' "CAS" "MODE" "APP" "DIG" "RÉSULTAT"
else
	printf '%-38s %-6s %-5s %s\n' "CAS" "MODE" "APP" "RÉSULTAT (dig absent)"
fi
printf '%s\n' "------------------------------------------------------------------------------------"

for entry in "${CASES[@]}"; do
	IFS='|' read -r label query type mode <<<"$entry"

	# Requête app (avec le type si fourni ; sinon on laisse le préfixe agir).
	url="$API?query=$(jq -rn --arg q "$query" '$q|@uri')"
	if [ -n "$type" ]; then
		url="$url&type=$(jq -rn --arg t "$type" '$t|@uri')"
	fi

	body="$(curl -fsS --max-time 30 "$url" 2>/dev/null)"
	if [ -z "$body" ] || ! echo "$body" | jq empty >/dev/null 2>&1; then
		printf '%-38s %-6s %-5s %-5s %s\n' "$label" "$mode" "-" "-" "✗ (réponse app invalide)"
		fail=$((fail + 1))
		continue
	fi

	app_vals="$(echo "$body" | jq -r '[.records[]?.Records[]? | if .Type=="MX" then "\(.Priority) \(.Value)" else .Value end] | .[]')"
	app_n="$(count_lines "$app_vals")"

	# ── Sans dig : vérification simple app-only ────────────────────────────
	if ! $HAVE_DIG; then
		if [ "$mode" = "empty" ]; then
			ok=$([ "$app_n" -eq 0 ] && echo true || echo false)
		else
			ok=$([ "$app_n" -gt 0 ] && echo true || echo false)
		fi
		if [ "$ok" = true ]; then
			printf '%-38s %-6s %-5s %s\n' "$label" "$mode" "$app_n" "✓"; pass=$((pass + 1))
		else
			printf '%-38s %-6s %-5s %s\n' "$label" "$mode" "$app_n" "✗"; fail=$((fail + 1))
		fi
		continue
	fi

	# ── Avec dig : interroge le MÊME résolveur que l'app ───────────────────
	server="$(echo "$body" | jq -r '.server // ""' | sed 's/:[0-9]*$//')"
	[ -z "$server" ] || [ "$server" = "null" ] && server="8.8.8.8"

	# Détermine type et domaine pour dig (gère le préfixe TYPE:domaine).
	dig_type="$type"; dig_domain="$query"
	if [ -z "$dig_type" ]; then
		left="${query%%:*}"
		if printf '%s' "$left" | grep -qE '^[A-Za-z]+$'; then
			dig_type="$(printf '%s' "$left" | tr 'a-z' 'A-Z')"
			dig_domain="${query#*:}"
		fi
	fi

	if [ "$dig_type" = "PTR" ]; then
		dig_vals="$(dig +short "@$server" -x "$dig_domain" 2>/dev/null)"
	else
		dig_vals="$(dig +short "@$server" "$dig_type" "$dig_domain" 2>/dev/null)"
	fi
	dig_n="$(count_lines "$dig_vals")"

	case "$mode" in
		exact)
			a="$(printf '%s\n' "$app_vals" | norm)"
			d="$(printf '%s\n' "$dig_vals" | norm)"
			if [ "$a" = "$d" ]; then
				result="✓"; pass=$((pass + 1))
			else
				result="✗ (écart de valeurs)"; fail=$((fail + 1))
			fi
			;;
		count)
			if [ "$app_n" -gt 0 ] && [ "$dig_n" -gt 0 ]; then
				result="✓"; pass=$((pass + 1))
			else
				result="✗ (attendu ≥1 des deux côtés)"; fail=$((fail + 1))
			fi
			;;
		empty)
			if [ "$app_n" -eq 0 ] && [ "$dig_n" -eq 0 ]; then
				result="✓"; pass=$((pass + 1))
			else
				result="✗ (attendu vide des deux côtés)"; fail=$((fail + 1))
			fi
			;;
		*)
			result="✗ (mode inconnu: $mode)"; fail=$((fail + 1))
			;;
	esac

	printf '%-38s %-6s %-5s %-5s %s\n' "$label" "$mode" "$app_n" "$dig_n" "$result"
done

printf '%s\n' "------------------------------------------------------------------------------------"
if $HAVE_DIG; then
	printf '%d réussis, %d échoués (comparaison dig activée)\n' "$pass" "$fail"
else
	printf '%d réussis, %d échoués (dig absent : vérification app seule)\n' "$pass" "$fail"
fi

[ "$fail" -eq 0 ]
