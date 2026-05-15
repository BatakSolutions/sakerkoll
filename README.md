# Säkerkoll

> En svensk lösenordskoll som aldrig ser ditt lösenord.

**Live:** [säkerkoll.se](https://säkerkoll.se) · [sakerkoll.vercel.app](https://sakerkoll.vercel.app)

Säkerkoll låter dig kolla om ditt lösenord finns i kända dataintrång — utan att lösenordet någonsin lämnar din webbläsare. Vi använder samma teknik (**k-anonymitet** mot HaveIBeenPwneds Pwned Passwords API) som 1Password, Bitwarden och Mozilla Monitor använder internt.

## Hur det funkar

```
1. Du skriver in ett lösenord
2. Din webbläsare hashar det lokalt med SHA-1 (SubtleCrypto)
3. Bara de första 5 tecknen av hashen skickas till api.pwnedpasswords.com
4. HIBP returnerar alla hashar som börjar på samma 5 tecken (hundratals)
5. Din webbläsare jämför resten lokalt och visar resultatet
```

Lösenordet lämnar **aldrig** din enhet. Verifiera själv genom att öppna DevTools (F12) → Network-fliken → kolla att det enda som skickas är 5 tecken.

## Funktioner

- **Lösenordsläck-koll** mot HIBP Pwned Passwords (k-anonymitet)
- **Realtids-styrkemätare** (egen entropi-beräkning, helt offline)
- **Bot-arena** som demonstrerar hur snabbt vanliga lösenord knäcks (offline)
- **Lösenords-generator** (`/generator`) — kryptografiskt slumpade lösenord
- **URL-koll** (`/url-koll`) — kolla om en länk är misstänkt
- **Säkerhetsquiz** (`/quiz`) — 10 frågor om hur du skyddar dig
- **Integritetspolicy** (`/integritet`) — GDPR-kompatibel

## Tech

- Ren HTML/CSS/JavaScript — inga byggsteg
- Vanilla DOM, ingen framework
- `SubtleCrypto.digest('SHA-1')` för lokal hashning
- Google Fonts: Fraunces (serif) + Geist (sans) + Geist Mono
- Hostas på Vercel
- DNS via Cloudflare

## Kör lokalt

```bash
git clone https://github.com/cetoro67/sakerkoll.git
cd sakerkoll
# Servera mappen med valfri statisk server, t.ex.:
python -m http.server 8000
# eller
npx serve .
```

Öppna sedan `http://localhost:8000`.

## Bidra

Hittar du en bugg eller säkerhetsbrist? Öppna ett issue eller mejla **ari.dev.web@gmail.com**. Säkerhetsrapporter prioriteras.

## Licens

[**GNU AGPL-3.0**](LICENSE)

AGPL valdes medvetet: om någon kör en kopia av Säkerkoll som webbtjänst måste de också släppa sin källkod. Det avskräcker scam-kloner som vill ge sken av att vara en seriös säkerhetstjänst utan att vara det.

Använder du koden i ett eget projekt? Hör gärna av dig — vi gillar att se vad folk bygger.

## Operatör

**Batak Solutions** · Ängelholm, Sverige
Kontakt: [ari.dev.web@gmail.com](mailto:ari.dev.web@gmail.com)
