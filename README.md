# PKI 7

## Uruchamianie

Program budujemy oraz uruchamiamy za pomocą narzędzia cargo będącego częścią toolchain'a języka rust, np.:

```
cargo run --release
```

Do uruchomienia programu wymagane jest istnienie w folderze głównym pliku .env zawierającego następujące zmienne środowiskowe:

```
PORT = port na którym serwowana jest aplikacja
DEPLOYMENT_URL = link do strony gdzie strona została wdrożona (https://pki-6.onrender.com)
DATABASE_URL = link do połączenia z bazą danych Postgres
GOOGLE_CLIENT_ID = id klienta OAuth Google
GOOGLE_CLIENT_SECRET = hasło klienta OAuth Google
GOOGLE_AUTH_URL = endpoint to autoryzacji OAuth Google (https://accounts.google.com/o/oauth2/auth)
GOOGLE_TOKEN_URL = endpoint do pozyskania Access Token'a Google (https://oauth2.googleapis.com/token)
GITHUB_CLIENT_ID = id klienta OAuth Github
GITHUB_CLIENT_SECRET = hasło klienta OAuth Github
GITHUB_AUTH_URL = endpoint to autoryzacji OAuth Github (https://github.com/login/oauth/authorize)
GITHUB_TOKEN_URL = endpoint do pozyskania Access Token'a Github (https://github.com/login/oauth/access_token)
````

## Linki

REPO https://github.com/jgrodzki/pki_6

DEPLOYMENT https://pki-6.onrender.com
