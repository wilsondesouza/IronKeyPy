from __future__ import annotations

import hashlib
import time
from typing import Dict, Iterable, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    Retry = None  # type: ignore[assignment]

USER_AGENT = "IronKeyPy-PasswordManager/2.0 (+https://github.com/wilsondesouza/IronKeyPy)"


class PwnedError(Exception):
    """Erro de comunicação com a API (mensagem pronta para a UI)."""


class PwnedChecker:
    def __init__(self, timeout: int = 8):
        self.password_api_url = "https://api.pwnedpasswords.com/range/"
        self.breach_api_url = "https://haveibeenpwned.com/api/v3/breachedaccount/"
        self.timeout = timeout
        self._cache: Dict[str, Dict[str, int]] = {}
        self._session = self._build_session()

    @staticmethod
    def _build_session() -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "User-Agent": USER_AGENT,
            # Uniformiza o tamanho das respostas (defesa contra análise de tráfego).
            "Add-Padding": "true",
        })
        if Retry is not None:
            retry = Retry(
                total=3,
                backoff_factor=0.6,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET"]),
                respect_retry_after_header=True,
            )
            session.mount("https://", HTTPAdapter(max_retries=retry))
        return session

    # ------------------------------------------------------------------
    @staticmethod
    def sha1_hex(password: str) -> str:
        return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    def _fetch_range(self, prefix: str) -> Dict[str, int]:
        if prefix in self._cache:
            return self._cache[prefix]

        try:
            response = self._session.get(
                f"{self.password_api_url}{prefix}", timeout=self.timeout, verify=True
            )
        except requests.exceptions.SSLError as exc:
            raise PwnedError(
                "Falha na validação do certificado TLS. A conexão pode estar "
                "sendo interceptada — verificação cancelada."
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise PwnedError("Tempo esgotado ao consultar a API. Tente novamente.") from exc
        except requests.exceptions.ConnectionError as exc:
            raise PwnedError("Sem conexão com a internet. A verificação online foi ignorada.") from exc
        except requests.exceptions.RequestException as exc:
            raise PwnedError(f"Falha na requisição: {exc}") from exc

        if response.status_code == 429:
            raise PwnedError("Limite de requisições atingido. Aguarde alguns segundos.")
        if response.status_code != 200:
            raise PwnedError(f"A API respondeu com status {response.status_code}.")

        suffixes: Dict[str, int] = {}
        for line in response.text.splitlines():
            suffix, _, count = line.partition(":")
            suffix = suffix.strip().upper()
            if not suffix:
                continue
            try:
                occurrences = int(count.strip())
            except ValueError:
                continue
            # Com Add-Padding a API injeta entradas de contagem 0: ignore.
            if occurrences > 0:
                suffixes[suffix] = occurrences

        self._cache[prefix] = suffixes
        return suffixes

    # ------------------------------------------------------------------
    def check_password(self, password: str) -> Tuple[bool, int]:
        if not password:
            return False, 0
        digest = self.sha1_hex(password)
        suffixes = self._fetch_range(digest[:5])
        count = suffixes.get(digest[5:], 0)
        return count > 0, count

    def check_many(self, passwords: Iterable[str],
                   progress=None, pause: float = 0.15) -> Dict[str, int]:
        """
        Verifica várias senhas agrupando por prefixo (1 requisição por prefixo).

        Retorna ``{sha1_hex_maiusculo: ocorrencias}`` apenas para as vazadas.
        Erros de rede em um prefixo não abortam a auditoria inteira.
        """
        digests = {self.sha1_hex(p) for p in passwords if p}
        prefixes: Dict[str, List[str]] = {}
        for digest in digests:
            prefixes.setdefault(digest[:5], []).append(digest)

        results: Dict[str, int] = {}
        total = len(prefixes)
        for index, (prefix, group) in enumerate(sorted(prefixes.items()), start=1):
            if progress:
                progress(index, total)
            try:
                suffixes = self._fetch_range(prefix)
            except PwnedError:
                continue
            for digest in group:
                count = suffixes.get(digest[5:], 0)
                if count:
                    results[digest] = count
            if pause and index < total and prefix not in self._cache:
                time.sleep(pause)  # cortesia com a API pública
        return results

    # ------------------------------------------------------------------
    def check_email(self, email: str, api_key: Optional[str] = None) -> Tuple[bool, List[str]]:
        if not api_key:
            raise PwnedError(
                "A verificação de e-mails exige uma chave da API do HIBP "
                "(serviço pago). Cadastre-a em Configurações."
            )
        try:
            response = self._session.get(
                f"{self.breach_api_url}{requests.utils.quote(email)}",
                headers={"hibp-api-key": api_key},
                params={"truncateResponse": "true"},
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as exc:
            raise PwnedError(f"Falha ao consultar o HIBP: {exc}") from exc

        if response.status_code == 404:
            return False, []
        if response.status_code == 401:
            raise PwnedError("Chave da API do HIBP inválida ou expirada.")
        if response.status_code == 429:
            raise PwnedError("Limite de requisições atingido. Aguarde alguns segundos.")
        if response.status_code != 200:
            raise PwnedError(f"A API respondeu com status {response.status_code}.")

        try:
            breaches = [b.get("Name", "?") for b in response.json()]
        except ValueError as exc:
            raise PwnedError("Resposta inesperada da API.") from exc
        return bool(breaches), breaches

    # ------------------------------------------------------------------
    @staticmethod
    def get_password_strength_advice(is_pwned: bool, count: int) -> str:
        if not is_pwned:
            return "Senha não encontrada em nenhum vazamento conhecido."
        formatted = f"{count:,}".replace(",", ".")
        if count < 10:
            return (
                f"Esta senha apareceu {formatted} vez(es) em vazamentos públicos. "
                "Não a utilize."
            )
        if count < 1000:
            return (
                f"Esta senha apareceu {formatted} vezes em vazamentos. "
                "Ela já está em listas de ataque — troque imediatamente."
            )
        return (
            f"Esta senha apareceu {formatted} vezes em vazamentos. "
            "É uma das primeiras testadas em qualquer ataque automatizado."
        )

    @staticmethod
    def format_breach_info(breaches: List[str]) -> str:
        if not breaches:
            return "E-mail não encontrado em vazamentos conhecidos."
        shown = "\n• ".join(breaches[:8])
        total = len(breaches)
        if total <= 8:
            return f"E-mail encontrado em {total} vazamento(s):\n• {shown}"
        return (
            f"E-mail encontrado em {total} vazamentos. Primeiros 8:\n• {shown}"
            f"\n… e mais {total - 8}."
        )

    def clear_cache(self) -> None:
        self._cache.clear()
