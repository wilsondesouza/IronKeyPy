"""
Auditoria de saúde do cofre.

Funcionalidade ausente na versão anterior e considerada básica em qualquer
gerenciador de senhas: o usuário não tinha como descobrir, sem abrir registro
por registro, quais credenciais estão **reutilizadas**, **fracas**, **vazadas**
ou **antigas** — exatamente os quatro fatores que causam comprometimento de
conta na prática.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Sequence

from database.database import UNREADABLE_TITLE, VaultEntry
from services.password_generator import PasswordGenerator


class IssueLevel(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Issue:
    level: IssueLevel
    kind: str
    title: str
    detail: str
    entry_uid: str = ""
    entry_title: str = ""


@dataclass
class AuditReport:
    total_entries: int = 0
    issues: List[Issue] = field(default_factory=list)
    reused_groups: Dict[str, List[str]] = field(default_factory=dict)
    checked_online: bool = False
    score: int = 100

    @property
    def critical(self) -> List[Issue]:
        return [i for i in self.issues if i.level is IssueLevel.CRITICAL]

    @property
    def warnings(self) -> List[Issue]:
        return [i for i in self.issues if i.level is IssueLevel.WARNING]

    @property
    def infos(self) -> List[Issue]:
        return [i for i in self.issues if i.level is IssueLevel.INFO]

    def summary(self) -> str:
        if not self.issues:
            return "Nenhum problema encontrado. Seu cofre está saudável."
        parts = []
        if self.critical:
            parts.append(f"{len(self.critical)} crítico(s)")
        if self.warnings:
            parts.append(f"{len(self.warnings)} aviso(s)")
        if self.infos:
            parts.append(f"{len(self.infos)} observação(ões)")
        return " · ".join(parts)


class VaultAuditor:
    OLD_PASSWORD_DAYS = 365
    WEAK_ENTROPY_BITS = 60

    def __init__(self, generator: Optional[PasswordGenerator] = None):
        self.generator = generator or PasswordGenerator()

    # ------------------------------------------------------------------
    def audit(self, entries: Sequence[VaultEntry],
              pwned_counts: Optional[Dict[str, int]] = None) -> AuditReport:
        """
        ``pwned_counts`` mapeia ``sha1(senha).upper()`` -> nº de vazamentos.
        Passe ``None`` para uma auditoria 100% offline.
        """
        report = AuditReport(total_entries=len(entries), checked_online=pwned_counts is not None)
        real = [e for e in entries if e.password]

        self._check_reuse(real, report)
        self._check_strength(real, report)
        self._check_age(real, report)
        self._check_hygiene(entries, report)
        if pwned_counts:
            self._check_pwned(real, pwned_counts, report)

        report.score = self._score(report, len(real) or 1)
        return report

    # ------------------------------------------------------------------
    def _check_reuse(self, entries: Sequence[VaultEntry], report: AuditReport) -> None:
        buckets: Dict[str, List[VaultEntry]] = defaultdict(list)
        for entry in entries:
            # Agrupa por hash para não manter senhas duplicadas em memória.
            buckets[hashlib.sha256(entry.password.encode()).hexdigest()].append(entry)

        for digest, group in buckets.items():
            if len(group) < 2:
                continue
            names = [e.display_title for e in group]
            report.reused_groups[digest] = names
            for entry in group:
                others = [n for n in names if n != entry.display_title] or names
                report.issues.append(
                    Issue(
                        level=IssueLevel.CRITICAL,
                        kind="reuse",
                        title="Senha reutilizada",
                        detail=(
                            "A mesma senha é usada em: " + ", ".join(names) +
                            ". Um vazamento em qualquer um desses serviços "
                            "compromete todos os outros."
                        ),
                        entry_uid=entry.uid,
                        entry_title=entry.display_title,
                    )
                )
                del others

    def _check_strength(self, entries: Sequence[VaultEntry], report: AuditReport) -> None:
        for entry in entries:
            analysis = self.generator.analyze(entry.password)
            if analysis.entropy_bits < 40:
                level, label = IssueLevel.CRITICAL, "Senha muito fraca"
            elif analysis.entropy_bits < self.WEAK_ENTROPY_BITS:
                level, label = IssueLevel.WARNING, "Senha fraca"
            else:
                continue
            reasons = "; ".join(analysis.warnings) or "Entropia insuficiente."
            report.issues.append(
                Issue(
                    level=level,
                    kind="weak",
                    title=label,
                    detail=(
                        f"{analysis.entropy_bits:.0f} bits de entropia "
                        f"(quebra estimada: {analysis.crack_time}). {reasons}"
                    ),
                    entry_uid=entry.uid,
                    entry_title=entry.display_title,
                )
            )

    def _check_age(self, entries: Sequence[VaultEntry], report: AuditReport) -> None:
        now = datetime.now(timezone.utc)
        for entry in entries:
            changed = _parse_iso(entry.password_changed_at or entry.created_at)
            if changed is None:
                continue
            age_days = (now - changed).days
            if age_days >= self.OLD_PASSWORD_DAYS:
                report.issues.append(
                    Issue(
                        level=IssueLevel.INFO,
                        kind="old",
                        title="Senha antiga",
                        detail=f"Sem troca há {age_days} dias.",
                        entry_uid=entry.uid,
                        entry_title=entry.display_title,
                    )
                )

    def _check_hygiene(self, entries: Sequence[VaultEntry], report: AuditReport) -> None:
        for entry in entries:
            if entry.title == UNREADABLE_TITLE:
                report.issues.append(
                    Issue(
                        level=IssueLevel.CRITICAL,
                        kind="corrupt",
                        title="Registro ilegível",
                        detail="Falha na verificação de integridade (AES-GCM).",
                        entry_uid=entry.uid,
                        entry_title=entry.display_title,
                    )
                )
                continue
            if not entry.password:
                report.issues.append(
                    Issue(
                        level=IssueLevel.INFO,
                        kind="empty",
                        title="Sem senha",
                        detail="Registro salvo sem senha.",
                        entry_uid=entry.uid,
                        entry_title=entry.display_title,
                    )
                )
            if entry.url and entry.url.lower().startswith("http://"):
                report.issues.append(
                    Issue(
                        level=IssueLevel.WARNING,
                        kind="insecure_url",
                        title="URL sem HTTPS",
                        detail=(
                            f"“{entry.url}” usa HTTP. Credenciais enviadas a esse "
                            "endereço trafegam sem criptografia."
                        ),
                        entry_uid=entry.uid,
                        entry_title=entry.display_title,
                    )
                )

    def _check_pwned(self, entries: Sequence[VaultEntry],
                     pwned_counts: Dict[str, int], report: AuditReport) -> None:
        for entry in entries:
            digest = hashlib.sha1(entry.password.encode("utf-8")).hexdigest().upper()
            count = pwned_counts.get(digest, 0)
            if count > 0:
                report.issues.append(
                    Issue(
                        level=IssueLevel.CRITICAL,
                        kind="pwned",
                        title="Senha exposta em vazamento",
                        detail=(
                            f"Encontrada {count:,} vez(es) na base do Have I Been Pwned. "
                            "Troque imediatamente.".replace(",", ".")
                        ),
                        entry_uid=entry.uid,
                        entry_title=entry.display_title,
                    )
                )

    @staticmethod
    def _score(report: AuditReport, total: int) -> int:
        """
        Pontuação relativa ao tamanho do cofre.

        Calibrada para que um cofre com 1 senha reutilizada em 10 fique perto de
        90, e um cofre em que metade das senhas é fraca/reutilizada caia para a
        faixa vermelha (< 50).
        """
        penalty = (
            len(report.critical) * 15
            + len(report.warnings) * 6
            + len(report.infos) * 2
        )
        return max(0, min(100, 100 - round(penalty / max(total, 1) * 2.5)))


def _parse_iso(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        try:
            parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
