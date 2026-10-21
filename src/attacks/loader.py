"""
Attack loader — reads YAML seed files and loads them into the database.
Also supports importing from garak and PyRIT adapters.
"""

import logging
import uuid
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.attacks.categories import AttackCategory, Severity
from src.models.attack import Attack

logger = logging.getLogger(__name__)

SEEDS_DIR = Path(__file__).parent / "seeds"

# Map YAML category names to seed filenames
CATEGORY_FILE_MAP = {
    AttackCategory.JAILBREAK: "jailbreaks.yaml",
    AttackCategory.INDIRECT_INJECTION: "indirect_injection.yaml",
    AttackCategory.PROMPT_EXTRACTION: "prompt_extraction.yaml",
    AttackCategory.PII_EXTRACTION: "pii_extraction.yaml",
    AttackCategory.HARMFUL_CONTENT: "harmful_content.yaml",
    AttackCategory.TOOL_ABUSE: "tool_abuse.yaml",
    AttackCategory.ENCODING_TRICKS: "encoding_tricks.yaml",
}


async def load_yaml_seeds(session: AsyncSession, force_reload: bool = False) -> int:
    """
    Load all attack seed YAML files into the database.
    Returns the number of new attacks loaded.
    
    Args:
        session: Async database session
        force_reload: If True, reload even if attacks already exist
    """
    total_loaded = 0

    for category, filename in CATEGORY_FILE_MAP.items():
        filepath = SEEDS_DIR / filename
        if not filepath.exists():
            logger.warning(f"Seed file not found: {filepath}")
            continue

        loaded = await _load_seed_file(session, filepath, category, force_reload)
        total_loaded += loaded
        logger.info(f"Loaded {loaded} attacks from {filename}")

    # Load domain-specific attacks
    domain_file = SEEDS_DIR / "domain_specific.yaml"
    if domain_file.exists():
        loaded = await _load_domain_seeds(session, domain_file, force_reload)
        total_loaded += loaded
        logger.info(f"Loaded {loaded} domain-specific attacks")

    await session.commit()
    logger.info(f"Total attacks loaded: {total_loaded}")
    return total_loaded


async def _load_seed_file(
    session: AsyncSession,
    filepath: Path,
    category: AttackCategory,
    force_reload: bool,
) -> int:
    """Load attacks from a single YAML seed file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "attacks" not in data:
        logger.warning(f"No attacks found in {filepath}")
        return 0

    loaded = 0
    for attack_data in data["attacks"]:
        name = attack_data["name"]

        # Check for existing attack by name (skip if already exists and not force)
        if not force_reload:
            existing = await session.execute(
                select(Attack).where(Attack.name == name).limit(1)
            )
            if existing.scalar_one_or_none():
                continue

        severity = Severity(attack_data.get("severity", "medium"))
        source = attack_data.get("source", "custom")

        attack = Attack(
            id=uuid.uuid4(),
            category=category,
            severity=severity,
            name=name,
            payload=attack_data["payload"].strip(),
            expected_safe_behavior=attack_data["expected_safe_behavior"].strip(),
            source=source,
            metadata_json=attack_data.get("metadata"),
            enabled=True,
        )
        session.add(attack)
        loaded += 1

    return loaded


async def _load_domain_seeds(
    session: AsyncSession,
    filepath: Path,
    force_reload: bool,
) -> int:
    """Load domain-specific attacks that may span multiple categories."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "attacks" not in data:
        return 0

    loaded = 0
    for attack_data in data["attacks"]:
        name = attack_data["name"]

        if not force_reload:
            existing = await session.execute(
                select(Attack).where(Attack.name == name).limit(1)
            )
            if existing.scalar_one_or_none():
                continue

        # Determine category from the attack content
        category = _infer_category(attack_data)
        severity = Severity(attack_data.get("severity", "medium"))

        attack = Attack(
            id=uuid.uuid4(),
            category=category,
            severity=severity,
            name=name,
            payload=attack_data["payload"].strip(),
            expected_safe_behavior=attack_data["expected_safe_behavior"].strip(),
            source=attack_data.get("source", "domain"),
            metadata_json=attack_data.get("metadata"),
            enabled=True,
        )
        session.add(attack)
        loaded += 1

    return loaded


def _infer_category(attack_data: dict) -> AttackCategory:
    """Infer the attack category from domain-specific attacks based on keywords."""
    name_lower = attack_data["name"].lower()
    payload_lower = attack_data.get("payload", "").lower()
    combined = name_lower + " " + payload_lower

    if any(kw in combined for kw in ["rag", "retrieval", "knowledge base", "document", "citation"]):
        return AttackCategory.INDIRECT_INJECTION
    if any(kw in combined for kw in ["agent", "impersonat", "forward", "inter-agent"]):
        return AttackCategory.TOOL_ABUSE
    if any(kw in combined for kw in ["pii", "confidential", "leak", "cross-context"]):
        return AttackCategory.PII_EXTRACTION
    if any(kw in combined for kw in ["fraud", "bias", "misinformation"]):
        return AttackCategory.HARMFUL_CONTENT
    if any(kw in combined for kw in ["prompt", "system", "instruction"]):
        return AttackCategory.PROMPT_EXTRACTION

    return AttackCategory.JAILBREAK  # Default fallback


async def get_attack_stats(session: AsyncSession) -> dict:
    """Get statistics about the attack battery."""
    result = await session.execute(select(Attack).where(Attack.enabled == True))
    attacks = result.scalars().all()

    stats = {
        "total": len(attacks),
        "by_category": {},
        "by_severity": {},
        "by_source": {},
    }

    for attack in attacks:
        cat = attack.category if isinstance(attack.category, str) else attack.category.value
        sev = attack.severity if isinstance(attack.severity, str) else attack.severity.value
        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
        stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
        stats["by_source"][attack.source] = stats["by_source"].get(attack.source, 0) + 1

    return stats
