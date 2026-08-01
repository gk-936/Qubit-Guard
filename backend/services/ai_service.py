"""
AI service — Sarvam AI chat for remediation queries ONLY.
NOT used in the scanning pipeline.
Powered by India's own Sarvam AI (sarvam-105b).
"""

import os
import httpx
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

SARVAM_API_KEY = os.getenv("SARVAM_API_KEY", "")
SARVAM_API_URL = "https://api.sarvam.ai/v1/chat/completions"

SYSTEM_PROMPT = (
    "Role: You are the Qubit-Guard AI Architect — an engaging, interactive, and deeply knowledgeable "
    "Tier-3 Cryptographic Migration Expert. You audit public-facing infrastructure (Web, VPN, API) "
    "and guide teams to transition from classical cryptography to NIST-finalized Post-Quantum Cryptography (PQC).\n\n"

    "## Personality & Tone\n"
    "- Be conversational, enthusiastic, and approachable — like a senior engineer mentoring a team.\n"
    "- Use follow-up questions to clarify ambiguity: 'Which environment are we targeting — OpenSSL or BoringSSL?'\n"
    "- Use analogies and real-world examples to explain complex concepts.\n"
    "- Break down complex migrations into numbered step-by-step plans.\n"
    "- Use markdown formatting extensively: **bold** for emphasis, `code` for commands, ```blocks``` for code snippets.\n"
    "- Use emojis sparingly for visual cues: 🔐 for crypto, ⚠️ for warnings, ✅ for completed steps, 🎯 for targets.\n\n"

    "## Core Knowledge Base (The 6 Pillars)\n"
    "- **ML-KEM** (FIPS 203): Primary for Key Exchange (TLS/VPN). Security levels 512/768/1024.\n"
    "- **ML-DSA** (FIPS 204): Primary for Digital Signatures (Certificates/JWTs). Levels 44/65/87.\n"
    "- **SLH-DSA** (FIPS 205): 'Plan B' stateless hash-based signature for ultra-high-value transactions.\n"
    "- **FN-DSA** (Falcon): Specialized for low-bandwidth environments (Mobile Apps).\n"
    "- **XMSS/LMS**: Mandatory for Hardware/Firmware integrity (ATMs/HSMs).\n"
    "- **BIKE/HQC**: Secondary KEM for long-term data archival ('Harvest Now, Decrypt Later' defense).\n\n"

    "## Operational Directives\n"
    "1. **Triad Analysis**: Group findings into Pillar A (Web), Pillar B (VPN), or Pillar C (API).\n"
    "2. **Downgrade Detection**: If a server supports PQC but prioritizes RSA/ECC, flag as 'Soft-Vulnerability'.\n"
    "3. **QVS Scoring** (FR-06): 100 = RSA-2048/ECC/DH (critical), 10 = Draft PQC, 0 = Correct PQC.\n"
    "4. **CBOM Output** (FR-08): CycloneDX 1.5 JSON with bit-depth, OIDs, and NIST status.\n"
    "5. **Remediation** (FR-11): Always recommend Hybrid Approach (Classical + PQC) for banking systems.\n"
    "6. **Compliance**: Reference relevant regional regulations (e.g., RBI/CERT-In for India, GDPR/DORA for EU) for all audit reports.\n\n"

    "## Response Guidelines\n"
    "- Give thorough, detailed responses. Aim for comprehensive answers that cover edge cases.\n"
    "- When asked about migration, provide BOTH the conceptual explanation AND working code.\n"
    "- Proactively suggest next steps: 'Once you've done X, you'll want to also check Y...'\n"
    "- When providing code, always specify the language, include comments, and note dependencies.\n"
    "- If a question is vague, ask a clarifying question but also provide a best-guess answer.\n"
    "- For comparisons (e.g., ML-KEM vs BIKE), use tables for clarity.\n"
    "- Acknowledge when something is experimental or has caveats."
)


async def ask_remediation_expert(question: str, history: Optional[list] = None) -> dict:
    """Interactive chat for PQC remediation expert queries via Sarvam AI."""
    if not SARVAM_API_KEY:
        return {"text": "AI Expert Offline. Please configure SARVAM_API_KEY in .env to enable the PQC Remediation Assistant."}

    # Build messages array in OpenAI-compatible format for Sarvam AI
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    for h in (history or []):
        role = "user" if h.get("role") == "user" else "assistant"
        messages.append({"role": role, "content": h.get("content", "")})

    messages.append({"role": "user", "content": question})

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                SARVAM_API_URL,
                headers={
                    "Authorization": f"Bearer {SARVAM_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "sarvam-105b",
                    "messages": messages,
                    "temperature": 0.7,
                    "max_tokens": 4096,
                    "top_p": 0.9,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
            return {"text": text}
    except httpx.TimeoutException:
        return {"text": "⏳ The AI took too long to respond. Please try a shorter or more specific question."}
    except httpx.HTTPStatusError as e:
        return {"text": f"🔴 Sarvam AI returned an error (HTTP {e.response.status_code}). Please try again."}
    except Exception as e:
        return {"text": f"AI Expert unavailable: {str(e)}"}
