"""Heuristic detector for common AI-writing tells. Rules-only, deterministic, no LLM.
Not proof of AI authorship - a signal. Free quick score, paid detailed report."""
import re, statistics

RULES = [
    (r"\bdelve(?:s|d|ing)?\b", "vocab"), (r"\btapestry\b", "vocab"),
    (r"\btestament to\b", "vocab"), (r"\bunderscor(?:e|es|ing)\b", "vocab"),
    (r"\bpivotal\b", "vocab"), (r"\bcrucial\b", "vocab"), (r"\brealm\b", "vocab"),
    (r"\bbustling\b", "vocab"), (r"\bvibrant\b", "vocab"),
    (r"\bdive(?:s|d|ing)? into\b", "vocab"), (r"\bnavigat(?:e|es|ed|ing|ion)\b", "vocab"),
    (r"\bseamless(?:ly)?\b", "hype"), (r"\bunlock(?:s|ed|ing)?\b", "hype"),
    (r"\bunleash(?:es|ed|ing)?\b", "hype"), (r"\bharness(?:es|ed|ing)?\b", "hype"),
    (r"\belevat(?:e|es|ed|ing)\b", "hype"), (r"\bleverag(?:e|es|ed|ing)\b", "hype"),
    (r"\brobust(?:ly)?\b", "hype"), (r"\bcutting[- ]edge\b", "hype"),
    (r"\bgame[- ]?chang(?:er|ing)\b", "hype"), (r"\bsupercharg(?:e|es|ed|ing)\b", "hype"),
    (r"\bever[- ](?:evolving|changing|growing|expanding)\b", "hype"),
    (r"\bfast[- ]paced\b", "hype"), (r"\bdeep[- ]dive\b", "hype"),
    (r"\btap(?:s|ped|ping)? into\b", "hype"), (r"\blook no further\b", "hype"),
    (r"\bit'?s not just\b", "structure"), (r"\bnot just\b.{0,60}\bbut\b", "structure"),
    (r"\bnot only\b.{0,80}\bbut also\b", "structure"), (r"\bisn'?t just\b", "structure"),
    (r"\bwhether you'?re\b", "structure"), (r"\bin today'?s\b", "structure"),
    (r"\bin the (?:world|realm) of\b", "structure"), (r"\bwhen it comes to\b", "structure"),
    (r"\bthe key takeaway\b", "structure"), (r"\bwhether it'?s\b", "structure"),
    (r"\bit'?s (?:important|worth) (?:to note|noting)\b", "hedging"),
    (r"\bat the end of the day\b", "hedging"), (r"\bessentially,?\b", "hedging"),
    (r"\bnotably,?\b", "hedging"), (r"\barguably,?\b", "hedging"),
    (r"\bin conclusion\b", "transition"), (r"\bultimately,?\b", "transition"),
    (r"\bmoreover,?\b", "transition"), (r"\bfurthermore,?\b", "transition"),
    (r"\badditionally,?\b", "transition"), (r"\bhowever,?\b", "transition"),
    (r"\boverall,?\b", "transition"),
]
COMPILED = [(re.compile(p, re.I), c, p) for p, c in RULES]
TRIAD = re.compile(r"\b\w[\w'-]{0,20},\s+\w[\w'-]{0,20},\s+(?:and|or)\s+\w", re.I)
SENT_SPLIT = re.compile(r"(?<=[.!?])[\"')\]]*\s+")
STARTERS = re.compile(r"^(?:however|moreover|furthermore|additionally|ultimately|overall|notably|in conclusion|therefore|thus),?\s", re.I)

def _sentences(text):
    return [s for s in SENT_SPLIT.split(text) if s and s.strip()]

def analyze(text):
    words = re.findall(r"[A-Za-z0-9']+", text)
    w = max(1, len(words))
    sents = _sentences(text)
    matches, cat_counts = [], {}
    for rx, cat, pat in COMPILED:
        hits = list(rx.finditer(text))
        if not hits:
            continue
        ex = []
        for s in sents:
            if rx.search(s) and len(ex) < 2:
                ex.append(s.strip()[:220])
        matches.append({"pattern": pat, "category": cat, "count": len(hits), "examples": ex})
        cat_counts[cat] = cat_counts.get(cat, 0) + len(hits)
    emdash = len(re.findall("[\u2014\u2013]", text))
    triads = len(TRIAD.findall(text))
    lens = [len(re.findall(r"[A-Za-z0-9']+", s)) for s in sents]
    lens = [l for l in lens if l > 0]
    n = len(lens)
    stdev = statistics.stdev(lens) if n > 1 else 0
    starters = sum(1 for s in sents if STARTERS.match(s.strip()))
    starter_frac = starters / n if n else 0
    density = sum(m["count"] for m in matches) / w * 1000
    em_rate = emdash / w * 1000
    score = density * 5 + em_rate * 8 + triads / w * 1000 * 6
    if n >= 8:
        if stdev < 4.5: score += 18
        elif stdev < 7: score += 9
    if starter_frac > 0.25: score += 15
    elif starter_frac > 0.15: score += 7
    score = int(min(99, max(0, round(score))))
    return {
        "score": score,
        "verdict": ("strong AI-writing signals" if score >= 65 else
                    "likely AI-assisted or unedited AI" if score >= 40 else
                    "mixed signals" if score >= 20 else
                    "no strong AI tells"),
        "words": len(words), "sentences": n,
        "tells_per_1k_words": round(density + em_rate * 0.3, 1),
        "categories": dict(sorted(cat_counts.items(), key=lambda kv: -kv[1])),
        "top_patterns": sorted(matches, key=lambda m: -m["count"])[:12],
        "style": {"em_dash_count": emdash, "em_dash_per_1k": round(em_rate, 1),
                  "rule_of_three_lists": triads, "sentence_len_stdev": round(stdev, 1),
                  "formulaic_sentence_starts_pct": round(starter_frac * 100, 1)},
        "disclaimer": "Heuristic signals, not proof. Humans use em-dashes too; AI-free text scores 0-20.",
    }
