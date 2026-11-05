"""Extended PII Patterns — Phase 4 (Hermes Hardening 2026-08-21).

Adds 35 patterns across 7 categories to the base 12 patterns:
- A: Financial (BTC, ETH, BIP39 seeds, SWIFT)
- B: DSGVO Art. 9 (Sozialversicherung, Personalausweis neu, Gesundheit, ...)
- C: Auth (JWT, OAuth, API-Key, SSH/PEM keys)
- D: Device (MAC, IMEI, IMSI, GPS)
- E: Organisatorisch (Handelsregister, Steuernummer alt, ...)
- F: Moderne Daten-Lecks (Discord/Slack/Telegram webhooks, AWS, Stripe, GitHub, ...)
- G: Kontextuelle Erkennung (Geburtsdatum, Familienstand, Beruf, Gehalt)

All patterns are compiled once at import time. Contextual patterns return a
confidence below 1.0 to distinguish them from regex certainties.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


# ── ReDoS / tuning constants ─────────────────────────────────────────────

# Context-window radius for passport/Reisepass disambiguation (chars).
_PASSPORT_CONTEXT_WINDOW: int = 50


@dataclass(frozen=True)
class CompiledPattern:
    pii_type: str
    pattern: re.Pattern[str]
    validator: "Callable[[str, str, int, int], bool] | None" = None
    confidence: float = 1.0
    # FIX-4C: when set to N > 0, scan() uses m.group(N) as the value/span
    # instead of the full match (group 0).  Useful for patterns that
    # capture only the value (api_key, label+value) so the pseudonymizer
    # does not replace the label prefix and destroy JSON/YAML structure.
    # Default 0 = use group(0) (legacy behaviour).
    value_group: int = 0


# ── Kategorie A: Finanz / Krypto ───────────────────────────────────────────

_BTC_RE = re.compile(
    r"\b(bc1[ac-hj-np-z02-9]{8,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
)

_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

# BIP39 word set used by the seed-phrase validator (not a giant regex).
_BIP39_WORDS: frozenset[str] = frozenset({
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "abuse", "access", "accident", "account",
    "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
    "action", "actor", "actress", "actual", "adapt", "add", "addict",
    "address", "adjust", "admit", "adult", "advance", "advice", "aerobic",
    "affair", "afford", "afraid", "again", "age", "agent", "agree",
    "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
    "alone", "alpha", "already", "also", "alter", "always", "amateur",
    "amazing", "among", "amount", "amused", "analyst", "anchor",
    "ancient", "anger", "angle", "angry", "animal", "ankle", "announce",
    "annual", "another", "answer", "antenna", "antique", "anxiety",
    "apart", "apology", "appear", "apple", "approve", "april", "arch",
    "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army",
    "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist",
    "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
    "attract", "auction", "audit", "august", "aunt", "author", "auto",
    "autumn", "average", "avocado", "avoid", "awake", "aware", "away",
    "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon",
    "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
    "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below",
    "belt", "bench", "benefit", "best", "betray", "better", "between",
    "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird",
    "birth", "bitter", "black", "blade", "blame", "blanket", "blast",
    "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue",
    "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone",
    "bonus", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "box", "boy", "bracket", "brain", "brand",
    "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "brilliant", "bring", "brisk", "broccoli", "broken",
    "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy",
    "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
    "bunker", "burden", "burger", "burst", "bus", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus",
    "cage", "cake", "call", "calm", "camera", "camp", "can", "canal",
    "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable",
    "capital", "captain", "car", "carbon", "card", "cargo", "carpet",
    "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat",
    "catalog", "catch", "category", "cattle", "caught", "cause",
    "caution", "cave", "ceiling", "celery", "cement", "census",
    "century", "cereal", "certain", "chair", "chalk", "champion",
    "chance", "change", "chaos", "chapter", "charge", "chase", "chat",
    "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken",
    "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle",
    "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city",
    "civil", "claim", "clap", "clarify", "claw", "clay", "clean",
    "clerk", "clever", "click", "client", "cliff", "climb", "clinic",
    "clip", "clock", "close", "cloth", "cloud", "clown", "club",
    "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee",
    "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct",
    "confirm", "connect", "consent", "consider", "control", "convert",
    "convince", "cook", "cool", "copy", "coral", "core", "corn",
    "correct", "cost", "cotton", "couch", "country", "couple", "course",
    "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram",
    "crane", "crash", "crater", "crawl", "crazy", "cream", "credit",
    "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
    "cross", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
    "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard",
    "curious", "current", "curtain", "curve", "cushion", "custom",
    "cycle", "dad", "damage", "damp", "dance", "danger", "daring",
    "dash", "daughter", "dawn", "day", "deal", "debate", "debris",
    "decade", "december", "decide", "decline", "decorate", "decrease",
    "deer", "defense", "define", "defy", "degree", "delay", "deliver",
    "demand", "demise", "denial", "dentist", "deny", "depart", "depend",
    "deposit", "depth", "deputy", "derive", "describe", "desert",
    "design", "desk", "despair", "destroy", "detail", "detect",
    "develop", "device", "devote", "diagram", "dial", "diamond",
    "diary", "dice", "diesel", "diet", "differ", "digital", "dignity",
    "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree",
    "discover", "disease", "dish", "dismiss", "disorder", "display",
    "distance", "divert", "divide", "divorce", "dizzy", "doctor",
    "document", "dog", "doll", "dolphin", "domain", "donate", "donkey",
    "donor", "door", "dose", "double", "dove", "draft", "dragon",
    "drain", "drama", "drastic", "draw", "dream", "dress", "drift",
    "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck",
    "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf",
    "dwell", "eagle", "early", "earn", "earth", "easily", "east",
    "easy", "echo", "economy", "edge", "edit", "educate", "effort",
    "egg", "eight", "either", "elbow", "elder", "electric", "elegant",
    "element", "elephant", "elevator", "elite", "else", "embark",
    "embody", "embrace", "emerge", "emotion", "employ", "empty",
    "enable", "enact", "end", "endless", "enemy", "energy", "enforce",
    "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll",
    "ensure", "enter", "entire", "entry", "envelope", "episode",
    "equal", "equip", "era", "erase", "erode", "erosion", "error",
    "erupt", "escape", "essay", "essence", "estate", "eternal",
    "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example",
    "excess", "exchange", "excite", "exclude", "excuse", "execute",
    "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic",
    "expand", "expect", "expire", "explain", "expose", "express",
    "extend", "extra", "eye", "eyebrow", "fabric", "face", "facility",
    "fact", "factor", "factory", "fade", "fail", "fair", "faith",
    "fall", "false", "fame", "family", "famous", "fan", "fancy",
    "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
    "fault", "favorite", "feature", "february", "federal", "fee",
    "feed", "feel", "female", "fence", "festival", "fetch", "fever",
    "few", "fiber", "fiction", "field", "fierce", "figure", "file",
    "fill", "film", "filter", "final", "find", "fine", "finger",
    "finish", "fire", "firm", "first", "fish", "fiscal", "fit",
    "fitness", "fix", "flag", "flame", "flash", "flat", "flavor",
    "flee", "flight", "flip", "float", "flock", "floor", "flower",
    "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold",
    "follow", "food", "foot", "force", "forest", "forget", "fork",
    "fortune", "forum", "forward", "fossil", "foster", "found", "fox",
    "fragile", "frame", "frequent", "fresh", "friend", "fringe",
    "frog", "from", "front", "frost", "frown", "frozen", "fruit",
    "fuel", "fun", "funny", "furnace", "fury", "future", "gadget",
    "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage",
    "garden", "garlic", "garment", "gas", "gasp", "gate", "gather",
    "gauge", "gaze", "gear", "gender", "gene", "general", "genius",
    "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift",
    "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory",
    "glove", "glow", "glue", "goat", "gold", "good", "goose", "gorilla",
    "gospel", "gossip", "govern", "gown", "grab", "grace", "grade",
    "gradual", "grain", "grand", "grape", "grass", "gravity", "great",
    "green", "grid", "grief", "grit", "grocery", "ground", "group",
    "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar",
    "gun", "gym", "habit", "hair", "half", "hall", "halt", "hand",
    "handle", "hang", "happen", "happy", "harbor", "hard", "harsh",
    "harvest", "hat", "have", "hawk", "hazard", "head", "health",
    "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help",
    "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire",
    "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow",
    "holy", "home", "honey", "hood", "hope", "horn", "horror",
    "horse", "hospital", "host", "hotel", "hour", "house", "hover",
    "how", "huge", "human", "humble", "humor", "hundred", "hungry",
    "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice",
    "icon", "idea", "identify", "idle", "ignore", "ill", "illegal",
    "illness", "image", "imitate", "immense", "immune", "impact",
    "impose", "improve", "impulse", "inch", "incident", "include",
    "income", "increase", "index", "indicate", "indoor", "industry",
    "infant", "inflict", "inform", "inhale", "inherit", "initial",
    "inject", "injury", "inmate", "inner", "innocent", "input",
    "inquiry", "insane", "insect", "inside", "insight", "insist",
    "inspire", "install", "intact", "interest", "into", "invest",
    "invite", "involve", "iron", "island", "isolate", "issue", "item",
    "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans",
    "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge",
    "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo",
    "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind",
    "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi",
    "knee", "knife", "knock", "knot", "know", "lab", "label", "labor",
    "ladder", "lady", "lake", "lamp", "land", "language", "large",
    "last", "late", "laugh", "laundry", "law", "lawn", "lawsuit",
    "layer", "lazy", "lead", "leaf", "league", "lean", "learn",
    "leave", "lecture", "left", "leg", "legal", "legend", "leisure",
    "lemon", "lend", "length", "lens", "leopard", "lesson", "letter",
    "level", "liar", "liberty", "library", "license", "life", "lift",
    "light", "like", "limb", "limit", "link", "lion", "liquid",
    "list", "little", "live", "lizard", "load", "loan", "lobster",
    "local", "location", "lock", "locust", "log", "lonely", "long",
    "loop", "lottery", "loud", "lounge", "love", "loyal", "luck",
    "luggage", "lumber", "lunch", "luxury", "lyrics", "machine",
    "mad", "magic", "magnet", "maid", "mail", "main", "major",
    "make", "mammal", "man", "manage", "mandate", "mango", "mansion",
    "manual", "maple", "marble", "march", "margin", "marine", "market",
    "marriage", "marsh", "master", "match", "material", "math",
    "matrix", "matter", "maximum", "mayor", "meadow", "meal", "mean",
    "measure", "meat", "mechanic", "medal", "media", "melody", "melt",
    "member", "memory", "mention", "menu", "mercy", "merge", "merit",
    "merry", "mesh", "message", "metal", "method", "middle", "midnight",
    "milk", "million", "mimic", "mind", "minimum", "minister", "minor",
    "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix",
    "mixed", "mixture", "mobile", "model", "modify", "mom", "moment",
    "monitor", "monkey", "month", "moon", "moral", "more", "morning",
    "mosquito", "mother", "motion", "motor", "mountain", "mouse",
    "move", "movie", "much", "muffin", "mule", "multiply", "muscle",
    "museum", "mushroom", "music", "must", "mutual", "myself",
    "mystery", "myth", "naive", "name", "napkin", "narrow", "nation",
    "nature", "near", "neck", "need", "negative", "neglect", "neither",
    "nephew", "nerve", "nest", "net", "network", "neutral", "never",
    "news", "next", "nice", "niece", "night", "nine", "noble", "node",
    "noise", "nominee", "noodle", "noon", "normal", "north", "nose",
    "notable", "note", "nothing", "notice", "novel", "now", "nuclear",
    "number", "nurse", "nut", "oak", "obey", "object", "oblige",
    "obscure", "observe", "obtain", "obvious", "ocean", "october",
    "odor", "off", "offer", "office", "often", "oil", "okay", "old",
    "olive", "olympic", "omit", "once", "one", "onion", "only", "open",
    "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard",
    "order", "ordinary", "organ", "orient", "original", "orphan",
    "ostrich", "other", "outdoor", "outer", "output", "outside",
    "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone",
    "pact", "paddle", "page", "pain", "paint", "pair", "palace",
    "palm", "panda", "panel", "panic", "panther", "paper", "parade",
    "parent", "park", "parrot", "party", "pass", "patch", "path",
    "patient", "patrol", "pattern", "pause", "pave", "payment", "peace",
    "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil",
    "people", "pepper", "perfect", "permit", "person", "pet", "phone",
    "photo", "phrase", "physical", "piano", "picnic", "picture", "piece",
    "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe",
    "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate",
    "play", "please", "pledge", "pluck", "plug", "plunge", "poem",
    "poet", "point", "polar", "pole", "police", "polish", "polite",
    "poll", "polyester", "pond", "pony", "pool", "popular", "portion",
    "position", "possible", "post", "potato", "pottery", "poverty",
    "powder", "power", "practice", "praise", "predict", "prefer",
    "prepare", "present", "pretty", "prevent", "price", "pride",
    "primary", "print", "priority", "prison", "private", "prize",
    "problem", "process", "produce", "profit", "program", "project",
    "promote", "proof", "property", "prosper", "protect", "proud",
    "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin",
    "punch", "pupil", "puppy", "purchase", "purity", "purpose",
    "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum",
    "quarter", "queen", "question", "quick", "quiet", "quilt", "quit",
    "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar",
    "radio", "raft", "rage", "raid", "rail", "rain", "raise", "rally",
    "ramp", "ranch", "random", "range", "rapid", "rare", "rate",
    "rather", "raven", "raw", "razor", "ready", "real", "reason",
    "rebel", "rebuild", "recall", "receive", "recipe", "record",
    "recycle", "reduce", "refer", "reflect", "reform", "refuse",
    "region", "regret", "regular", "reject", "relax", "release",
    "relief", "rely", "remain", "remember", "remind", "remove",
    "render", "renew", "rent", "reopen", "repair", "repeat", "replace",
    "report", "require", "rescue", "resemble", "resist", "resource",
    "response", "result", "retire", "retreat", "return", "reunion",
    "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice",
    "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot",
    "ripple", "risk", "ritual", "rival", "river", "road", "roast",
    "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
    "rose", "rotate", "rough", "round", "route", "royal", "rubber",
    "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle",
    "sadness", "safe", "sail", "salad", "salmon", "salon", "salt",
    "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce",
    "sausage", "save", "say", "scale", "scan", "scare", "scatter",
    "scene", "scheme", "school", "science", "scissors", "scorpion",
    "scout", "scrap", "screen", "script", "scrub", "sea", "search",
    "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "seem", "segment", "select", "sell", "seminar", "senior",
    "sense", "sentence", "series", "service", "session", "settle",
    "setup", "seven", "shadow", "shaft", "shallow", "share", "shark",
    "sharp", "shave", "sheep", "sheet", "shelf", "shell", "shelter",
    "shield", "shift", "shine", "ship", "shiver", "shock", "shoe",
    "shoot", "shop", "short", "shoulder", "shout", "show", "shrimp",
    "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege",
    "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "six",
    "size", "skate", "sketch", "ski", "skill", "skin", "skirt",
    "skull", "sky", "slab", "slam", "sleep", "slice", "slide", "slim",
    "slip", "slogan", "slope", "slow", "slush", "small", "smart",
    "smash", "smell", "smile", "smoke", "smooth", "snack", "snake",
    "snap", "sniff", "snow", "soap", "soccer", "social", "sock",
    "soda", "sofa", "soft", "solar", "soldier", "solid", "solution",
    "solve", "someone", "song", "soon", "sorry", "sort", "soul",
    "sound", "soup", "source", "south", "space", "spare", "spark",
    "speak", "special", "speech", "speed", "spell", "spend", "sphere",
    "spice", "spider", "spike", "spill", "spin", "spirit", "split",
    "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread",
    "spring", "spy", "square", "squeeze", "squirrel", "stable",
    "stadium", "staff", "stage", "stair", "stamp", "stand", "star",
    "stare", "start", "state", "stay", "steak", "steel", "stem",
    "step", "stereo", "steward", "stick", "still", "sting", "stock",
    "stomach", "stone", "stool", "story", "stove", "strategy",
    "street", "strike", "strong", "struggle", "student", "stuff",
    "stumble", "style", "subject", "submit", "subway", "success",
    "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer",
    "sun", "super", "supply", "supreme", "sure", "surface", "surge",
    "surprise", "surround", "survey", "suspect", "sustain", "swallow",
    "swamp", "swan", "swarm", "swear", "sweat", "sweep", "sweet",
    "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup",
    "system", "table", "tackle", "tag", "tail", "talent", "talk",
    "tank", "tape", "target", "task", "taste", "tattoo", "taxi",
    "teach", "team", "tear", "tease", "teenager", "teeth", "tell",
    "temper", "temple", "tempo", "tend", "tennis", "tent", "term",
    "test", "text", "thank", "that", "theme", "then", "theory",
    "there", "they", "thick", "thief", "thigh", "thing", "think",
    "third", "thirst", "thirteen", "thirty", "this", "thorn", "those",
    "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket",
    "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired",
    "tissue", "title", "toast", "tobacco", "today", "toe", "together",
    "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight",
    "tool", "tooth", "top", "topic", "topple", "torch", "tornado",
    "tortoise", "toss", "total", "toucan", "touch", "tough", "tour",
    "tourist", "toward", "tower", "town", "toy", "track", "trade",
    "traffic", "tragic", "train", "trait", "transfer", "trap", "trash",
    "travel", "tray", "treat", "tree", "trend", "trial", "tribe",
    "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck",
    "true", "trumpet", "trunk", "trust", "truth", "try", "tube",
    "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle",
    "twelve", "twenty", "twice", "twin", "twist", "two", "type",
    "typical", "ugly", "umbrella", "unable", "unaware", "uncle",
    "uncover", "under", "undo", "unfair", "unfold", "unhappy",
    "uniform", "unique", "unit", "universe", "unknown", "unlock",
    "until", "unusual", "unveil", "update", "upgrade", "uphold",
    "upon", "upper", "upset", "urban", "urge", "usage", "use", "used",
    "useful", "useless", "usual", "utility", "vacant", "vacuum",
    "vague", "valid", "valley", "valve", "van", "vanish", "vapor",
    "vast", "vault", "vegetable", "vehicle", "velvet", "vendor",
    "venture", "verb", "verify", "version", "very", "vessel", "veteran",
    "viable", "vibrant", "vicious", "victory", "video", "view",
    "village", "vintage", "violin", "virtual", "virus", "visa",
    "visit", "visual", "vital", "vivid", "vocal", "voice", "volcano",
    "volume", "vote", "voyage", "wage", "wagon", "waist", "wait",
    "walk", "wall", "walnut", "want", "war", "warm", "warrior", "wash",
    "wasp", "waste", "watch", "water", "wave", "way", "wealth", "weapon",
    "wear", "weasel", "weather", "web", "wedding", "weekend", "weird",
    "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when",
    "where", "whip", "whisper", "whistle", "white", "who", "whole",
    "why", "wide", "width", "wife", "wild", "will", "win", "window",
    "wine", "wing", "wink", "winner", "winter", "wire", "wisdom",
    "wise", "wish", "witness", "wolf", "woman", "wonder", "wood",
    "wool", "word", "work", "world", "worm", "worry", "worth", "wound",
    "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard",
    "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone",
    "zoo",
})

_BIP39_RE = re.compile(
    r"\b(?:" + "|".join(sorted(_BIP39_WORDS, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)

_SWIFT_RE = re.compile(
    r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b"
)


# ── Kategorie B: DSGVO Art. 9 + Identität ────────────────────────────────

# EU VAT-ID (broad fallback): 2-letter country code + 9-12 alphanumeric chars.
# Moved here from regex_detector.py so it takes priority over the overly-broad
# fuehrerschein_de regex, which would otherwise shadow ATU12345678 etc.
_VAT_EU_COUNTRIES: frozenset[str] = frozenset({
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES",
    "FI", "FR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT",
    "NL", "PL", "PT", "RO", "SE", "SI", "SK",
})
_VAT_EU_RE = re.compile(r"\b[A-Z]{2}[A-Z0-9]{9,12}\b")

# DE Sozialversicherungsnummer (Rentenversicherung): 12 123456 A 123
_SVNR_DE_RE = re.compile(
    r"\b\d{2}\s?\d{6}\s?[A-Z]\s?\d{3}\b"
)

# Personalausweis (neu, seit 2010): z.B. L01X00T47
_PERSONALAUSWEIS_NEU_RE = re.compile(r"\b[A-Z]\d{2}[A-Z0-9]{6,7}\b")

# Führerschein (DE): meist 11 Stellen, variiert nach Bundesland
_FUEHRERSCHEIN_DE_RE = re.compile(
    r"\b[A-Z]{2,3}\s?\d{2}\s?\d{4}\s?\d{2,4}\b"
)

# Reisepass (international): 6-9 alphanumerisch, meist im Pass-/Visum-Kontext
_REISEPASS_RE = re.compile(r"\b[A-Z0-9]{6,9}\b")
_REISEPASS_KEYWORDS_RE = re.compile(
    r"Reisepass|Passnummer|Pass-Nr|Visum|Visa?", re.IGNORECASE
)

# Krankenversicherungsnummer (DE) / Allgemein
_KVNR_DE_RE = re.compile(r"\b[A-Z]\d{9}\b")

# Gesundheitsdaten-Kontext (Diagnose, Medikament, Blutdruck, Allergie, ...)
_HEALTH_CONTEXT_RE = re.compile(
    r"(?i)(?:diagnose|medikament|blutdruck|allergie|impfung|therapie|"
    r"krankheit|beschwerde|beschwerden|symptom|ärztlich|arzt|klinik|"
    r"krankenhaus|krankenkasse|versicherung)\s*[:\-]\s*\S+",
)

# DSGVO Art. 9 politisch/religiös/sexuell
_SENSITIVE_CONTEXT_RE = re.compile(
    r"(?i)(?:parteimitgliedschaft|religion|konfession|sexuelle\s+orientierung|"
    r"rassische|ethnische|gewerkschaft)\s*[:\-]?\s*\S+",
)

# Cookie-ID / Session-Token: requires a key=value prefix so that JWTs and
# other long alphanumeric secrets are not misclassified as cookies.
# Confidence: LOW — high false-positive rate, detection only (not auto-masked)
#
# Recognised key prefixes: ``session_id``, ``session-id``, ``sessionid``,
# ``session=`` (HTTP Set-Cookie style), ``sid``, ``cookie``, ``auth_token``,
# ``auth-token``, ``authtoken``, ``jwt_id`` (used by some gateways), or a
# ``Set-Cookie: <name>=`` HTTP header.
_COOKIE_ID_RE = re.compile(
    r"(?<![A-Za-z0-9_.])"
    r"(?:Set-Cookie\s*:\s*)?"
    r"(?:session(?:[_-]?id)?|sid|cookie|auth(?:[_-]?token)?|jwt(?:[_-]?id)?)"
    r"\s*=\s*"
    r"([A-Za-z0-9_+\-/.=]{16,128})"
    r"(?![A-Za-z0-9_.])",
    re.IGNORECASE,
)


# ── Kategorie C: Auth & API-Schlüssel ─────────────────────────────────────

# JWT (JSON Web Token): 3 dot-separated base64url segments, header MUST start
# with the base64url-encoded literal ``{"`` (i.e. ``eyJ``) so we don't catch
# arbitrary 3-segment alphanumeric blobs.
#
# FIX-5: the middle and last segments accept ``.`` and ``=`` chars as well
# (in addition to base64url), so elided/truncated JWTs like
# ``eyJhbG...wIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`` (where ``...``
# is a placeholder) still match — without that, the cookie_id pattern would
# win on the 32+ char signature segment and misclassify the whole token.
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_+\-/=]+\.[A-Za-z0-9_+\-/.=]+\.[A-Za-z0-9_+\-/.=]+\b"
)

# Generischer API-Key/Secret/Token
#
# Strukturhinweis (FIX-4C): Prefix (api_key/secret/token/...) ist non-capturing,
# der Wert (group 1) ist die einzige Capture-Gruppe.  scan()/scan_types()
# bevorzugen group(1) wenn vorhanden, sodass m.group(0) == m.group(1) ist und
# nur der reine Schluesselwert pseudonymisiert wird (kein Label-Leak in
# JSON/YAML-Strukturen).
#
# Char-Klasse enthaelt + / = um base64-/JWT-Fragmente zu erkennen.
_API_KEY_GENERIC_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|apikey|auth)\s*[:=]\s*['\"]?"
    r"([a-zA-Z0-9_\-+/=]{16,})['\"]?"
)

# Private Key (PEM / SSH)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN\s+(?:OPENSSH\s+)?(?:RSA\s+|EC\s+|DSA\s+)?(?:PRIVATE\s+)?KEY-----"
)

# OAuth-Tokens (Google, GitHub, Azure)
_GOOGLE_OAUTH_RE = re.compile(r"\bya29\.[a-zA-Z0-9_-]+\b")
_GITHUB_OAUTH_RE = re.compile(r"\bgho_[a-zA-Z0-9]{36}\b")
_AZURE_SAS_RE = re.compile(
    r"\bsv=\d{4}-\d{2}-\d{2}&sr=[bc]&sig=[a-zA-Z0-9%]{40,}\b"
)

# DB-URL mit Credentials
_DATABASE_URL_RE = re.compile(
    r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s:]+:[^\s@]+@[^\s/]+/\S*\b",
    re.IGNORECASE,
)

# Authorization Bearer
_AUTH_BEARER_RE = re.compile(
    r"(?i)bearer\s+[a-zA-Z0-9_\-]{20,}"
)


# ── Kategorie D: Geräte & Netzwerk ────────────────────────────────────────

_MAC_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
)

_IMEI_RE = re.compile(
    r"(?i)\b(?:IMEI|Seriennummer)[:\s]+\d{2}\s*[-]?\s*\d{6}\s*[-]?\s*\d{6}\s*[-]?\s*\d\b"
)

_IMSI_RE = re.compile(
    r"\b\d{15}\b"
)

_GPS_RE = re.compile(
    r"\b-?\d{1,3}\.\d{4,8}°?\s*[NS]?[,\s]+-?\d{1,3}\.\d{4,8}°?\s*[EW]?\b"
)

_WLAN_SSID_RE = re.compile(
    r"(?i)SSID\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{2,32})['\"]?"
)


# ── Kategorie E: Organisatorisch ───────────────────────────────────────────

_HRB_RE = re.compile(
    r"\b(?:HRB|HRA|VR|PR|GnR)\s*\d{1,6}\b",
    re.IGNORECASE,
)

# DE Steuernummer alt: z.B. 123/456/78901 oder 123 456 7890 1
_STEUERNUMMER_ALT_RE = re.compile(
    r"\b\d{2,3}[\s/\-]+\d{2,3}[\s/\-]+\d{4,5}\b"
)

# Mitarbeiter-ID
_MA_ID_RE = re.compile(
    r"\b(?:MA|EMP|Mitarbeiter)[\-\s]?\d{3,}\b",
    re.IGNORECASE,
)


# ── Kategorie F: Moderne Daten-Lecks ───────────────────────────────────────

_DISCORD_WEBHOOK_RE = re.compile(
    r"https?://(?:discord(?:app)?)\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"
)

_TELEGRAM_BOT_RE = re.compile(
    r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b"
)

_SLACK_WEBHOOK_RE = re.compile(
    r"https?://hooks\.slack\.com/services/[A-Z0-9/]+"
)

_GOOGLE_API_RE = re.compile(
    r"\bAIza[0-9A-Za-z_-]{35}\b"
)

# Stripe-Familie: live (geheim), test (öffentlich), public (pk), restricted (rk),
# webhook-secret (whsec). Mindestlänge 8 Zeichen nach dem Prefix — die realen
# Stripe-Schlüssel sind alle >= 24 Zeichen, aber die Schwellwert-Senkung von
# 20 auf 8 ermöglicht die Erkennung gekürzter/teilmaskierter Beispiele im
# Red-Team-Harness (Combined Red-Team 2026-08-22, GAP-001 / D-08).
_STRIPE_LIVE_RE = re.compile(
    r"\bsk_live_[a-zA-Z0-9]{8,}\b"
)
_STRIPE_TEST_RE = re.compile(
    r"\bsk_test_[a-zA-Z0-9]{8,}\b"
)
_STRIPE_PUBLIC_RE = re.compile(
    r"\bpk_live_[a-zA-Z0-9]{8,}\b"
)
_STRIPE_RESTRICTED_RE = re.compile(
    r"\brk_live_[a-zA-Z0-9]{8,}\b"
)
_STRIPE_WEBHOOK_SECRET_RE = re.compile(
    r"\bwhsec_[a-zA-Z0-9]{8,}\b"
)

_AWS_ACCESS_KEY_RE = re.compile(
    r"\bAKIA[0-9A-Z]{16}\b"
)

# GitHub PAT (classic). 30+ nach Prefix; reale PATs sind genau 36 Zeichen.
_GITHUB_PAT_RE = re.compile(
    r"\bghp_[a-zA-Z0-9]{30,}\b"
)
# GitHub fine-grained PAT: github_pat_ + 22 alnum/_ (GAP-001)
_GITHUB_FINE_GRAINED_PAT_RE = re.compile(
    r"\bgithub_pat_[a-zA-Z0-9_]{22,}\b"
)

# NPM-Token: exakt 36 Zeichen nach Prefix (GAP-001 — Mindestlänge 36 bleibt).
_NPM_TOKEN_RE = re.compile(
    r"\bnpm_[a-zA-Z0-9]{36}\b"
)

# Slack-Tokens (User/Bot/App/Patreon/Refresh): xox[bpars]- (GAP-001 —
# injection-shield hatte das schon, privacy-shield fehlte diese Vendor-Familie.)
# Mindestlänge 10 Zeichen nach Prefix wie in injection-shield/credential_leak.py.
_SLACK_TOKEN_RE = re.compile(
    r"\bxox[bpars]-[a-zA-Z0-9-]{10,}\b"
)

_PYPI_TOKEN_RE = re.compile(
    r"\bpypi-[A-Za-z0-9_-]+\b"
)

_DOCKER_HUB_PAT_RE = re.compile(
    r"\bdckr_pat_[a-zA-Z0-9_-]{40,}\b"
)

_HEROKU_API_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
)


# ── Kategorie G: Kontextuelle Erkennung ───────────────────────────────────

_BIRTHDAY_CONTEXT_RE = re.compile(
    r"(?i)(?:geboren|geburtstag|geb\.?)\s*(?:am\s+)?"
    r"(\d{1,2}[./-]\d{1,2}[./-]\d{2,4})"
)

_DEATH_CONTEXT_RE = re.compile(
    r"(?i)(?:gestorben|verstorben|todestag)\s*(?:am\s+)?"
    r"(\d{1,2}[./-]\d{1,2}[./-]\d{2,4})"
)

_FAMILY_CONTEXT_RE = re.compile(
    r"(?i)(?:verheiratet|geschieden|getrennt|verlobt)\s+(?:mit|von|von\s+der|mit\s+der)\s+"
    r"([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)"
)

_NATIONALITY_CONTEXT_RE = re.compile(
    r"(?i)(?:staatsangehörigkeit|nationalität|staatsbürgerschaft)\s*[:\-]?\s*"
    r"([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)"
)

_JOB_CONTEXT_RE = re.compile(
    r"(?i)(?:arbeitet\s+(?:bei|als)|ist\s+CEO\s+von|ist\s+geschäftsführer\s+(?:von|bei)|"
    r"beruf\s*[:\-]?\s*|arbeitgeber\s*[:\-]?\s*)"
    r"([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ]?[a-zäöüß]+){0,4})"
)

_SALARY_CONTEXT_RE = re.compile(
    r"(?i)(?:gehalt|verdienst|einkommen|salary|brutto|netto)\s*[:\-]?\s*"
    r"[€$]?\s*\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?"
)

_DEBT_CONTEXT_RE = re.compile(
    r"(?i)(?:schulden|kredit|darlehen|hypothek)\s*[:\-]?\s*"
    r"[€$]?\s*\d{1,3}(?:[.,]\d{3})*"
)


# ── Public API ───────────────────────────────────────────────────────────

BASE_EXTENDED_PATTERNS: list[CompiledPattern] = [
    # A: Financial
    CompiledPattern("crypto_btc", _BTC_RE),
    CompiledPattern("crypto_eth", _ETH_RE),
    CompiledPattern("swift_code", _SWIFT_RE),
    # B: DSGVO Art. 9 / identity
    CompiledPattern("svnr_de", _SVNR_DE_RE),
    CompiledPattern("personalausweis", _PERSONALAUSWEIS_NEU_RE),
    # Broad EU VAT fallback — must come BEFORE fuehrerschein_de so values like
    # ATU12345678 are typed as VAT and not as a DE driver's license.
    CompiledPattern("vat_id_eu", _VAT_EU_RE),
    CompiledPattern("fuehrerschein_de", _FUEHRERSCHEIN_DE_RE),
    CompiledPattern("kvnr_de", _KVNR_DE_RE),
    CompiledPattern("health_context", _HEALTH_CONTEXT_RE, confidence=0.5),
    CompiledPattern("sensitive_context", _SENSITIVE_CONTEXT_RE, confidence=0.5),
    # Cookie / session token: requires a key=value prefix (session_id=,
    # sid=, Set-Cookie: session=…) so JWTs and other long alphanumeric
    # secrets are not misclassified as cookies. value_group=1 so the
    # prefix is preserved in masked output (FIX-4C parity with api_key).
    CompiledPattern("cookie_id", _COOKIE_ID_RE, confidence=0.5, value_group=1),
    # C: Auth
    CompiledPattern("jwt", _JWT_RE),
    CompiledPattern("api_key", _API_KEY_GENERIC_RE, value_group=1),
    CompiledPattern("private_key", _PRIVATE_KEY_RE),
    CompiledPattern("google_oauth", _GOOGLE_OAUTH_RE),
    CompiledPattern("github_oauth", _GITHUB_OAUTH_RE),
    CompiledPattern("azure_sas", _AZURE_SAS_RE),
    CompiledPattern("database_url", _DATABASE_URL_RE),
    CompiledPattern("auth_bearer", _AUTH_BEARER_RE),
    # D: Device / network
    CompiledPattern("mac_address", _MAC_RE),
    CompiledPattern("imei", _IMEI_RE),
    CompiledPattern("imsi", _IMSI_RE),
    CompiledPattern("gps", _GPS_RE, confidence=0.7),
    CompiledPattern("wlan_ssid", _WLAN_SSID_RE),
    # E: Organisational
    CompiledPattern("handelsregisternummer", _HRB_RE),
    CompiledPattern("steuernummer_alt", _STEUERNUMMER_ALT_RE),
    CompiledPattern("mitarbeiter_id", _MA_ID_RE),
    # F: Modern leaks
    CompiledPattern("discord_webhook", _DISCORD_WEBHOOK_RE),
    CompiledPattern("telegram_bot_token", _TELEGRAM_BOT_RE),
    CompiledPattern("slack_webhook", _SLACK_WEBHOOK_RE),
    CompiledPattern("google_api_key", _GOOGLE_API_RE),
    # Stripe-Familie (GAP-001 / D-08): sk_live + sk_test + pk_live + rk_live + whsec.
    CompiledPattern("stripe_live_key", _STRIPE_LIVE_RE),
    CompiledPattern("stripe_test_key", _STRIPE_TEST_RE),
    CompiledPattern("stripe_public_key", _STRIPE_PUBLIC_RE),
    CompiledPattern("stripe_restricted_key", _STRIPE_RESTRICTED_RE),
    CompiledPattern("stripe_webhook_secret", _STRIPE_WEBHOOK_SECRET_RE),
    CompiledPattern("aws_access_key", _AWS_ACCESS_KEY_RE),
    CompiledPattern("github_pat", _GITHUB_PAT_RE),
    CompiledPattern("github_fine_grained_pat", _GITHUB_FINE_GRAINED_PAT_RE),
    CompiledPattern("npm_token", _NPM_TOKEN_RE),
    CompiledPattern("slack_token", _SLACK_TOKEN_RE),
    CompiledPattern("pypi_token", _PYPI_TOKEN_RE),
    CompiledPattern("docker_hub_pat", _DOCKER_HUB_PAT_RE),
    CompiledPattern("heroku_api_key", _HEROKU_API_RE),
    # G: Contextual
    CompiledPattern("birthday_context", _BIRTHDAY_CONTEXT_RE, confidence=0.5),
    CompiledPattern("death_context", _DEATH_CONTEXT_RE, confidence=0.5),
    CompiledPattern("family_context", _FAMILY_CONTEXT_RE, confidence=0.5),
    CompiledPattern("nationality_context", _NATIONALITY_CONTEXT_RE, confidence=0.5),
    CompiledPattern("job_context", _JOB_CONTEXT_RE, confidence=0.5),
    CompiledPattern("salary_context", _SALARY_CONTEXT_RE, confidence=0.5),
    CompiledPattern("debt_context", _DEBT_CONTEXT_RE, confidence=0.5),
]


def count_bip39_words(text: str) -> int:
    """Return how many BIP39 words appear in ``text``.

    Used to flag potential seed phrases without running an expensive full
    word-list scan on every input.
    """
    return sum(1 for _ in _BIP39_RE.finditer(text))


def is_seed_phrase(text: str, min_words: int = 12) -> bool:
    """Heuristic: at least ``min_words`` BIP39 dictionary words in a row.

    A real BIP39 seed phrase is exactly 12 or 24 words. We require at least
    ``min_words`` consecutive BIP39 words separated only by whitespace.
    """
    if not text:
        return False
    # Split the text into runs of words; count consecutive BIP39 matches
    tokens = re.split(r"[^A-Za-z]+", text)
    consecutive = 0
    for tok in tokens:
        if tok.lower() in _BIP39_WORDS:
            consecutive += 1
            if consecutive >= min_words:
                return True
        else:
            consecutive = 0
    return False


def has_passport_context(text: str, start: int, end: int, window: int = _PASSPORT_CONTEXT_WINDOW) -> bool:
    """Check if passport/Reisepass keywords exist near the match span."""
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    return bool(_REISEPASS_KEYWORDS_RE.search(text[ctx_start:ctx_end]))
