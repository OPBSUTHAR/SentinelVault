"""Secure password & passphrase generation (CSPRNG via `secrets`)."""
from __future__ import annotations

import secrets
import string

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("Il1O0o")

WORDLIST = [
    "amber", "anchor", "apple", "arrow", "atlas", "azure", "badge", "bamboo",
    "beacon", "birch", "bison", "blaze", "bloom", "breeze", "bridge", "bronze",
    "cabin", "cactus", "candle", "canoe", "canyon", "cedar", "cello", "cherry",
    "cipher", "citrus", "cliff", "cloud", "clover", "cobalt", "comet", "coral",
    "cosmos", "cotton", "crater", "crimson", "crystal", "cyclone", "dagger",
    "dawn", "delta", "denim", "desert", "dolphin", "dragon", "dune", "eagle",
    "echo", "ember", "emerald", "falcon", "fern", "fjord", "flame", "flint",
    "forest", "fossil", "frost", "galaxy", "garnet", "geyser", "glacier",
    "glade", "granite", "grove", "harbor", "hawk", "hazel", "heron", "hickory",
    "hollow", "horizon", "indigo", "iris", "island", "ivory", "jade", "jasper",
    "jungle", "juniper", "kestrel", "koala", "lagoon", "lantern", "larch",
    "lava", "leaf", "lily", "lizard", "lobster", "lunar", "lynx", "magnet",
    "mango", "maple", "marble", "meadow", "mesa", "meteor", "mint", "mist",
    "monsoon", "moss", "mountain", "nebula", "nectar", "nova", "oasis",
    "ocean", "olive", "onyx", "orchid", "otter", "owl", "palm", "panda",
    "pebble", "pelican", "penguin", "pepper", "petal", "phoenix", "pilot",
    "pine", "plasma", "plateau", "plum", "polar", "pond", "poppy", "prairie",
    "prism", "puffin", "quartz", "quill", "raven", "reef", "ridge", "river",
    "robin", "rocket", "rose", "ruby", "saffron", "sage", "salmon", "sand",
    "sapphire", "savanna", "scarlet", "shadow", "shore", "silver", "sketch",
    "sky", "slate", "snow", "sparrow", "spruce", "storm", "summit", "sunset",
    "swan", "tango", "teal", "tempest", "thistle", "thunder", "tiger",
    "timber", "topaz", "torrent", "trail", "tulip", "tundra", "turtle",
    "twilight", "valley", "velvet", "vertex", "violet", "viper", "vista",
    "volcano", "walrus", "willow", "wind", "wolf", "wren", "yarrow", "zephyr",
]

POLICIES = {
    "basic":    {"length": 12, "upper": True, "lower": True, "digits": True, "symbols": False},
    "strong":   {"length": 16, "upper": True, "lower": True, "digits": True, "symbols": True},
    "paranoid": {"length": 24, "upper": True, "lower": True, "digits": True, "symbols": True},
    "pin":      {"length": 6,  "upper": False, "lower": False, "digits": True, "symbols": False},
    "passphrase": {"words": 4, "separator": "-", "capitalize": True, "add_number": True},
}


def generate(
    length: int = 16,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    pools = []
    if lower:
        pools.append([c for c in LOWER if not (avoid_ambiguous and c in AMBIGUOUS)])
    if upper:
        pools.append([c for c in UPPER if not (avoid_ambiguous and c in AMBIGUOUS)])
    if digits:
        pools.append([c for c in DIGITS if not (avoid_ambiguous and c in AMBIGUOUS)])
    if symbols:
        pools.append(list(SYMBOLS))
    if not pools:
        pools = [list(LOWER)]

    length = max(4, min(int(length), 128))
    chars = [secrets.choice(pool) for pool in pools]           # guarantee each class
    all_chars = [c for pool in pools for c in pool]
    while len(chars) < length:
        chars.append(secrets.choice(all_chars))
    # Fisher–Yates shuffle with CSPRNG
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars[:length])


def passphrase(words: int = 4, separator: str = "-", capitalize: bool = True, add_number: bool = True) -> str:
    words = max(3, min(int(words), 8))
    chosen = [secrets.choice(WORDLIST) for _ in range(words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    if add_number:
        phrase += separator + str(secrets.randbelow(90) + 10)
    return phrase


def generate_with_policy(policy: str) -> str:
    spec = POLICIES.get(policy, POLICIES["strong"])
    if policy == "passphrase":
        return passphrase(spec["words"], spec["separator"], spec["capitalize"], spec["add_number"])
    return generate(
        spec["length"], spec["upper"], spec["lower"], spec["digits"], spec["symbols"]
    )
