"""Every user-facing name and URL, in one place.

The site header, the browser title, the social card, the README banner and the
GitHub About box all have to say the same thing. When they disagree Google picks
its own site name, and mentions stop compounding into one brand. Change a string
here and every generated surface follows.
"""

BRAND = "PoC Index"
TITLE = f"{BRAND}: Search CVE Proof-of-Concept Exploits"
# Short line under the wordmark, on the site and on both cards. Also carries
# og:description and twitter:description.
SUBTITLE = "Public proof-of-concept exploits, indexed by CVE."
# Meta description, the JSON-LD description and the GitHub About box, which are
# three places a reader meets the same sentence and so should be one string.
# States what the thing is and stops. No trailing feature list.
DESCRIPTION = (
    "Search 82,000+ public CVE proof-of-concept exploits from GitHub, Nuclei, "
    "ExploitDB, Metasploit and Vulhub."
)

SITE = "https://pocindex.io"
SLUG = "0xMarcio/pocindex"


def host() -> str:
    """SITE without the scheme, for the places that display a bare domain."""
    return SITE.split("://", 1)[-1].rstrip("/")
