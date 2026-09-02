"""Every user-facing name and URL, in one place.

The site header, the browser title, the social card, the README banner and the
GitHub About box all have to say the same thing. When they disagree Google picks
its own site name, and mentions stop compounding into one brand. Change a string
here and every generated surface follows.
"""

BRAND = "PoC Index"
# Short line under the wordmark, on the site and on both cards.
SUBTITLE = "Public proof-of-concept exploits, indexed by CVE."
TITLE = f"{BRAND}: Search CVE Proof-of-Concept Exploits"
# og:description and twitter:description. Shorter than DESCRIPTION because a
# social card truncates far earlier than a search result does.
SOCIAL_DESCRIPTION = (
    f"{SUBTITLE} Searchable, refreshed hourly, no signup."
)
DESCRIPTION = (
    "Search 82,000+ public CVE proof-of-concept exploits from GitHub, Nuclei, "
    "ExploitDB, Metasploit and Vulhub. Updated hourly. Free JSON API, no signup."
)
# Shown under the GitHub About box and in search results for the repository.
# Deliberately unlike the upstream wording: the forks carry the old description
# verbatim, so a generic line ranks the copies alongside the original. Kept under
# 150 characters because GitHub truncates listings around there.
REPO_DESCRIPTION = (
    "Search 82,000+ public CVE proof-of-concept exploits from GitHub, Nuclei, "
    "ExploitDB, Metasploit and Vulhub. Updated hourly. Plain JSON, no key."
)

# Flip to https://pocindex.io only after DNS resolves and GitHub Pages has issued
# the certificate. A canonical pointing at a host that does not answer yet drops
# the page out of the index, so this trails the DNS cutover, it does not lead it.
SITE = "https://pocindex.io"
SLUG = "0xMarcio/pocindex"


def host() -> str:
    """SITE without the scheme, for the places that display a bare domain."""
    return SITE.split("://", 1)[-1].rstrip("/")
