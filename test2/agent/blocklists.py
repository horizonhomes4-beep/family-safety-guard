"""Category blocklists and site classification for the ParentGuard agent."""
import re

ADULT = set("""pornhub.com xvideos.com xnxx.com xhamster.com xhamster2.com redtube.com youporn.com tube8.com spankbang.com eporner.com tnaflix.com porntrex.com beeg.com motherless.com
fapello.com fansly.com onlyfans.com chaturbate.com stripchat.com bongacams.com livejasmin.com cam4.com myfreecams.com camsoda.com brazzers.com realitykings.com bangbros.com
naughtyamerica.com nhentai.net hentaihaven.xxx rule34.xxx e-hentai.org gelbooru.com thumbzilla.com porn.com sex.com hqporner.com 4tube.com txxx.com hclips.com vporn.com daftsex.com
erome.com literotica.com adultfriendfinder.com ashleymadison.com xvideos2.com xnxx2.com pornone.com sunporno.com drtuber.com porndig.com pornhat.com fuq.com ixxx.com""".split())

GAMBLING = set("""bet365.com betway.com 1xbet.com 1xbet.ng sportybet.com bet9ja.com nairabet.com betking.com msport.com merrybet.com betano.com williamhill.com paddypower.com ladbrokes.com
betfair.com bwin.com unibet.com 888casino.com 888.com pokerstars.com partypoker.com draftkings.com fanduel.com stake.com stake.us bovada.lv betonline.ag 22bet.com melbet.com mostbet.com
parimatch.com betwinner.com 1win.com linebet.com pin-up.casino betsson.com leovegas.com casumo.com betmgm.com accessbet.com livescorebet.com 1xbit.com bc.game roobet.com
rollbit.com gamdom.com bet-at-home.com betclic.com sportingbet.com 10bet.com betvictor.com skybet.com spinpalace.com jackpotcity.co.za hollywoodbets.net supabets.co.za""".split())

SOCIAL = set("""facebook.com fb.com fb.me messenger.com instagram.com tiktok.com snapchat.com twitter.com x.com threads.net reddit.com discord.com discord.gg pinterest.com tumblr.com
telegram.org t.me omegle.com likee.video bigo.tv kwai.com""".split())

PROXY = set("""nordvpn.com expressvpn.com protonvpn.com surfshark.com cyberghostvpn.com hide.me windscribe.com tunnelbear.com hotspotshield.com privateinternetaccess.com mullvad.net
purevpn.com ipvanish.com vyprvpn.com torproject.org psiphon.ca hidemyass.com hidester.com proxysite.com croxyproxy.com kproxy.com whoer.net vpnbook.com zenmate.com betternet.co
urban-vpn.com ultrasurf.us dns.google cloudflare-dns.com mozilla.cloudflare-dns.com dns.quad9.net doh.opendns.com dns.nextdns.io dns.adguard.com""".split())

CATEGORY_DOMAINS = {"adult": ADULT, "gambling": GAMBLING, "social": SOCIAL, "proxy": PROXY}

# Keyword rules catch sites that are not on the lists. Kept specific to avoid false positives.
KEYWORDS = {
    "adult": re.compile(r"(porn|xxx|hentai|xvideos|xnxx|nsfw|camgirl|livesex|sexcam|erotic|fetish|redtube|youporn|onlyfans)"),
    "gambling": re.compile(r"(casino|sportsbook|sportybet|bet9ja|nairabet|betking|1xbet|bet365|betway|poker|jackpot|gambl|lottery|lotto|bookmaker|slotmachine|betting)"),
    "proxy": re.compile(r"(^|[.-])(vpn|proxy|unblock)([.-]|$)"),
}

# Infrastructure that is not a site the child chose to visit. Hidden by default in the dashboard.
BACKGROUND = tuple("""microsoft.com windows.com windowsupdate.com msftncsi.com msedge.net live.com office.com office365.com msftconnecttest.com skype.com
gstatic.com googleapis.com googleusercontent.com google-analytics.com doubleclick.net googlesyndication.com googletagmanager.com gvt1.com gvt2.com ggpht.com googleadservices.com
akamai.net akamaiedge.net akamaihd.net edgekey.net cloudfront.net azureedge.net azure.com trafficmanager.net digicert.com letsencrypt.org symcd.com sectigo.com verisign.com
cloudflare.net fastly.net fastlylb.net amazonaws.com adnxs.com scorecardresearch.com 1e100.net mozilla.com mozilla.net mozilla.org firefox.com mozaws.net
nr-data.net bing.net clarity.ms vo.msecnd.net azurefd.net firebaseio.com""".split())

SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"}
IGNORE_SUFFIX = (".local", ".arpa", ".lan", ".home", ".internal", ".localdomain", ".corp")
IGNORE_NAMES = {"wpad", "isatap", "localhost"}


def base_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def valid_host(host: str) -> bool:
    return bool(host and "." in host and re.fullmatch(r"[a-z0-9.-]+", host) and not host.endswith(IGNORE_SUFFIX) and host.split(".")[0] not in IGNORE_NAMES)


def is_background(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in BACKGROUND)


def in_set(host: str, domains) -> bool:
    return host in domains or any(host.endswith("." + d) for d in domains)


def classify(host: str, categories) -> str:
    """First enabled category the host belongs to ('' if none): exact/suffix lists first, then keywords."""
    for cat in categories:
        if in_set(host, CATEGORY_DOMAINS.get(cat, ())):
            return cat
    for cat in categories:
        rx = KEYWORDS.get(cat)
        if rx and rx.search(host):
            return cat
    return ""
