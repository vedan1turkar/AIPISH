"""Registry of approved corpora: where they come from, their terms, and checksums.

`sha256` values are the digests observed when the files were first acquired
(the providers do not publish checksums); acquisition fails if a later
download differs, so the corpus is reproducible or loudly not.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SourceFile:
    name: str
    url: str
    sha256: str | None  # pinned after first verified acquisition
    size: int | None = None


@dataclass(frozen=True)
class Source:
    id: str
    title: str
    homepage: str
    licence: str
    licence_url: str | None
    redistribution: str
    attribution: str
    files: tuple[SourceFile, ...] = field(default_factory=tuple)


NAZARIO = Source(
    id="nazario",
    title="Nazario phishing corpus (Jose Nazario)",
    homepage="https://monkey.org/~jose/phishing/",
    licence="CC-BY-4.0 (stated in the corpus README.txt; LICENSE.txt is the CC BY 4.0 legal code)",
    licence_url="https://monkey.org/~jose/phishing/LICENSE.txt",
    redistribution="Permitted with attribution. AIPISH still keeps raw mail local "
                   "(live phishing URLs); only hashes/labels are committed.",
    attribution="Jose Nazario, Phishing Corpus, https://monkey.org/~jose/phishing/ (CC BY 4.0).",
    files=(
        SourceFile("phishing0.mbox", "https://monkey.org/~jose/phishing/phishing0.mbox",
                   "6184b0a34ed8cbbb252676e21c1eab9eac5fa4be89c61e30cc9954ebbb25d848", 3119972),
        SourceFile("phishing1.mbox", "https://monkey.org/~jose/phishing/phishing1.mbox",
                   "99f02474a11086408a5ce6d11ef38823f003c6611a4312c31fbee96773eeba28", 4191770),
        SourceFile("phishing2.mbox", "https://monkey.org/~jose/phishing/phishing2.mbox",
                   "5113277984eae759a5ff958ccf408b542441ce033a49b923ab3b0f324075e6bd", 10420294),
        SourceFile("phishing3.mbox", "https://monkey.org/~jose/phishing/phishing3.mbox",
                   "b29336d2e31c2dff19639415e98ed2aced5b4d63675ea5e29bea1a7d4e452841", 20067215),
        SourceFile("20051114.mbox", "https://monkey.org/~jose/phishing/20051114.mbox",
                   "928cbf1c394d01d0b398ded8dc7cbd94dd4ce9cb0d4efdecd12696338c247926", 4071556),
    ),
)

SPAMASSASSIN = Source(
    id="spamassassin",
    title="SpamAssassin public corpus (ham subsets only)",
    homepage="https://spamassassin.apache.org/old/publiccorpus/",
    licence="No licence granted. Readme: copyright in message text remains with the original "
            "senders; messages were posted to public fora or donated knowing they may be public.",
    licence_url="https://spamassassin.apache.org/old/publiccorpus/readme.html",
    redistribution="Not granted. Do not commit or redistribute message content; acquire locally. "
                   "Do not send the messages into a live mail system (readme request).",
    attribution="The Apache SpamAssassin Project, public corpus (2003-02-28 snapshot).",
    files=(
        SourceFile("20030228_easy_ham.tar.bz2",
                   "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
                   "2b7b65904bcfcc31d2b5f51946f2d261370b257402cbbd62930b46ab83367438", 1612216),
        SourceFile("20030228_easy_ham_2.tar.bz2",
                   "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham_2.tar.bz2",
                   "b4bd3dc5ae5b40f38e99a0e41ad7d16b428b56e818e3a6ffa07330d62004dd38", 1077892),
        SourceFile("20030228_hard_ham.tar.bz2",
                   "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
                   "ce2ce67880643dbde65ea7f85bffbfe4417349c4bd80b6b0de56262ae6b0a9c9", 1029898),
    ),
)

ENRON = Source(
    id="enron",
    title="Enron email dataset (CMU, 7 May 2015 version) - sent-folder subset",
    homepage="https://www.cs.cmu.edu/~enron/",
    licence="No formal licence. Released publicly by FERC during its investigation; CMU "
            "distributes it as a research resource and asks users to respect the privacy "
            "of the people involved.",
    licence_url=None,
    redistribution="Not committed: contains real employees' personal correspondence. "
                   "Acquire locally from CMU; only hashes/labels are committed.",
    attribution="William W. Cohen, CMU, Enron Email Dataset (May 7, 2015 version).",
    files=(
        SourceFile("enron_mail_20150507.tar.gz",
                   "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz",
                   "b3da1b3fe0369ec3140bb4fbce94702c33b7da810ec15d718b3fadf5cd748ca7", 443254787),
    ),
)

SOURCES: dict[str, Source] = {s.id: s for s in (NAZARIO, SPAMASSASSIN, ENRON)}

# Considered but deliberately not used (see data card):
EXCLUDED_FILES = {
    "nazario/private-phishing4.mbox": "Name marks it 'private'; README does not clarify its status.",
    "nazario/phishing-2015..2025": "Same licence, but 2015-2025 would widen the era gap to the "
                                   "1998-2003 legitimate corpora (temporal confound). Deferred.",
    "spamassassin/spam, spam_2": "Not an approved source for any AIPISH class (spam != phishing).",
}
