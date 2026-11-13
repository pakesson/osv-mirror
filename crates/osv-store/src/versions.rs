use std::cmp::Ordering::{self, Equal, Greater, Less};
use std::str::FromStr;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::value::RawValue;
use unive_rs::ecosystems::{
    apk::ApkVersion, brew::BrewVersion, cran::CranVersion, deb::DebVersion, gem::GemVersion,
    hackage::HackageVersion, hex::HexVersion, maven::MavenVersion, nuget::NugetVersion,
    opam::OpamVersion, r#pub::PubVersion, rpm::RpmVersion,
};

use crate::packages::base_ecosystem;

type Comparator = fn(&str, &str) -> Option<Ordering>;

fn compare<T: FromStr + Ord>(a: &str, b: &str) -> Option<Ordering> {
    if a.trim().is_empty() || b.trim().is_empty() {
        return None;
    }
    Some(a.parse::<T>().ok()?.cmp(&b.parse().ok()?))
}

fn semver(a: &str, b: &str) -> Option<Ordering> {
    let parse = |s: &str| semver::Version::parse(s.strip_prefix('v').unwrap_or(s)).ok();
    Some(parse(a)?.cmp_precedence(&parse(b)?))
}

fn ecosystem_comparator(ecosystem: &str) -> Option<Comparator> {
    let (base, suffix) = ecosystem.split_once(':').unwrap_or((ecosystem, ""));
    Some(match base {
        "Debian" | "Ubuntu" | "Raspberry Pi OS" | "Echo" if suffix.is_empty() || base != "Echo" => {
            compare::<DebVersion>
        }
        "AlmaLinux" | "Azure Linux" | "Mageia" | "openEuler" | "openSUSE" | "Photon OS"
        | "Red Hat" | "Rocky Linux" | "SUSE" => compare::<RpmVersion>,
        "Alpine"
        | "Alpaquita"
        | "BellSoft Hardened Containers"
        | "Chainguard"
        | "CleanStart"
        | "MinimOS"
        | "Wolfi" => apk,
        "PyPI" => compare::<pep440_rs::Version>,
        "Maven" => compare::<MavenVersion>,
        "NuGet" => compare::<NugetVersion>,
        "RubyGems" => compare::<GemVersion>,
        "Go" | "npm" | "crates.io" | "Bitnami" | "Julia" | "SwiftURL" | "Linux" | "Kubernetes" => {
            semver
        }
        "Pub" => compare::<PubVersion>,
        "Hex" => compare::<HexVersion>,
        "Hackage" | "GHC" => compare::<HackageVersion>,
        "CRAN" | "Bioconductor" => compare::<CranVersion>,
        "Homebrew" => compare::<BrewVersion>,
        "opam" => compare::<OpamVersion>,
        "Echo" if suffix.eq_ignore_ascii_case("npm") => echo_semver,
        "Echo" if suffix.eq_ignore_ascii_case("NuGet") => echo_nuget,
        "Echo" | "Red Hat Lightwell" if !suffix.is_empty() => {
            return match suffix {
                "PyPI" | "Maven" => ecosystem_comparator(suffix),
                _ => return None,
            };
        }
        "Docker Hardened Images" | "TuxCare" => {
            return match base_ecosystem(suffix) {
                "Alpine" | "Debian" | "Ubuntu" | "AlmaLinux" | "Rocky Linux" | "Red Hat"
                | "PyPI" | "Maven" | "npm" | "NuGet" => ecosystem_comparator(suffix),
                _ => return None,
            };
        }
        "Root" => match base_ecosystem(suffix).to_ascii_lowercase().as_str() {
            "alpine" => |a, b| root(apk, a, b),
            "debian" | "ubuntu" => |a, b| root(compare::<DebVersion>, a, b),
            "pypi" | "python" => |a, b| root(compare::<pep440_rs::Version>, a, b),
            "npm" => |a, b| root(semver, a, b),
            "maven" => |a, b| root(compare::<MavenVersion>, a, b),
            _ => return None,
        },
        "Packagist" => packagist_numeric,
        _ => return None,
    })
}

fn echo_semver(a: &str, b: &str) -> Option<Ordering> {
    echo(semver, a, b)
}

fn echo_nuget(a: &str, b: &str) -> Option<Ordering> {
    echo(compare::<NugetVersion>, a, b)
}

fn echo(cmp: Comparator, a: &str, b: &str) -> Option<Ordering> {
    fn patch(value: &str) -> Option<u64> {
        match value.split_once("+echo.") {
            None => Some(0),
            Some((_, patch)) => patch.parse().ok(),
        }
    }
    Some(cmp(a, b)?.then(patch(a)?.cmp(&patch(b)?)))
}

fn root(cmp: Comparator, a: &str, b: &str) -> Option<Ordering> {
    fn split(value: &str) -> Option<(&str, u64)> {
        if let Some((upstream, patch)) = value
            .rsplit_once("+root.io.")
            .or_else(|| value.rsplit_once(".root.io."))
        {
            return Some((upstream, patch.parse().ok()?));
        }
        let patch = value
            .rsplit_once("-r")
            .and_then(|(_, patch)| patch.parse().ok())
            .unwrap_or(0);
        Some((value, patch))
    }
    let (a, a_patch) = split(a)?;
    let (b, b_patch) = split(b)?;
    Some(cmp(a, b)?.then(a_patch.cmp(&b_patch)))
}

fn packagist_numeric(a: &str, b: &str) -> Option<Ordering> {
    fn parse(value: &str) -> Option<Vec<u64>> {
        let value = value.trim_start_matches(['v', 'V']);
        value.split('.').map(|part| part.parse().ok()).collect()
    }
    let a = parse(a)?;
    let b = parse(b)?;
    // PHP's version_compare orders an additional numeric component after
    // an otherwise equal shorter version, even when the component is zero.
    Some(a.cmp(&b))
}

fn apk(a: &str, b: &str) -> Option<Ordering> {
    // The comparator covers the ordinary APK suffixes. Refuse other
    // extensions instead of treating an unknown suffix as a release.
    static APK: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[0-9]+(?:\.[0-9]+)*[a-z]?(?:_(?:alpha|beta|pre|rc|p)[0-9]*)*(?:-r[0-9]+)?$")
            .unwrap()
    });
    if !APK.is_match(a) || !APK.is_match(b) {
        return None;
    }
    compare::<ApkVersion>(a, b)
}

#[derive(Deserialize)]
struct Range<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    events: Vec<Event<'a>>,
}

#[derive(Deserialize)]
struct Event<'a> {
    introduced: Option<&'a str>,
    fixed: Option<&'a str>,
    last_affected: Option<&'a str>,
    limit: Option<&'a str>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum Boundary {
    Introduced,
    LastAffected,
    Fixed,
    Limit,
}

impl<'a> Event<'a> {
    fn boundary(self) -> Option<(&'a str, Boundary)> {
        let mut fields = [
            (self.introduced, Boundary::Introduced),
            (self.fixed, Boundary::Fixed),
            (self.last_affected, Boundary::LastAffected),
            (self.limit, Boundary::Limit),
        ]
        .into_iter()
        .filter_map(|(value, kind)| Some((value?, kind)));
        let field = fields.next()?;
        fields.next().is_none().then_some(field)
    }
}

/// None means an unevaluable candidate could change the result.
pub(crate) fn matches(
    ecosystem: &str,
    query_ecosystem: &str,
    version: &str,
    versions: Option<&RawValue>,
    ranges: Option<&RawValue>,
) -> Option<bool> {
    let comparator = ecosystem_comparator(ecosystem);
    let mut uncertain = false;
    if let Some(versions) = versions {
        match serde_json::from_str::<Vec<String>>(versions.get()) {
            Ok(versions) => {
                let structured = comparator.filter(|cmp| cmp(version, version).is_some());
                if versions.iter().any(|listed| {
                    listed == version
                        || match structured {
                            Some(cmp) => cmp(version, listed) == Some(Equal),
                            None => fuzzy_equal(version, listed),
                        }
                }) {
                    return Some(true);
                }
            }
            Err(_) => uncertain = true,
        }
    }
    // Upstream deliberately restricts these unscoped distro queries to lists.
    if matches!(query_ecosystem, "Ubuntu" | "Alpine") {
        return (!uncertain).then_some(false);
    }
    if let Some(ranges) = ranges {
        for raw in serde_json::from_str::<Vec<&RawValue>>(ranges.get()).ok()? {
            match range_matches(raw, comparator, version) {
                Some(true) => return Some(true),
                Some(false) => {}
                None => uncertain = true,
            }
        }
    }
    (!uncertain).then_some(false)
}

fn range_matches(raw: &RawValue, ecosystem: Option<Comparator>, version: &str) -> Option<bool> {
    #[derive(Deserialize)]
    struct Kind<'a> {
        #[serde(rename = "type")]
        kind: &'a str,
    }
    let kind = serde_json::from_str::<Kind<'_>>(raw.get()).ok()?.kind;
    let cmp = match kind {
        "SEMVER" => semver as Comparator,
        "ECOSYSTEM" => ecosystem?,
        "GIT" => return Some(false), // Git ancestry is a separate query mode.
        _ => return None,
    };
    let range: Range<'_> = serde_json::from_str(raw.get()).ok()?;
    debug_assert_eq!(range.kind, kind);
    let mut latest = None;
    let mut has_introduced = false;
    let mut has_fixed = false;
    let mut has_last = false;
    let mut limits = 0;
    let mut before_limit = false;

    for event in range.events {
        let (bound, kind) = event.boundary()?;
        if kind == Boundary::Limit {
            limits += 1;
            before_limit |= bound == "*" || cmp(version, bound)? == Less;
            continue;
        }
        has_introduced |= kind == Boundary::Introduced;
        has_fixed |= kind == Boundary::Fixed;
        has_last |= kind == Boundary::LastAffected;
        let order = compare_bound(cmp, version, bound, kind)?;
        if order == Less || (order == Equal && kind == Boundary::LastAffected) {
            continue;
        }
        if let Some((previous, previous_kind)) = latest
            && compare_boundaries(cmp, bound, kind, previous, previous_kind)? == Less
        {
            continue;
        }
        latest = Some((bound, kind));
    }
    if !has_introduced || (has_fixed && has_last) {
        return None;
    }
    Some(
        (limits == 0 || before_limit)
            && latest.is_some_and(|(_, kind)| kind == Boundary::Introduced),
    )
}

fn compare_bound(cmp: Comparator, version: &str, bound: &str, kind: Boundary) -> Option<Ordering> {
    if kind == Boundary::Introduced && bound == "0" {
        return cmp(version, version).map(|_| Greater);
    }
    cmp(version, bound)
}

fn compare_boundaries(
    cmp: Comparator,
    a: &str,
    a_kind: Boundary,
    b: &str,
    b_kind: Boundary,
) -> Option<Ordering> {
    let a_zero = a_kind == Boundary::Introduced && a == "0";
    let b_zero = b_kind == Boundary::Introduced && b == "0";
    let order = if a_zero || b_zero {
        b_zero.cmp(&a_zero)
    } else {
        cmp(a, b)?
    };
    Some(order.then(a_kind.cmp(&b_kind)))
}

pub(crate) fn fuzzy_equal(a: &str, b: &str) -> bool {
    static SEPARATORS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[-_.]+").unwrap());
    static COMPONENTS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i:[0-9]+|rc[0-9]*|alpha[0-9]*|beta[0-9]*|preview[0-9]*)").unwrap()
    });
    let canonical = |value: &str| {
        SEPARATORS
            .replace_all(&value.to_lowercase(), ".")
            .trim_matches('.')
            .to_owned()
    };
    if canonical(a) == canonical(b) {
        return true;
    }
    let components = |value: &str| {
        let prefixed;
        let value = if value.starts_with('.') {
            prefixed = format!("0{value}");
            &prefixed
        } else {
            value
        };
        COMPONENTS
            .find_iter(value)
            .filter(|part| {
                part.as_str().as_bytes()[0].is_ascii_digit()
                    || part.start() == 0
                    || !value.as_bytes()[part.start() - 1].is_ascii_alphabetic()
            })
            .map(|part| part.as_str().to_owned())
            .collect::<Vec<_>>()
    };
    let a = components(a);
    !a.is_empty() && a == components(b)
}
