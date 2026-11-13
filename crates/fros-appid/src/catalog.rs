//! The signature catalog and name matching (1.x's `frfw.appid`): a name
//! belongs to the app whose catalog entry is the longest matching
//! suffix; exact entries match only themselves and are checked first.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use fros_sensor::pyjson::{Dict, Value};
use fros_sensor::pytext::{self, repr_str, str_of, type_name};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppSignature {
    pub id: String,
    pub name: String,
    pub category: String,
    /// Suffix entries: the name itself and every subdomain of it.
    pub domains: Vec<String>,
    /// Exact entries: only this precise name.
    pub exact: Vec<String>,
}

impl AppSignature {
    pub fn all_names(&self) -> impl Iterator<Item = &String> {
        self.domains.iter().chain(&self.exact)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Catalog {
    pub apps: Vec<AppSignature>,
    pub source: String,
    pub license: String,
    pub reference: String,
    pub generated: String,
}

impl Catalog {
    pub fn by_id(&self, id: &str) -> Option<&AppSignature> {
        // Ids are unique (parse_catalog refuses a repeat).
        self.apps.iter().find(|a| a.id == id)
    }

    /// Every category, sorted.
    pub fn categories(&self) -> Vec<String> {
        let set: BTreeSet<&String> = self.apps.iter().map(|a| &a.category).collect();
        set.into_iter().cloned().collect()
    }
}

/// 1.x's `CatalogError`, with its text word for word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogError(pub String);

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CatalogError {}

/// `raw[key]` with str() of the result, or the text of the exception
/// Python raises (a KeyError's text is the key's repr).
fn item(raw: &Value, key: &str) -> Result<String, String> {
    match raw {
        Value::Dict(d) => d.get(key).map(str_of).ok_or_else(|| repr_str(key)),
        Value::List(_) => Err("list indices must be integers or slices, not str".into()),
        Value::Str(_) => Err("string indices must be integers, not 'str'".into()),
        other => Err(format!(
            "'{}' object is not subscriptable",
            type_name(other)
        )),
    }
}

/// `tuple(str(d).lower() for d in raw.get(key, []))` for a dict `raw`.
fn names(raw: &Dict, key: &str) -> Result<Vec<String>, String> {
    let lowered = |v: &Value| pytext::lower(&str_of(v));
    match raw.get(key) {
        None => Ok(Vec::new()),
        Some(Value::List(items)) => Ok(items.iter().map(lowered).collect()),
        Some(Value::Dict(d)) => Ok(d.0.iter().map(|(k, _)| pytext::lower(k)).collect()),
        Some(Value::Str(s)) => Ok(s.chars().map(|c| pytext::lower(&c.to_string())).collect()),
        Some(other) => Err(format!("'{}' object is not iterable", type_name(other))),
    }
}

fn header(data: &Dict, key: &str) -> String {
    data.get(key).map(str_of).unwrap_or_default()
}

/// 1.x's `parse_catalog` of what `json.loads` read.
pub fn parse_catalog(data: &Value) -> Result<Catalog, CatalogError> {
    let malformed =
        || CatalogError("signature catalog must be an object with an 'apps' list".into());
    let Value::Dict(data) = data else {
        return Err(malformed());
    };
    let Some(Value::List(raw_apps)) = data.get("apps") else {
        return Err(malformed());
    };
    let mut apps: Vec<AppSignature> = Vec::with_capacity(raw_apps.len());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (i, raw) in raw_apps.iter().enumerate() {
        let app = (|| -> Result<AppSignature, String> {
            let id = item(raw, "id")?;
            let name = item(raw, "name")?;
            let category = item(raw, "category")?;
            let Value::Dict(d) = raw else {
                unreachable!("item() only succeeds on a dict")
            };
            Ok(AppSignature {
                id,
                name,
                category,
                domains: names(d, "domains")?,
                exact: names(d, "exact")?,
            })
        })()
        .map_err(|exc| CatalogError(format!("apps[{i}]: malformed entry ({exc})")))?;
        if !seen.insert(app.id.clone()) {
            return Err(CatalogError(format!(
                "apps[{i}]: duplicate app id {}",
                repr_str(&app.id)
            )));
        }
        apps.push(app);
    }
    Ok(Catalog {
        apps,
        source: header(data, "source"),
        license: header(data, "license"),
        reference: header(data, "ref"),
        generated: header(data, "generated"),
    })
}

/// name -> app id. O(number of labels) per name: the exact table first,
/// then every suffix from longest to shortest.
#[derive(Debug, Clone, Default)]
pub struct AppMatcher {
    exact: HashMap<String, String>,
    suffix: HashMap<String, String>,
}

impl AppMatcher {
    pub fn new(catalog: &Catalog) -> Self {
        let mut m = Self::default();
        for app in &catalog.apps {
            // The first app to claim a name keeps it (1.x's setdefault).
            for name in &app.exact {
                m.exact
                    .entry(name.clone())
                    .or_insert_with(|| app.id.clone());
            }
            for name in &app.domains {
                m.suffix
                    .entry(name.clone())
                    .or_insert_with(|| app.id.clone());
            }
        }
        m
    }

    pub fn matches(&self, hostname: &str) -> Option<&str> {
        let name = pytext::lower(pytext::strip(hostname).trim_end_matches('.'));
        if name.is_empty() {
            return None;
        }
        if let Some(app) = self.exact.get(&name) {
            return Some(app);
        }
        let mut rest = name.as_str();
        loop {
            if let Some(app) = self.suffix.get(rest) {
                return Some(app);
            }
            rest = &rest[rest.find('.')? + 1..];
        }
    }
}

/// Every catalog name of the given apps, sorted, for the resolver's and
/// the XDP filter's blocklists. Unknown ids are ignored.
pub fn blocking_names(app_ids: &[String], catalog: &Catalog) -> Vec<String> {
    let mut names: BTreeSet<&String> = BTreeSet::new();
    for id in app_ids {
        if let Some(app) = catalog.by_id(id) {
            names.extend(app.all_names());
        }
    }
    names.into_iter().cloned().collect()
}
