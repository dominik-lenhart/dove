//! Agent-visible IMAP message ids: `f<folder_id>-<uidvalidity>-<uid>` (design "Identifiers"). The format satisfies
//! `gmail::gateway::valid_id`, so refs and argument checks stay provider-neutral. A UIDVALIDITY change makes old ids
//! resolve to `not_found`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImapMsgId {
    pub folder_id: i64,
    pub uidvalidity: u32,
    pub uid: u32,
}

fn num<T: std::str::FromStr>(s: &str) -> Option<T> {
    // Canonical decimal only: no sign, no leading zeros (so every id has exactly one spelling).
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

impl ImapMsgId {
    pub fn encode(&self) -> String {
        format!("f{}-{}-{}", self.folder_id, self.uidvalidity, self.uid)
    }

    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix('f')?;
        let mut it = rest.split('-');
        let (f, v, u) = (it.next()?, it.next()?, it.next()?);
        if it.next().is_some() {
            return None;
        }
        let id = Self { folder_id: num(f)?, uidvalidity: num(v)?, uid: num(u)? };
        (id.uid > 0 && id.uidvalidity > 0 && id.folder_id > 0).then_some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_parse() {
        let id = ImapMsgId { folder_id: 3, uidvalidity: 1_700_000_000, uid: 4211 };
        assert_eq!(id.encode(), "f3-1700000000-4211");
        assert_eq!(ImapMsgId::parse("f3-1700000000-4211"), Some(id));
        for bad in
            ["f3-1700000000", "f03-1-1", "f3-1-1-1", "3-1-1", "f3-1-0", "f-1-1-1", "f3-1-+1", "f3-99999999999-1", ""]
        {
            assert_eq!(ImapMsgId::parse(bad), None, "{bad}");
        }
    }
}
