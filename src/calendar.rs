//! Minimal iCalendar (RFC 5545) reader for `text/calendar` mail parts (v0.2 design section 4).
//!
//! Reads the first `VEVENT` of the first `VCALENDAR` into a small, bounded summary. It never evaluates recurrence
//! rules, alarms or time zone definitions and never fetches anything. All text is untrusted: it is cleaned like
//! other mail content, single-line and length-limited, and attendee addresses are counted, not returned.
//!
//! Time zones: Dove carries no time zone database. A `DTSTART;TZID=Europe/Berlin:20261113T140000` is reported as
//! the local time as written (`2026-11-13T14:00:00`) together with the `timezone` name; UTC times (`...Z`) are
//! reported with a `Z` suffix; all-day dates (`VALUE=DATE`) as plain dates with `all_day = true`.

use serde::Serialize;

use crate::content;

/// Most bytes of a calendar part that are read.
pub const MAX_BYTES: usize = 256 * 1024;
/// Most unfolded content lines examined.
const MAX_LINES: usize = 5_000;
/// Longest content line kept, in bytes (longer lines are cut at a character boundary).
const MAX_LINE_BYTES: usize = 8 * 1024;
const MAX_TEXT_CHARS: usize = 200;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CalendarEvent {
    /// `REQUEST`, `CANCEL`, `REPLY`, `PUBLISH`, ... (upper case, letters only), from the calendar or the part's
    /// `method` parameter.
    pub method: Option<String>,
    pub summary: Option<String>,
    /// UTC `YYYY-MM-DDTHH:MM:SSZ`, local `YYYY-MM-DDTHH:MM:SS` (see `timezone`), or a date for all-day events.
    pub start: Option<String>,
    /// Same forms as `start`. For all-day events it is exclusive, as in iCalendar.
    pub end: Option<String>,
    /// `TZID` of the start when it names one.
    pub timezone: Option<String>,
    pub all_day: bool,
    pub location: Option<String>,
    /// `Name <address>` or the address of the organizer.
    pub organizer: Option<String>,
    pub attendees_count: usize,
    pub uid: Option<String>,
}

struct Line {
    name: String,
    params: Vec<(String, String)>,
    value: String,
}

/// Parses calendar text. `method_hint` is the `method` parameter of the part's Content-Type, used when the calendar
/// itself carries no `METHOD`. Returns `None` when there is no `VEVENT` or the text is not iCalendar.
pub fn parse(text: &str, method_hint: Option<&str>) -> Option<CalendarEvent> {
    let text = cut(text, MAX_BYTES);
    let mut stack: Vec<String> = Vec::new();
    let mut calendar_seen = false;
    let mut method = None;
    let mut ev = CalendarEvent::default();
    let mut in_event_done = false;
    let mut found_event = false;
    for raw in unfold(text).take(MAX_LINES) {
        let Some(line) = split_line(&raw) else { continue };
        match line.name.as_str() {
            "BEGIN" => {
                let comp = line.value.trim().to_ascii_uppercase();
                if stack.is_empty() && comp != "VCALENDAR" {
                    // Not iCalendar, or a stray component: nothing trustworthy to read.
                    return None;
                }
                if comp == "VCALENDAR" && stack.is_empty() {
                    calendar_seen = true;
                }
                if comp == "VEVENT" && stack.len() == 1 && found_event {
                    in_event_done = true;
                }
                if comp == "VEVENT" && stack.len() == 1 {
                    found_event = true;
                }
                stack.push(comp);
                if stack.len() > 8 {
                    return None;
                }
            }
            "END" => {
                let comp = line.value.trim().to_ascii_uppercase();
                if stack.last() == Some(&comp) {
                    stack.pop();
                } else {
                    // Mismatched nesting: stop reading rather than guess.
                    break;
                }
                if comp == "VEVENT" && stack.len() == 1 {
                    in_event_done = true;
                }
            }
            _ if !calendar_seen => return None,
            "METHOD" if stack.len() == 1 && method.is_none() => method = clean_method(&line.value),
            n if stack.len() == 2 && stack[1] == "VEVENT" && !in_event_done => event_prop(&mut ev, n, &line),
            _ => {}
        }
    }
    if !found_event {
        return None;
    }
    ev.method = method.or_else(|| method_hint.and_then(clean_method));
    Some(ev)
}

fn event_prop(ev: &mut CalendarEvent, name: &str, line: &Line) {
    match name {
        "SUMMARY" if ev.summary.is_none() => ev.summary = text_value(&line.value),
        "LOCATION" if ev.location.is_none() => ev.location = text_value(&line.value),
        "UID" if ev.uid.is_none() => {
            let v = one_line(&line.value);
            let (v, _) = content::truncate_chars(v.trim(), MAX_TEXT_CHARS);
            ev.uid = (!v.is_empty()).then_some(v);
        }
        "DTSTART" if ev.start.is_none() => {
            if let Some((t, date_only)) = time_value(line) {
                ev.start = Some(t);
                ev.all_day = date_only;
                ev.timezone = param(line, "TZID").map(|z| {
                    let z = one_line(z);
                    content::truncate_chars(z.trim(), 64).0
                });
                ev.timezone.take_if(|z| z.is_empty());
            }
        }
        "DTEND" if ev.end.is_none() => ev.end = time_value(line).map(|(t, _)| t),
        "ORGANIZER" if ev.organizer.is_none() => ev.organizer = organizer(line),
        "ATTENDEE" => ev.attendees_count += 1,
        _ => {}
    }
}

fn clean_method(m: &str) -> Option<String> {
    let m: String = m.trim().chars().filter(char::is_ascii_alphabetic).take(16).collect();
    (!m.is_empty()).then(|| m.to_ascii_uppercase())
}

fn cut(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Unfolded content lines (RFC 5545 3.1: a line break followed by one space or tab continues the line).
fn unfold(text: &str) -> impl Iterator<Item = String> + '_ {
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l)).peekable();
    std::iter::from_fn(move || {
        let first = lines.next()?;
        let mut cur = cut(first, MAX_LINE_BYTES).to_string();
        while let Some(next) = lines.peek() {
            if next.starts_with([' ', '\t']) {
                let room = MAX_LINE_BYTES.saturating_sub(cur.len());
                cur.push_str(cut(&next[1..], room));
                lines.next();
            } else {
                break;
            }
        }
        Some(cur)
    })
}

/// `NAME;PARAM=value;PARAM="quoted:value":value` (names upper-cased). Colons and semicolons inside double quotes do
/// not split.
fn split_line(l: &str) -> Option<Line> {
    let mut in_q = false;
    let mut colon = None;
    for (i, c) in l.char_indices() {
        match c {
            '"' => in_q = !in_q,
            ':' if !in_q => {
                colon = Some(i);
                break;
            }
            _ => {}
        }
    }
    let colon = colon?;
    let (head, value) = (&l[..colon], &l[colon + 1..]);
    let mut parts = Vec::new();
    let (mut start, mut q) = (0, false);
    for (i, c) in head.char_indices() {
        match c {
            '"' => q = !q,
            ';' if !q => {
                parts.push(&head[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&head[start..]);
    let name = parts[0].trim().to_ascii_uppercase();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    let params = parts[1..]
        .iter()
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((k.trim().to_ascii_uppercase(), v.trim().trim_matches('"').to_string()))
        })
        .collect();
    Some(Line { name, params, value: value.to_string() })
}

fn param<'a>(l: &'a Line, name: &str) -> Option<&'a str> {
    l.params.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// One line of cleaned text (control and invisible characters removed, line breaks become spaces).
fn one_line(s: &str) -> String {
    content::clean_text(s).split_whitespace().collect::<Vec<_>>().join(" ")
}

/// iCalendar TEXT: backslash escapes resolved, then cleaned, single-line and bounded.
fn text_value(raw: &str) -> Option<String> {
    let mut s = String::with_capacity(raw.len());
    let mut it = raw.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n' | 'N') => s.push(' '),
                Some(o) => s.push(o),
                None => {}
            }
        } else {
            s.push(c);
        }
    }
    let one = one_line(&s);
    let (t, _) = content::truncate_chars(&one, MAX_TEXT_CHARS);
    (!t.is_empty()).then_some(t)
}

fn digits(s: &str) -> Option<u32> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

fn days_in_month(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400) => 29,
        _ => 28,
    }
}

/// `(value, all_day)` of a DATE or DATE-TIME property. Invalid values give `None`.
fn time_value(l: &Line) -> Option<(String, bool)> {
    let v = l.value.trim();
    let date_only = param(l, "VALUE").is_some_and(|x| x.eq_ignore_ascii_case("DATE")) || v.len() == 8;
    let (d, t) = if date_only { (v, None) } else { v.split_once(['T', 't']).map(|(d, t)| (d, Some(t)))? };
    if d.len() != 8 || !d.is_ascii() {
        return None;
    }
    let (y, mo, da) = (digits(&d[..4])?, digits(&d[4..6])?, digits(&d[6..])?);
    if !(1..=12).contains(&mo) || da == 0 || da > days_in_month(y, mo) {
        return None;
    }
    let date = format!("{y:04}-{mo:02}-{da:02}");
    let Some(t) = t else { return Some((date, true)) };
    let (clock, utc) = match t.strip_suffix(['Z', 'z']) {
        Some(c) => (c, true),
        None => (t, false),
    };
    if clock.len() != 6 || !clock.is_ascii() {
        return None;
    }
    let (h, mi, s) = (digits(&clock[..2])?, digits(&clock[2..4])?, digits(&clock[4..])?);
    if h > 23 || mi > 59 || s > 60 {
        return None;
    }
    Some((format!("{date}T{h:02}:{mi:02}:{:02}{}", s.min(59), if utc { "Z" } else { "" }), false))
}

fn organizer(l: &Line) -> Option<String> {
    let v = l.value.trim();
    let addr = v.get(..7).filter(|p| p.eq_ignore_ascii_case("mailto:")).map_or(v, |_| v[7..].trim());
    if addr.is_empty()
        || addr.len() > 254
        || !addr.contains('@')
        || addr.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '"'))
    {
        return None;
    }
    let addr = addr.to_ascii_lowercase();
    match param(l, "CN").map(one_line).map(|n| content::truncate_chars(n.trim(), 100).0).filter(|n| !n.is_empty()) {
        Some(n) => Some(format!("{n} <{addr}>")),
        None => Some(addr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(event: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\n{event}END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    #[test]
    fn utc_event_with_organizer_and_attendees() {
        let ics = wrap(
            "UID:abc-123@example.org\r\nSUMMARY:Planning\\, Q4\r\nDTSTART:20261113T140000Z\r\nDTEND:20261113T150000Z\r\n\
             LOCATION:Room 4\\nFloor 2\r\nORGANIZER;CN=\"Anna B\":mailto:Anna@Example.org\r\n\
             ATTENDEE;CN=Bob:mailto:bob@example.org\r\nATTENDEE:mailto:carl@example.org\r\n",
        );
        let e = parse(&ics, None).unwrap();
        assert_eq!(e.method.as_deref(), Some("REQUEST"));
        assert_eq!(e.summary.as_deref(), Some("Planning, Q4"));
        assert_eq!(e.start.as_deref(), Some("2026-11-13T14:00:00Z"));
        assert_eq!(e.end.as_deref(), Some("2026-11-13T15:00:00Z"));
        assert_eq!(e.location.as_deref(), Some("Room 4 Floor 2"));
        assert_eq!(e.organizer.as_deref(), Some("Anna B <anna@example.org>"));
        assert_eq!(e.attendees_count, 2);
        assert_eq!(e.uid.as_deref(), Some("abc-123@example.org"));
        assert!(!e.all_day && e.timezone.is_none());
    }

    #[test]
    fn tzid_all_day_and_floating() {
        let e = parse(
            &wrap("DTSTART;TZID=Europe/Berlin:20261113T140000\r\nDTEND;TZID=Europe/Berlin:20261113T153000\r\n"),
            None,
        )
        .unwrap();
        assert_eq!(e.start.as_deref(), Some("2026-11-13T14:00:00"));
        assert_eq!(e.end.as_deref(), Some("2026-11-13T15:30:00"));
        assert_eq!(e.timezone.as_deref(), Some("Europe/Berlin"));
        let e = parse(&wrap("DTSTART;TZID=\"W. Europe Standard Time\":20261113T140000\r\n"), None).unwrap();
        assert_eq!(e.timezone.as_deref(), Some("W. Europe Standard Time"));
        let e = parse(&wrap("DTSTART;VALUE=DATE:20261224\r\nDTEND;VALUE=DATE:20261226\r\n"), None).unwrap();
        assert_eq!((e.start.as_deref(), e.end.as_deref(), e.all_day), (Some("2026-12-24"), Some("2026-12-26"), true));
        let e = parse(&wrap("DTSTART:20261224\r\n"), None).unwrap();
        assert!(e.all_day, "8-digit value is a date");
    }

    #[test]
    fn folded_lines_and_method_hint() {
        let ics = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:A very lo\n ng title\n\t that continues\nDTSTART:20260102T030405Z\nEND:VEVENT\nEND:VCALENDAR\n";
        let e = parse(ics, Some("cancel")).unwrap();
        assert_eq!(e.summary.as_deref(), Some("A very long title that continues"));
        assert_eq!(e.method.as_deref(), Some("CANCEL"), "falls back to the Content-Type method; LF-only input works");
    }

    #[test]
    fn nested_components_and_second_event_are_not_read() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nDTSTART:19700101T000000\r\nSUMMARY:tz\r\nEND:VTIMEZONE\r\n\
                   BEGIN:VEVENT\r\nSUMMARY:first\r\nBEGIN:VALARM\r\nSUMMARY:alarm\r\nDTSTART:20000101T000000Z\r\nEND:VALARM\r\n\
                   DTSTART:20261113T100000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nSUMMARY:second\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let e = parse(ics, None).unwrap();
        assert_eq!(e.summary.as_deref(), Some("first"));
        assert_eq!(e.start.as_deref(), Some("2026-11-13T10:00:00Z"));
    }

    #[test]
    fn garbage_and_invalid_values_are_dropped() {
        assert!(parse("", None).is_none());
        assert!(parse("hello world, not a calendar", None).is_none());
        assert!(parse("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n", None).is_none(), "no VEVENT");
        assert!(parse("SUMMARY:x\r\nBEGIN:VEVENT\r\nEND:VEVENT\r\n", None).is_none(), "event outside a calendar");
        let e = parse(
            &wrap("DTSTART:20261313T140000Z\r\nDTEND:20260230T000000\r\nORGANIZER:mailto:not an address\r\n"),
            None,
        )
        .unwrap();
        assert_eq!((e.start, e.end, e.organizer), (None, None, None), "month 13, Feb 30 and a bad organizer");
        // Mismatched nesting stops reading instead of misattributing properties.
        let e = parse(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:kept\r\nEND:VALARM\r\nSUMMARY:late\r\nEND:VEVENT\r\n",
            None,
        )
        .unwrap();
        assert_eq!(e.summary.as_deref(), Some("kept"));
        // Binary junk.
        assert!(parse(&"\u{0}\u{1}BEGIN:VEVENT\r\n".repeat(10), None).is_none());
    }

    #[test]
    fn text_is_sanitized_and_bounded() {
        let long = "x".repeat(5_000);
        let e =
            parse(&wrap(&format!("SUMMARY:ab\u{202e}cd\u{200b}\\n\u{7}ef\r\nLOCATION:{long}\r\nUID:{long}\r\n")), None)
                .unwrap();
        assert_eq!(e.summary.as_deref(), Some("abcd ef"));
        assert!(e.location.unwrap().chars().count() <= MAX_TEXT_CHARS);
        assert!(e.uid.unwrap().chars().count() <= MAX_TEXT_CHARS);
        let e = parse(&wrap(&"ATTENDEE:mailto:a@b.c\r\n".repeat(100)), None).unwrap();
        assert_eq!(e.attendees_count, 100);
    }

    #[test]
    fn huge_input_is_cut() {
        let big = format!("{}{}", wrap("SUMMARY:ok\r\n"), "X-JUNK:y\r\n".repeat(200_000));
        assert_eq!(parse(&big, None).unwrap().summary.as_deref(), Some("ok"));
    }
}
