use hyper::{header, HeaderMap, StatusCode};

use super::authority::{AuthorityError, Carrier, Record};
use super::request::Code;
use super::{cookie, Issuer, SESSION_COOKIE};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Route {
    Upgrade,
    Snapshot,
    Stream,
    Command,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) struct Refusal {
    pub status: StatusCode,
    pub code: Code,
}

impl Refusal {
    pub(super) const INVALID: Self = Self::new(StatusCode::BAD_REQUEST, Code::BadMessage);
    pub(super) const UNAUTHENTICATED: Self =
        Self::new(StatusCode::UNAUTHORIZED, Code::Unauthenticated);
    pub(super) const FORBIDDEN: Self = Self::new(StatusCode::FORBIDDEN, Code::Forbidden);
    pub(super) const UNAVAILABLE: Self =
        Self::new(StatusCode::SERVICE_UNAVAILABLE, Code::Unavailable);
    pub(super) const RATE_LIMIT: Self = Self::new(StatusCode::TOO_MANY_REQUESTS, Code::RateLimited);
    pub(super) const NOT_FOUND: Self = Self::new(StatusCode::NOT_FOUND, Code::NotFoundOrDenied);

    const fn new(status: StatusCode, code: Code) -> Self {
        Self { status, code }
    }
}

impl From<AuthorityError> for Refusal {
    fn from(error: AuthorityError) -> Self {
        match error {
            AuthorityError::Invalid | AuthorityError::Denied => Self::UNAUTHENTICATED,
            AuthorityError::Forbidden => Self::FORBIDDEN,
            AuthorityError::Busy | AuthorityError::Storage => Self::UNAVAILABLE,
        }
    }
}

pub(super) async fn authenticate(
    issuer: &Issuer,
    route: Route,
    headers: &HeaderMap,
) -> Result<Record, Refusal> {
    let (carrier, handle) = credential(route, headers, &issuer.config.public_origin)?;
    let record = issuer.authority.admit(handle, carrier)?;
    if matches!(
        record.class,
        super::authority::Class::Browser | super::authority::Class::Native
    ) {
        if issuer
            .revalidate(&record.principal, crate::storage::now_epoch_secs())
            .await
            .is_err()
        {
            issuer.authority.admit(handle, carrier)?;
            return Err(Refusal::UNAVAILABLE);
        }
        return issuer
            .authority
            .admit(handle, carrier)
            .map_err(Refusal::from);
    }
    Ok(record)
}

fn credential<'a>(
    route: Route,
    headers: &'a HeaderMap,
    public_origin: &str,
) -> Result<(Carrier, &'a str), Refusal> {
    let cookie_present = headers.get_all(header::COOKIE).iter().any(|line| {
        line.to_str().map_or(true, |line| {
            line.split(';').any(|pair| {
                pair.trim()
                    .split_once('=')
                    .is_some_and(|(key, _)| key == SESSION_COOKIE)
            })
        })
    });
    let bearer_present = headers.contains_key(header::AUTHORIZATION);
    match (cookie_present, bearer_present) {
        (false, true) => {
            let bearer = crate::observe_collector_auth::bearer(headers)
                .map_err(|_| Refusal::UNAUTHENTICATED)?;
            if bearer.len() > 512 {
                return Err(Refusal::UNAUTHENTICATED);
            }
            if headers.contains_key(header::ORIGIN) {
                return Err(Refusal::FORBIDDEN);
            }
            Ok((Carrier::Bearer, bearer))
        }
        (true, false) if matches!(route, Route::Upgrade | Route::Snapshot) => {
            let handle = cookie(headers, SESSION_COOKIE).ok_or(Refusal::UNAUTHENTICATED)?;
            let origin_ok = if route == Route::Snapshot && !headers.contains_key(header::ORIGIN) {
                single_header(headers, "sec-fetch-site", "same-origin")
            } else {
                single_header(headers, header::ORIGIN.as_str(), public_origin)
            };
            if !origin_ok {
                return Err(Refusal::FORBIDDEN);
            }
            Ok((Carrier::Cookie, handle))
        }
        _ => Err(Refusal::UNAUTHENTICATED),
    }
}

fn single_header(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    values
        .next()
        .is_some_and(|value| value.as_bytes() == expected.as_bytes())
        && values.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_origin_and_fetch_metadata_checks_precede_authority() {
        let mut headers = HeaderMap::new();
        let origin = "https://mc.example";
        headers.insert(header::COOKIE, "__Host-mc_session=fixture".parse().unwrap());
        assert!(matches!(
            credential(Route::Upgrade, &headers, origin),
            Err(Refusal::FORBIDDEN)
        ));
        headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
        assert!(matches!(
            credential(Route::Snapshot, &headers, origin),
            Ok((Carrier::Cookie, _))
        ));
        assert!(matches!(
            credential(Route::Stream, &headers, origin),
            Err(Refusal::UNAUTHENTICATED)
        ));
        headers.insert(header::ORIGIN, origin.parse().unwrap());
        assert!(matches!(
            credential(Route::Upgrade, &headers, origin),
            Ok((Carrier::Cookie, _))
        ));
        headers.append(header::ORIGIN, origin.parse().unwrap());
        assert!(matches!(
            credential(Route::Upgrade, &headers, origin),
            Err(Refusal::FORBIDDEN)
        ));
        headers.remove(header::COOKIE);
        headers.insert(header::AUTHORIZATION, "Bearer fixture".parse().unwrap());
        assert!(matches!(
            credential(Route::Upgrade, &headers, origin),
            Err(Refusal::FORBIDDEN)
        ));
        headers.remove(header::ORIGIN);
        assert!(matches!(
            credential(Route::Upgrade, &headers, origin),
            Ok((Carrier::Bearer, _))
        ));
        let (carrier, _) = credential(Route::Upgrade, &headers, origin).unwrap();
        let synthetic_class = super::super::authority::Class::Delegated;
        assert!(synthetic_class.matches_carrier(carrier));
        assert!(!synthetic_class.matches_carrier(Carrier::Cookie));
    }
}
