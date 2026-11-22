use serde_json::Value;
use std::{collections::HashSet, fmt, ops::Range};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Error {
    TooLarge,
    TooDeep,
    InvalidJson,
    DuplicateKey,
    ExpectedObject,
    ExpectedArray,
    InvalidNode,
    InvalidEdit,
    OverlappingEdits,
    IndexOutOfBounds,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "JSON exceeds the size limit",
            Self::TooDeep => "JSON exceeds the depth limit",
            Self::InvalidJson => "invalid JSON",
            Self::DuplicateKey => "duplicate JSON object key",
            Self::ExpectedObject => "expected a JSON object",
            Self::ExpectedArray => "expected a JSON array",
            Self::InvalidNode => "invalid JSON node",
            Self::InvalidEdit => "invalid JSON edit",
            Self::OverlappingEdits => "overlapping JSON edits",
            Self::IndexOutOfBounds => "JSON array index is out of bounds",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) span: Range<usize>,
    pub(crate) kind: Kind,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Kind {
    Object(Vec<Member>),
    Array(Vec<Node>),
    Scalar,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub(crate) key: String,
    pub(crate) key_span: Range<usize>,
    pub(crate) value: Node,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Edit {
    pub(crate) span: Range<usize>,
    pub(crate) replacement: Vec<u8>,
}
#[derive(Debug, Clone)]
pub(crate) struct Document {
    pub(crate) source: Vec<u8>,
    pub(crate) root: Node,
}

impl Document {
    pub(crate) fn parse(source: &[u8]) -> Result<Self, Error> {
        if source.len() > MAX_BYTES {
            return Err(Error::TooLarge);
        }
        let mut parser = Parser {
            source,
            position: 0,
        };
        let root = parser.node(0)?;
        parser.whitespace();
        if parser.position != source.len() {
            return Err(Error::InvalidJson);
        }
        Ok(Self {
            source: source.to_vec(),
            root,
        })
    }
    pub(crate) fn at(&self, path: &[&str]) -> Result<Option<&Node>, Error> {
        let mut node = &self.root;
        for key in path {
            let Kind::Object(members) = &node.kind else {
                return Err(Error::ExpectedObject);
            };
            let Some(member) = members.iter().find(|member| member.key == *key) else {
                return Ok(None);
            };
            node = &member.value;
        }
        Ok(Some(node))
    }
    pub(crate) fn value(&self, node: &Node) -> Result<Value, Error> {
        self.check_node(node)?;
        self.decode(node)
    }
    fn decode(&self, node: &Node) -> Result<Value, Error> {
        match &node.kind {
            Kind::Object(members) => {
                let mut value = serde_json::Map::new();
                for member in members {
                    value.insert(member.key.clone(), self.decode(&member.value)?);
                }
                Ok(Value::Object(value))
            }
            Kind::Array(nodes) => nodes
                .iter()
                .map(|child| self.decode(child))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Kind::Scalar => {
                serde_json::from_slice(self.bytes(&node.span)?).map_err(|_| Error::InvalidJson)
            }
        }
    }
    fn bytes(&self, span: &Range<usize>) -> Result<&[u8], Error> {
        self.source.get(span.clone()).ok_or(Error::InvalidNode)
    }
    fn check_node(&self, node: &Node) -> Result<(), Error> {
        fn contains(root: &Node, needle: &Node) -> bool {
            if std::ptr::eq(root, needle) || root == needle {
                return true;
            }
            match &root.kind {
                Kind::Object(members) => {
                    members.iter().any(|member| contains(&member.value, needle))
                }
                Kind::Array(children) => children.iter().any(|child| contains(child, needle)),
                Kind::Scalar => false,
            }
        }
        if contains(&self.root, node) {
            Ok(())
        } else {
            Err(Error::InvalidNode)
        }
    }
    pub(crate) fn set_member(
        &self,
        object: &Node,
        key: &str,
        value: &Value,
    ) -> Result<Option<Edit>, Error> {
        self.check_node(object)?;
        let Kind::Object(members) = &object.kind else {
            return Err(Error::ExpectedObject);
        };
        if let Some(member) = members.iter().find(|member| member.key == key) {
            if self.decode(&member.value)? == *value {
                return Ok(None);
            }
            return Ok(Some(Edit {
                span: member.value.span.clone(),
                replacement: encode(value)?,
            }));
        }
        let mut replacement = Vec::new();
        if !members.is_empty() {
            replacement.push(b',');
        }
        replacement.extend(serde_json::to_vec(key).map_err(|_| Error::InvalidJson)?);
        replacement.push(b':');
        replacement.extend(encode(value)?);
        let position = members
            .last()
            .map(|member| member.value.span.end)
            .unwrap_or(object.span.end - 1);
        Ok(Some(Edit {
            span: position..position,
            replacement,
        }))
    }
    pub(crate) fn remove_member(&self, object: &Node, key: &str) -> Result<Option<Edit>, Error> {
        self.check_node(object)?;
        let Kind::Object(members) = &object.kind else {
            return Err(Error::ExpectedObject);
        };
        let Some(index) = members.iter().position(|member| member.key == key) else {
            return Ok(None);
        };
        let item = members[index].key_span.start..members[index].value.span.end;
        let previous = index.checked_sub(1).map(|i| members[i].value.span.end);
        let next = members.get(index + 1).map(|member| member.key_span.start);
        self.remove_item(item, previous, next).map(Some)
    }
    pub(crate) fn append_element(&self, array: &Node, value: &Value) -> Result<Edit, Error> {
        self.check_node(array)?;
        let Kind::Array(elements) = &array.kind else {
            return Err(Error::ExpectedArray);
        };
        let mut replacement = Vec::new();
        if !elements.is_empty() {
            replacement.push(b',');
        }
        replacement.extend(encode(value)?);
        let position = elements
            .last()
            .map(|node| node.span.end)
            .unwrap_or(array.span.end - 1);
        Ok(Edit {
            span: position..position,
            replacement,
        })
    }
    pub(crate) fn remove_element(&self, array: &Node, index: usize) -> Result<Edit, Error> {
        self.check_node(array)?;
        let Kind::Array(elements) = &array.kind else {
            return Err(Error::ExpectedArray);
        };
        let item = elements
            .get(index)
            .ok_or(Error::IndexOutOfBounds)?
            .span
            .clone();
        self.remove_item(
            item,
            index.checked_sub(1).map(|i| elements[i].span.end),
            elements.get(index + 1).map(|node| node.span.start),
        )
    }
    fn comma_between(&self, left: usize, right: usize) -> Result<usize, Error> {
        let bytes = self.source.get(left..right).ok_or(Error::InvalidNode)?;
        let mut comma = None;
        for (offset, byte) in bytes.iter().enumerate() {
            if *byte == b',' && comma.is_none() {
                comma = Some(left + offset);
            } else if !json_whitespace(*byte) {
                return Err(Error::InvalidNode);
            }
        }
        comma.ok_or(Error::InvalidNode)
    }
    fn remove_item(
        &self,
        item: Range<usize>,
        previous: Option<usize>,
        next: Option<usize>,
    ) -> Result<Edit, Error> {
        if let Some(next) = next {
            let comma = self.comma_between(item.end, next)?;
            Ok(Edit {
                span: item.start..comma + 1,
                replacement: self.bytes(&(item.end..comma))?.to_vec(),
            })
        } else if let Some(previous) = previous {
            let comma = self.comma_between(previous, item.start)?;
            Ok(Edit {
                span: comma..item.end,
                replacement: self.bytes(&(comma + 1..item.start))?.to_vec(),
            })
        } else {
            Ok(Edit {
                span: item,
                replacement: Vec::new(),
            })
        }
    }
    pub(crate) fn render(&self, edits: &[Edit]) -> Result<Vec<u8>, Error> {
        let mut edits: Vec<_> = edits.iter().collect();
        edits.sort_by_key(|edit| (edit.span.start, edit.span.end));
        let mut length = self.source.len();
        let mut previous: Option<&Edit> = None;
        for edit in &edits {
            if edit.span.start > edit.span.end || edit.span.end > self.source.len() {
                return Err(Error::InvalidEdit);
            }
            if let Some(previous) = previous {
                if edit.span.start < previous.span.end || edit.span.start == previous.span.start {
                    return Err(Error::OverlappingEdits);
                }
            }
            length = length
                .checked_sub(edit.span.len())
                .and_then(|n| n.checked_add(edit.replacement.len()))
                .ok_or(Error::TooLarge)?;
            if length > MAX_BYTES {
                return Err(Error::TooLarge);
            }
            previous = Some(edit);
        }
        let mut output = Vec::with_capacity(length);
        let mut position = 0;
        for edit in edits {
            output.extend_from_slice(&self.source[position..edit.span.start]);
            output.extend_from_slice(&edit.replacement);
            position = edit.span.end;
        }
        output.extend_from_slice(&self.source[position..]);
        Self::parse(&output)?;
        Ok(output)
    }
}
fn encode(value: &Value) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(value).map_err(|_| Error::InvalidJson)
}
fn json_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t')
}
struct Parser<'a> {
    source: &'a [u8],
    position: usize,
}
impl Parser<'_> {
    fn whitespace(&mut self) {
        while self
            .source
            .get(self.position)
            .is_some_and(|byte| json_whitespace(*byte))
        {
            self.position += 1;
        }
    }
    fn take(&mut self, wanted: u8) -> Result<(), Error> {
        if self.source.get(self.position) == Some(&wanted) {
            self.position += 1;
            Ok(())
        } else {
            Err(Error::InvalidJson)
        }
    }
    fn string(&mut self) -> Result<(String, Range<usize>), Error> {
        let start = self.position;
        self.take(b'"')?;
        loop {
            match self.source.get(self.position).copied() {
                Some(b'"') => {
                    self.position += 1;
                    let span = start..self.position;
                    let decoded = serde_json::from_slice(
                        self.source.get(span.clone()).ok_or(Error::InvalidJson)?,
                    )
                    .map_err(|_| Error::InvalidJson)?;
                    return Ok((decoded, span));
                }
                Some(b'\\') => {
                    self.position += 1;
                    if self.position >= self.source.len() {
                        return Err(Error::InvalidJson);
                    }
                    self.position += 1;
                }
                Some(byte) if byte >= 0x20 => self.position += 1,
                _ => return Err(Error::InvalidJson),
            }
        }
    }
    fn node(&mut self, depth: usize) -> Result<Node, Error> {
        self.whitespace();
        let start = self.position;
        let next = self.source.get(start).copied().ok_or(Error::InvalidJson)?;
        if matches!(next, b'{' | b'[') && depth >= MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let kind = match next {
            b'{' => {
                self.position += 1;
                self.whitespace();
                let mut members = Vec::new();
                let mut keys = HashSet::new();
                if self.source.get(self.position) == Some(&b'}') {
                    self.position += 1;
                } else {
                    loop {
                        let (key, key_span) = self.string()?;
                        if !keys.insert(key.clone()) {
                            return Err(Error::DuplicateKey);
                        }
                        self.whitespace();
                        self.take(b':')?;
                        let value = self.node(depth + 1)?;
                        members.push(Member {
                            key,
                            key_span,
                            value,
                        });
                        self.whitespace();
                        match self.source.get(self.position) {
                            Some(b',') => {
                                self.position += 1;
                                self.whitespace();
                            }
                            Some(b'}') => {
                                self.position += 1;
                                break;
                            }
                            _ => return Err(Error::InvalidJson),
                        }
                    }
                }
                Kind::Object(members)
            }
            b'[' => {
                self.position += 1;
                self.whitespace();
                let mut elements = Vec::new();
                if self.source.get(self.position) == Some(&b']') {
                    self.position += 1;
                } else {
                    loop {
                        elements.push(self.node(depth + 1)?);
                        self.whitespace();
                        match self.source.get(self.position) {
                            Some(b',') => {
                                self.position += 1;
                                self.whitespace();
                            }
                            Some(b']') => {
                                self.position += 1;
                                break;
                            }
                            _ => return Err(Error::InvalidJson),
                        }
                    }
                }
                Kind::Array(elements)
            }
            b'"' => {
                self.string()?;
                Kind::Scalar
            }
            _ => {
                while self.source.get(self.position).is_some_and(|byte| {
                    !json_whitespace(*byte) && !matches!(byte, b',' | b']' | b'}')
                }) {
                    self.position += 1;
                }
                let value: Value = serde_json::from_slice(
                    self.source
                        .get(start..self.position)
                        .ok_or(Error::InvalidJson)?,
                )
                .map_err(|_| Error::InvalidJson)?;
                if matches!(value, Value::Object(_) | Value::Array(_)) {
                    return Err(Error::InvalidJson);
                }
                Kind::Scalar
            }
        };
        Ok(Node {
            span: start..self.position,
            kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn rendered(source: &[u8], f: impl FnOnce(&Document) -> Edit) -> Vec<u8> {
        let document = Document::parse(source).unwrap();
        document.render(&[f(&document)]).unwrap()
    }
    #[test]
    fn replace_value_preserves_dirty_neighbors_and_key_spelling() {
        let source = b" \r\n{\"z\" : [ 3,2 ], \"\\u0061\"  :  true ,\n\t\"last\": {\"q\":1}} \t";
        let output = rendered(source, |d| {
            d.set_member(&d.root, "a", &json!({"new":2}))
                .unwrap()
                .unwrap()
        });
        assert_eq!(
            output,
            b" \r\n{\"z\" : [ 3,2 ], \"\\u0061\"  :  {\"new\":2} ,\n\t\"last\": {\"q\":1}} \t"
        );
    }
    #[test]
    fn semantic_repeat_is_a_byte_exact_noop() {
        let source = b"{ \"config\" : { \"z\" : 2, \"a\" : [true,null] } }";
        let d = Document::parse(source).unwrap();
        assert_eq!(
            d.set_member(&d.root, "config", &json!({"a":[true,null],"z":2}))
                .unwrap(),
            None
        );
        assert_eq!(d.render(&[]).unwrap(), source);
    }
    #[test]
    fn reparsed_insert_then_repeat_never_rewrites_neighbors() {
        let original = b"{\n\t\"unmanaged\" : [ 1, 2 ]\n}";
        let d = Document::parse(original).unwrap();
        let edit = d
            .set_member(&d.root, "managed", &json!({"enabled":true}))
            .unwrap()
            .unwrap();
        let bytes = d.render(&[edit]).unwrap();
        let reparsed = Document::parse(&bytes).unwrap();
        assert_eq!(
            reparsed
                .set_member(&reparsed.root, "managed", &json!({"enabled":true}))
                .unwrap(),
            None
        );
        assert_eq!(reparsed.render(&[]).unwrap(), bytes);
        assert!(bytes.starts_with(b"{\n\t\"unmanaged\" : [ 1, 2 ]"));
    }
    #[test]
    fn add_member_preserves_existing_bytes_and_order() {
        let output = rendered(b"{ \"z\" : 1 \r\n}", |d| {
            d.set_member(&d.root, "a", &json!(2)).unwrap().unwrap()
        });
        assert_eq!(output, b"{ \"z\" : 1,\"a\":2 \r\n}");
        let output = rendered(b"{ \r\n }", |d| {
            d.set_member(&d.root, "a", &json!(2)).unwrap().unwrap()
        });
        assert_eq!(output, b"{ \r\n \"a\":2}");
    }
    #[test]
    fn remove_each_member_preserves_all_separator_whitespace() {
        let source = b"{ \"a\" : 1 \t,\n \"b\": 2 , \"c\" :3 }";
        for (key, wanted) in [
            ("a", b"{  \t\n \"b\": 2 , \"c\" :3 }".as_slice()),
            ("b", b"{ \"a\" : 1 \t,\n   \"c\" :3 }".as_slice()),
            ("c", b"{ \"a\" : 1 \t,\n \"b\": 2   }".as_slice()),
        ] {
            let output = rendered(source, |d| d.remove_member(&d.root, key).unwrap().unwrap());
            assert_eq!(output, wanted);
        }
        let d = Document::parse(b"{\"only\":1}").unwrap();
        assert_eq!(
            d.render(&[d.remove_member(&d.root, "only").unwrap().unwrap()])
                .unwrap(),
            b"{}"
        );
        assert_eq!(d.remove_member(&d.root, "absent").unwrap(), None);
    }
    #[test]
    fn array_append_remove_and_nested_values_preserve_neighbors() {
        let source = b"[ 1 \t,\n {\"x\": [2,3]} , false ]";
        let d = Document::parse(source).unwrap();
        assert_eq!(
            d.render(&[d.append_element(&d.root, &json!("new")).unwrap()])
                .unwrap(),
            b"[ 1 \t,\n {\"x\": [2,3]} , false,\"new\" ]"
        );
        let expected = [
            b"[  \t\n {\"x\": [2,3]} , false ]".as_slice(),
            b"[ 1 \t,\n   false ]".as_slice(),
            b"[ 1 \t,\n {\"x\": [2,3]}   ]".as_slice(),
        ];
        for (index, wanted) in expected.iter().enumerate() {
            assert_eq!(
                d.render(&[d.remove_element(&d.root, index).unwrap()])
                    .unwrap(),
                *wanted
            );
        }
        assert_eq!(
            rendered(b"[ \n ]", |d| d.append_element(&d.root, &json!(1)).unwrap()),
            b"[ \n 1]"
        );
        assert_eq!(
            rendered(b"[1]", |d| d.remove_element(&d.root, 0).unwrap()),
            b"[]"
        );
    }
    #[test]
    fn escaped_and_nested_duplicate_keys_are_rejected_before_value_decode() {
        for source in [
            br#"{"a":1,"\u0061":2}"#.as_slice(),
            br#"{"x":[{"same":1,"same":2}]}"#.as_slice(),
            br#"{"a":{"b":1,"\u0062":2}}"#.as_slice(),
        ] {
            assert_eq!(Document::parse(source).unwrap_err(), Error::DuplicateKey);
        }
    }
    #[test]
    fn invalid_json_never_becomes_a_document() {
        for source in [
            b"".as_slice(),
            b"true false",
            b"{\"a\":1,}",
            b"[1,]",
            b"{a:1}",
            b"01",
            b"1e",
            b"NaN",
            b"\xef\xbb\xbf{}",
            b"\"\\q\"",
            b"\"\\uD800\"",
            b"\"\xff\"",
            b"[0\x0b]",
            b"/* comment */ {}",
        ] {
            assert!(Document::parse(source).is_err(), "invalid input accepted");
        }
    }
    #[test]
    fn size_and_depth_limits_include_empty_containers() {
        assert_eq!(
            Document::parse(&vec![b' '; MAX_BYTES + 1]).unwrap_err(),
            Error::TooLarge
        );
        let accepted = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        let d = Document::parse(accepted.as_bytes()).unwrap();
        assert!(d.value(&d.root).is_ok());
        let too_deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert_eq!(
            Document::parse(too_deep.as_bytes()).unwrap_err(),
            Error::TooDeep
        );
    }
    #[test]
    fn decoded_key_path_and_scalar_values_are_fallible() {
        let d =
            Document::parse(br#"{"\u0061":{"list":["value",-2.5e2,null]},"scalar":1}"#).unwrap();
        let node = d.at(&["a", "list"]).unwrap().unwrap();
        assert_eq!(d.value(node).unwrap(), json!(["value", -250.0, null]));
        assert!(d.at(&["missing", "x"]).unwrap().is_none());
        assert_eq!(d.at(&["scalar", "x"]).unwrap_err(), Error::ExpectedObject);
        let foreign = Node {
            span: 0..usize::MAX,
            kind: Kind::Scalar,
        };
        assert_eq!(d.value(&foreign).unwrap_err(), Error::InvalidNode);
        assert_eq!(
            d.append_element(&d.root, &json!(0)).unwrap_err(),
            Error::ExpectedArray
        );
    }
    #[test]
    fn nonoverlapping_edits_compose_and_invalid_edits_refuse() {
        let d = Document::parse(b"{\"a\":1,\"b\":2}").unwrap();
        let a = d.set_member(&d.root, "a", &json!(3)).unwrap().unwrap();
        let b = d.set_member(&d.root, "b", &json!(4)).unwrap().unwrap();
        assert_eq!(d.render(&[b, a.clone()]).unwrap(), b"{\"a\":3,\"b\":4}");
        assert_eq!(
            d.render(&[a.clone(), a]).unwrap_err(),
            Error::OverlappingEdits
        );
        assert_eq!(
            d.render(&[Edit {
                span: 0..usize::MAX,
                replacement: Vec::new()
            }])
            .unwrap_err(),
            Error::InvalidEdit
        );
        assert_eq!(
            d.render(&[Edit {
                span: 0..1,
                replacement: b"[".to_vec()
            }])
            .unwrap_err(),
            Error::InvalidJson
        );
        let x = d.set_member(&d.root, "x", &json!(1)).unwrap().unwrap();
        let y = d.set_member(&d.root, "y", &json!(2)).unwrap().unwrap();
        assert_eq!(d.render(&[x, y]).unwrap_err(), Error::OverlappingEdits);
    }
    #[test]
    fn error_messages_never_echo_source_or_keys() {
        let error = Document::parse(br#"{"sensitive-canary":0,"sensitive-canary":1}"#).unwrap_err();
        assert_eq!(error.to_string(), "duplicate JSON object key");
        assert!(!format!("{error:?}").contains("sensitive-canary"));
    }
}
