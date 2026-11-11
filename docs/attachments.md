# Local file attachments

This protocol accompanies the local attachment implementation. Older daemons refuse these operations; federated file transfer is a separate follow-up.

A message can carry up to eight content-addressed references:

```json
{"name":"report.md","size":18,"media_type":"text/markdown","sha256":"<64 lowercase hex>"}
```

The bytes stay in SQLite rather than message text. `--max-attachment-bytes`
(`XMSG_MAX_ATTACHMENT_BYTES`, default 8 MiB) bounds each file. Names are sanitised
and capped at 128 bytes; media types default to `application/octet-stream`.
Attachment rows share the message's reply TTL. Unsent staged bytes and incomplete
uploads expire after the idempotency TTL, and garbage collection removes orphaned
blobs. Knowing a hash alone does not grant permission to attach or read it.

On `agent.sock`, stage inline bytes with
`{"action":"attach","name":"report.md","data":"<base64>"}`. Inline `data` is
the portable form, including across container filesystems. The same-host convenience
`{"action":"attach","name":"report.md","path":"/absolute/file"}` resolves the
path on the daemon host, which may differ from the caller's container.
The answer contains `attachment`; include that reference in the `attachments`
array of a send or reply. Plugin harnesses use these operations on `register.sock`
with the held `session` and `request_id`, as for send.

For larger socket uploads, send `attach` with an opaque `upload` ID, byte `offset`,
and base64 `data` for each chunk, starting at offset zero. Retrying identical bytes
at the same offset is a no-op; a conflicting offset is refused. Finalise with
`{"action":"attach","upload":"<id>","name":"report.md","sha256":"<optional expected hash>"}`.
The server verifies an expected hash before staging the completed file.

MCP `send` and `reply` accept `attachments` entries containing either
`{"path":"/absolute/file","name":"optional-name"}` or
`{"name":"report.md","text":"file contents"}`, with optional `media_type`.
MCP stages files before sending and chunks large inline text automatically.

Read with `{"action":"read_attachment","message_id":"<id>","index":0,"offset":0,"length":4096}`.
Length defaults to and is capped at the node's message-body limit. Offsets count
bytes; UTF-8 reads end at character boundaries, and an offset inside a character
is refused. Other data is base64 encoded. Follow `next` until it is absent.
A message's sender and recipient can read its files. Reply files are readable by
holders of that reply's pushed message ID, matching stored-reply access.

HTTP uploads use `POST /v1/attachments?name=report.md&media_type=text/markdown`
with raw bytes; an anonymous sender also supplies its usual `from` query value.
Sends and replies take the returned reference in `attachments`.
`GET /v1/messages/{id}/attachments/{index}?offset=0&length=4096` returns raw bytes,
`Content-Type`, `X-Xmsg-Sha256`, and `Content-Range`.

This release supports local files only; sends or replies carrying attachments to
another node are refused until federated attachment fetching is available.
