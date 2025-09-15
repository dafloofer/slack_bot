# slack_bot

Used to interact with Slack via a slackbot token as identified with prefix xobx_

#### Usage Examples

Get messages with replies, limiting the reply threads to 50 replies max. Default 10 message will be retrieved per --get_messages default
```
python3 slack.py --token "$SLACK_BOT_TOKEN" \
  --get_messages --channel general \
  --include-replies --max-replies 50
```

Get messages with flattened replies (replies will be inline with regular messages)
```
python3 slack.py --token "$SLACK_BOT_TOKEN" \
  --get_messages --channel C0123456789 \
  --count 200 --include-replies --flatten-replies --pretty
```
