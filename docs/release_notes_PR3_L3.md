# PR3 (L3) operator-facing log change

The legacy `|too many paths|current maximum:%d|` warning has been replaced by
`|hard cap reached|%d paths active, cap=%d|`. Operators with log-grep dashboards
should update patterns.
