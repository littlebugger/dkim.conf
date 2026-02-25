package dkim

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
)

type DKIMConf struct {
	Enabled     *bool
	SignHeaders string
	SignHeaderList []SignHeader
}

type SignHeader struct {
	Name               string
	Oversigned         bool
	OptionalOversigned bool
}

type DKIMSigningConf struct {
	Enabled              *bool
	AllowUsernameMismatch *bool
	SignAuthenticated    *bool
	SignLocal            *bool
	SignInbound          *bool
	UseDomain            string
	UseDomainSignLocal   string
	UseDomainSignNetworks string
	AllowHdrFromMismatch *bool
	UseESLD              *bool
	TryFallback          *bool
	Path                 string
	Selector             string
	PathMap              string
	SelectorMap          string
	Domain               map[string]DomainRule
}

type DomainRule struct {
	Selector string
	Path     string
}

func ParseDKIMConf(r io.Reader) (*DKIMConf, error) {
	assignments, _, err := parseRspamdConfig(r)
	if err != nil {
		return nil, err
	}

	conf := &DKIMConf{
		SignHeaders: assignments["sign_headers"],
	}
	if conf.SignHeaders != "" {
		conf.SignHeaderList = parseSignHeaders(conf.SignHeaders)
	}
	if val, ok := assignments["enabled"]; ok {
		parsed, err := parseBool(val)
		if err != nil {
			return nil, fmt.Errorf("parse enabled: %w", err)
		}
		conf.Enabled = &parsed
	}

	return conf, nil
}

func ParseDKIMSigningConf(r io.Reader) (*DKIMSigningConf, error) {
	assignments, domain, err := parseRspamdConfig(r)
	if err != nil {
		return nil, err
	}

	conf := &DKIMSigningConf{
		UseDomain:             assignments["use_domain"],
		UseDomainSignLocal:    assignments["use_domain_sign_local"],
		UseDomainSignNetworks: assignments["use_domain_sign_networks"],
		Path:                  assignments["path"],
		Selector:              assignments["selector"],
		PathMap:               assignments["path_map"],
		SelectorMap:           assignments["selector_map"],
		Domain:                make(map[string]DomainRule, len(domain)),
	}

	for key, rule := range domain {
		conf.Domain[key] = DomainRule{
			Selector: rule["selector"],
			Path:     rule["path"],
		}
	}

	setBool := func(dst **bool, key string) error {
		val, ok := assignments[key]
		if !ok {
			return nil
		}
		parsed, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("parse %s: %w", key, err)
		}
		*dst = &parsed
		return nil
	}

	if err := setBool(&conf.Enabled, "enabled"); err != nil {
		return nil, err
	}
	if err := setBool(&conf.AllowUsernameMismatch, "allow_username_mismatch"); err != nil {
		return nil, err
	}
	if err := setBool(&conf.SignAuthenticated, "sign_authenticated"); err != nil {
		return nil, err
	}
	if err := setBool(&conf.SignLocal, "sign_local"); err != nil {
		return nil, err
	}
	if err := setBool(&conf.SignInbound, "sign_inbound"); err != nil {
		return nil, err
	}
	if err := setBool(&conf.AllowHdrFromMismatch, "allow_hdrfrom_mismatch"); err != nil {
		return nil, err
	}
	if err := setBool(&conf.UseESLD, "use_esld"); err != nil {
		return nil, err
	}
	if err := setBool(&conf.TryFallback, "try_fallback"); err != nil {
		return nil, err
	}

	return conf, nil
}

type tokenType int

const (
	tokenEOF tokenType = iota
	tokenIdent
	tokenString
	tokenLBrace
	tokenRBrace
	tokenEqual
	tokenSemicolon
)

type token struct {
	typ tokenType
	val string
}

type lexer struct {
	r   *bufio.Reader
	buf []rune
	peek *token
}

func newLexer(r io.Reader) *lexer {
	return &lexer{r: bufio.NewReader(r)}
}

func (l *lexer) next() (token, error) {
	if l.peek != nil {
		tok := *l.peek
		l.peek = nil
		return tok, nil
	}
	for {
		r, _, err := l.r.ReadRune()
		if err == io.EOF {
			return token{typ: tokenEOF}, nil
		}
		if err != nil {
			return token{}, err
		}

		if r == '#' {
			if err := l.skipLine(); err != nil {
				return token{}, err
			}
			continue
		}

		if unicode.IsSpace(r) {
			continue
		}

		switch r {
		case '{':
			return token{typ: tokenLBrace}, nil
		case '}':
			return token{typ: tokenRBrace}, nil
		case '=':
			return token{typ: tokenEqual}, nil
		case ';':
			return token{typ: tokenSemicolon}, nil
		case '"':
			str, err := l.readString()
			if err != nil {
				return token{}, err
			}
			return token{typ: tokenString, val: str}, nil
		default:
			if isIdentStart(r) {
				l.buf = l.buf[:0]
				l.buf = append(l.buf, r)
				if err := l.readIdent(); err != nil {
					return token{}, err
				}
				return token{typ: tokenIdent, val: string(l.buf)}, nil
			}
			return token{}, fmt.Errorf("unexpected character: %q", r)
		}
	}
}

func (l *lexer) unread(tok token) {
	l.peek = &tok
}

func (l *lexer) readIdent() error {
	for {
		r, _, err := l.r.ReadRune()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if isIdentPart(r) {
			l.buf = append(l.buf, r)
			continue
		}
		if err := l.r.UnreadRune(); err != nil {
			return err
		}
		return nil
	}
}

func (l *lexer) readString() (string, error) {
	var b strings.Builder
	for {
		r, _, err := l.r.ReadRune()
		if err != nil {
			return "", err
		}
		if r == '"' {
			return b.String(), nil
		}
		if r == '\\' {
			esc, _, err := l.r.ReadRune()
			if err != nil {
				return "", err
			}
			b.WriteRune(esc)
			continue
		}
		b.WriteRune(r)
	}
}

func (l *lexer) skipLine() error {
	for {
		r, _, err := l.r.ReadRune()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if r == '\n' {
			return nil
		}
	}
}

func isIdentStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_' || r == '$'
}

func isIdentPart(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' || r == '/' || r == '$'
}

func parseRspamdConfig(r io.Reader) (map[string]string, map[string]map[string]string, error) {
	l := newLexer(r)
	assignments := make(map[string]string)
	domains := make(map[string]map[string]string)

	for {
		tok, err := l.next()
		if err != nil {
			return nil, nil, err
		}
		switch tok.typ {
		case tokenEOF:
			return assignments, domains, nil
		case tokenIdent:
			if tok.val == "domain" {
				if err := parseDomainBlock(l, domains); err != nil {
					return nil, nil, err
				}
				continue
			}
			key := tok.val
			if err := expect(l, tokenEqual); err != nil {
				return nil, nil, err
			}
			val, err := parseValue(l)
			if err != nil {
				return nil, nil, err
			}
			assignments[key] = val
			_, _ = tryConsume(l, tokenSemicolon)
		default:
			return nil, nil, fmt.Errorf("unexpected token: %v", tok.typ)
		}
	}
}

func parseDomainBlock(l *lexer, domains map[string]map[string]string) error {
	if err := expect(l, tokenLBrace); err != nil {
		return err
	}
	for {
		tok, err := l.next()
		if err != nil {
			return err
		}
		switch tok.typ {
		case tokenRBrace:
			_, _ = tryConsume(l, tokenSemicolon)
			return nil
		case tokenIdent, tokenString:
			domainKey := tok.val
			if err := expect(l, tokenLBrace); err != nil {
				return err
			}
			rule := make(map[string]string)
			for {
				t, err := l.next()
				if err != nil {
					return err
				}
				if t.typ == tokenRBrace {
					_, _ = tryConsume(l, tokenSemicolon)
					break
				}
				if t.typ != tokenIdent {
					return fmt.Errorf("unexpected token in domain rule: %v", t.typ)
				}
				if err := expect(l, tokenEqual); err != nil {
					return err
				}
				val, err := parseValue(l)
				if err != nil {
					return err
				}
				rule[t.val] = val
				_, _ = tryConsume(l, tokenSemicolon)
			}
			domains[domainKey] = rule
		default:
			return fmt.Errorf("unexpected token in domain block: %v", tok.typ)
		}
	}
}

func parseValue(l *lexer) (string, error) {
	tok, err := l.next()
	if err != nil {
		return "", err
	}
	switch tok.typ {
	case tokenIdent, tokenString:
		return tok.val, nil
	default:
		return "", fmt.Errorf("unexpected value token: %v", tok.typ)
	}
}

func expect(l *lexer, typ tokenType) error {
	tok, err := l.next()
	if err != nil {
		return err
	}
	if tok.typ != typ {
		return fmt.Errorf("expected token %v, got %v", typ, tok.typ)
	}
	return nil
}

func tryConsume(l *lexer, typ tokenType) (bool, error) {
	tok, err := l.next()
	if err != nil {
		return false, err
	}
	if tok.typ == typ {
		return true, nil
	}
	l.unread(tok)
	return false, nil
}

func parseBool(val string) (bool, error) {
	switch strings.ToLower(val) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", val)
	}
}

func parseSignHeaders(raw string) []SignHeader {
	parts := strings.Split(raw, ":")
	out := make([]SignHeader, 0, len(parts))
	for _, part := range parts {
		h := strings.TrimSpace(part)
		if h == "" {
			continue
		}
		oversigned := false
		optionalOversigned := false
		if strings.HasPrefix(h, "(o)") {
			oversigned = true
			h = strings.TrimSpace(h[3:])
		} else if strings.HasPrefix(h, "(x)") {
			optionalOversigned = true
			h = strings.TrimSpace(h[3:])
		}
		if h == "" {
			continue
		}
		out = append(out, SignHeader{
			Name:               h,
			Oversigned:         oversigned,
			OptionalOversigned: optionalOversigned,
		})
	}
	return out
}
