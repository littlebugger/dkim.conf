package dkim

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDKIMConf(t *testing.T) {
	f, err := os.Open("../../examples/1/dkim.conf")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	conf, err := ParseDKIMConf(f)
	require.NoError(t, err)
	require.NotEmpty(t, conf.SignHeaders)
	require.NotEmpty(t, conf.SignHeaderList)
	require.Contains(t, conf.SignHeaderList, SignHeader{Name: "from", Oversigned: true})
	require.Contains(t, conf.SignHeaderList, SignHeader{Name: "subject", Oversigned: true})

	f2, err := os.Open("../../examples/3/dkim.conf")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f2.Close() })

	conf2, err := ParseDKIMConf(f2)
	require.NoError(t, err)
	require.NotNil(t, conf2.Enabled)
	require.False(t, *conf2.Enabled)
}

func TestParseSignHeaders(t *testing.T) {
	raw := "(o)from:(x)sender:(o)reply-to:(o)subject:(x)date:" +
		"(o)to:(o)cc:(x)mime-version:(x)content-type:(x)content-transfer-encoding:" +
		"resent-to:resent-cc:resent-from:resent-sender:resent-message-id:" +
		"(x)in-reply-to:(x)references:list-id:list-help:list-owner:list-unsubscribe:" +
		"list-unsubscribe-post:list-subscribe:list-post:(x)openpgp:(x)autocrypt"

	list := parseSignHeaders(raw)
	require.NotEmpty(t, list)

	require.Contains(t, list, SignHeader{Name: "from", Oversigned: true})
	require.Contains(t, list, SignHeader{Name: "sender", OptionalOversigned: true})
	require.Contains(t, list, SignHeader{Name: "reply-to", Oversigned: true})
	require.Contains(t, list, SignHeader{Name: "subject", Oversigned: true})
	require.Contains(t, list, SignHeader{Name: "date", OptionalOversigned: true})
	require.Contains(t, list, SignHeader{Name: "to", Oversigned: true})
	require.Contains(t, list, SignHeader{Name: "cc", Oversigned: true})
	require.Contains(t, list, SignHeader{Name: "mime-version", OptionalOversigned: true})
	require.Contains(t, list, SignHeader{Name: "content-type", OptionalOversigned: true})
	require.Contains(t, list, SignHeader{Name: "content-transfer-encoding", OptionalOversigned: true})
	require.Contains(t, list, SignHeader{Name: "resent-to"})
	require.Contains(t, list, SignHeader{Name: "resent-cc"})
	require.Contains(t, list, SignHeader{Name: "resent-from"})
	require.Contains(t, list, SignHeader{Name: "resent-sender"})
	require.Contains(t, list, SignHeader{Name: "resent-message-id"})
	require.Contains(t, list, SignHeader{Name: "in-reply-to", OptionalOversigned: true})
	require.Contains(t, list, SignHeader{Name: "references", OptionalOversigned: true})
	require.Contains(t, list, SignHeader{Name: "list-id"})
	require.Contains(t, list, SignHeader{Name: "list-help"})
	require.Contains(t, list, SignHeader{Name: "list-owner"})
	require.Contains(t, list, SignHeader{Name: "list-unsubscribe"})
	require.Contains(t, list, SignHeader{Name: "list-unsubscribe-post"})
	require.Contains(t, list, SignHeader{Name: "list-subscribe"})
	require.Contains(t, list, SignHeader{Name: "list-post"})
	require.Contains(t, list, SignHeader{Name: "openpgp", OptionalOversigned: true})
	require.Contains(t, list, SignHeader{Name: "autocrypt", OptionalOversigned: true})
}

func TestParseDKIMSigningConf(t *testing.T) {
	f, err := os.Open("../../examples/2/dkim_signing.conf")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	conf, err := ParseDKIMSigningConf(f)
	require.NoError(t, err)
	require.NotNil(t, conf.Enabled)
	require.True(t, *conf.Enabled)
	require.Equal(t, "s1", conf.Selector)
	require.Contains(t, conf.Path, "/var/lib/rspamd/dkim/")
	require.Equal(t, "header", conf.UseDomain)
	require.NotEmpty(t, conf.Domain)
	require.Equal(t, "s1", conf.Domain["*"].Selector)

	f2, err := os.Open("../../examples/1/dkim_signing.conf")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f2.Close() })

	conf2, err := ParseDKIMSigningConf(f2)
	require.NoError(t, err)
	require.Equal(t, "/etc/rspamd/local.d/maps.d/signed_domains.map", conf2.PathMap)
	require.Equal(t, "/etc/rspamd/local.d/maps.d/dkim_selectors.map", conf2.SelectorMap)
}

func TestParseDKIMSelectorsMap(t *testing.T) {
	f, err := os.Open("../../examples/3/maps.d/dkim_selectors.map")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	m, err := ParseDKIMSelectorsMap(f)
	require.NoError(t, err)
	require.NotEmpty(t, m)
	require.Equal(t, "mail", m["test.mailer.com"])
	require.Equal(t, "s1", m["mailer.test.com"])
}

func TestParseDKIMPathsMap(t *testing.T) {
	f, err := os.Open("../../examples/1/maps.d/dkim_paths.map")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	m, err := ParseDKIMPathsMap(f)
	require.NoError(t, err)
	require.NotEmpty(t, m)
	require.Equal(t, "/var/lib/rspamd/dkim/s1.sender-01.com.key", m["s1.sender-01.com"])
}

func TestParseSignedDomainsMap(t *testing.T) {
	f, err := os.Open("../../examples/1/maps.d/signed_domains.map")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	m, err := ParseSignedDomainsMap(f)
	require.NoError(t, err)
	require.NotEmpty(t, m)
	require.Equal(t, "/var/lib/rspamd/dkim/c1.dkim.domain.com.key", m["@go.test.com"])
}
