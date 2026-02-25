# dkim.conf

Go parser for Rspamd DKIM configuration files (`dkim.conf` and `dkim_signing.conf`).

## Features
- Parses DKIM module config (`dkim.conf`).
- Parses DKIM signing config (`dkim_signing.conf`) including per-domain rules.
- Parses the `sign_headers` list into structured entries.

## Install

```bash
go get github.com/littlebugger/dkim.conf
```

## Usage

```go
package main

import (
    "fmt"
    "os"

    "github.com/littlebugger/dkim.conf/rspamd/dkim"
)

func main() {
    f, err := os.Open("dkim.conf")
    if err != nil {
        panic(err)
    }
    defer f.Close()

    conf, err := dkim.ParseDKIMConf(f)
    if err != nil {
        panic(err)
    }

    fmt.Printf("enabled=%v sign_headers=%q\n", conf.Enabled, conf.SignHeaders)
}
```

```go
package main

import (
    "os"

    "github.com/littlebugger/dkim.conf/rspamd/dkim"
)

func main() {
    f, err := os.Open("dkim_signing.conf")
    if err != nil {
        panic(err)
    }
    defer f.Close()

    conf, err := dkim.ParseDKIMSigningConf(f)
    if err != nil {
        panic(err)
    }

    _ = conf
}
```

## Tests

```bash
go test ./...
```

## Examples
See `examples/` for sample configs and map files. The examples include file paths only; no private keys are included.

## License
MIT. See `LICENSE`.
