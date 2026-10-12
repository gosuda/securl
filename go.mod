module securl.click/securl

go 1.26.5

require (
	github.com/go-sql-driver/mysql v1.10.1
	github.com/jackc/pgx/v5 v5.11.0
	github.com/joho/godotenv v1.5.1
	github.com/julienschmidt/httprouter v1.3.0
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10
	github.com/rs/zerolog v1.35.1
	golang.org/x/net v0.61.0
	google.golang.org/protobuf v1.36.12
)

require (
	cel.dev/expr v0.25.3 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/cubicdaiya/gonp v1.0.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/structtag v1.2.0 // indirect
	github.com/google/cel-go v0.31.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-sqlite3 v0.35.6 // indirect
	github.com/ncruces/go-sqlite3-wasm/v6 v6.3.35304 // indirect
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/pganalyze/pg_query_go/v6 v6.2.5 // indirect
	github.com/pingcap/errors v0.11.5-0.20250523034308-74f78ae071ee // indirect
	github.com/pingcap/failpoint v0.0.0-20260811232634-55ac33a48e3b // indirect
	github.com/pingcap/log v1.1.0 // indirect
	github.com/pingcap/tidb/pkg/parser v0.0.0-20261010115534-788ad51619dd // indirect
	github.com/riza-io/grpc-go v0.2.0 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/sqlc-dev/doubleclick v1.0.0 // indirect
	github.com/sqlc-dev/sqlc v1.31.1 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/wasilibs/go-pgquery v0.0.0-20260915022521-81f99195012b // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20250123031827-cd30c44769bb // indirect
	go.uber.org/atomic v1.12.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20261011100332-faecfb24eb49 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261005182115-fad411399dd8 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261005182115-fad411399dd8 // indirect
	google.golang.org/grpc v1.84.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto
	github.com/sqlc-dev/sqlc/cmd/sqlc
	google.golang.org/protobuf/cmd/protoc-gen-go
)

replace github.com/planetscale/vtprotobuf => github.com/planetscale/vtprotobuf v0.6.0
