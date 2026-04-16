# smp

SMP media relay — Go server and library. Real-time push/pull with fan-out, GOP caching, seamless reconnection, MP4 recording, and HTTP control API.

## Build

```
make
```

## Usage

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/yhbsh/smp"
)

func main() {
	s := smp.New(smp.Config{
		Addr:     ":7777",
		LogLevel: smp.InfoLevel,
		AWS: smp.AWSConfig{
			Bucket:    os.Getenv("AWS_BUCKET"),
			Region:    os.Getenv("AWS_REGION"),
			AccessKey: os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		},
		Record: &smp.RecordConfig{Dir: "recordings"},
	})

	mux := http.NewServeMux()
	s.Register(mux, "/smp")
	go func() { log.Fatal(http.ListenAndServe(":7778", mux)) }()

	log.Fatal(s.Run())
}
```

Push and pull with the [SMP-enabled FFmpeg fork](https://github.com/yhbsh/ffmpeg):

```
ffmpeg -re -i input.mp4 -c copy -f smp smp://localhost:7777/live
ffplay -f smp smp://localhost:7777/live
```
