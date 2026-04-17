# smp

SMP media relay — server and library. Real-time push/pull with fan-out and seamless publisher reconnection.

## Build

```
make
```

## Usage

```go
package main

import (
	"log"

	"github.com/yhbsh/smp"
)

func main() {
	s := smp.New(smp.Config{
		Addr:     ":7777",
		LogLevel: smp.InfoLevel,
	})
	log.Fatal(s.Run())
}
```

Push and pull with the [SMP-enabled FFmpeg fork](https://github.com/yhbsh/ffmpeg):

```
ffmpeg -re -i input.mp4 -c copy -f smp smp://localhost:7777/live
ffplay -f smp smp://localhost:7777/live
```
