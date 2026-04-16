# smp

SMP media relay — Go server and library. Real-time push/pull with fan-out, GOP caching, seamless reconnection, MP4 recording, and HTTP control API.

## Build

```
make
```

## Usage

```go
import "github.com/yhbsh/smp"

s := smp.New(smp.Config{Addr: ":7777"})
log.Fatal(s.Run())
```

Push and pull with the [SMP-enabled FFmpeg fork](https://github.com/yhbsh/ffmpeg):

```
ffmpeg -re -i input.mp4 -c copy -f smp smp://localhost:7777/live
ffplay -f smp smp://localhost:7777/live
```
