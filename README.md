# smp

Media relay server and Go library implementing the SMP (Simple Media Protocol).

Handles real-time push/pull media streaming with fan-out, GOP caching, seamless publisher reconnection, MP4 recording with S3 upload, and an HTTP control API.

## Protocol

SMP is a lightweight binary protocol for real-time media relay over TCP.

```
Client → Server (handshake):
  "SMP0" (4B) | version (1B) | mode (1B: 0=pull, 1=push) | path length (2B) | path (NB) | session id (16B)

Server → Client (response):
  "SMP0" (4B) | version (1B) | status (1B: 0=ok, 1=bad handshake, 2=occupied)

Data stream (after handshake):
  length (4B) | type (1B: 0x01=header, 0x02=packet, 0x03=keyframe) | payload
```

Subscribers catch up instantly with the cached stream header + current GOP. Seamless reconnection preserves the GOP when the session ID matches.

Supported codecs: H.264, HEVC/H.265, VP8, VP9, AV1, AAC, MP3, Opus.

## Usage

### As a library

```go
import "github.com/yhbsh/smp"

s := smp.New(smp.Config{
    Addr:      ":7777",
    RecordDir: "recordings",

    // Opt in to auto-recording per stream path. Nil (default) disables
    // recording entirely; the /clip endpoint then returns 404.
    ShouldRecord: func(path string) bool {
        return strings.HasPrefix(path, "/live/")
    },
})

mux := http.NewServeMux()
s.Register(mux, "/smp")
go http.ListenAndServe(":7778", mux)

log.Fatal(s.Run())
```

### Push and pull with [FFmpeg](https://github.com/yhbsh/ffmpeg)

Requires the [SMP-enabled FFmpeg fork](https://github.com/yhbsh/ffmpeg) which implements the SMP protocol and format.

```
ffmpeg -re -i input.mp4 -c copy -f smp smp://localhost:7777/live
ffplay -f smp smp://localhost:7777/live
```

## Build

```
make
```
