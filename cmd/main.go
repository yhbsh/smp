package main

import (
	"log"
	"net/http"
	"smp"
)

func main() {
	s := smp.New(smp.Config{
		Addr:      ":7777",
		RecordDir: "recordings",
		LogLevel:  smp.InfoLevel,
		AWS: smp.AWSConfig{
			Bucket:    awsBucket,
			Region:    awsRegion,
			AccessKey: awsAccessKeyID,
			SecretKey: awsSecretKey,
		},
	})

	mux := http.NewServeMux()
	s.Register(mux, "/smp")
	// mux.HandleFunc("/other", otherHandler) — your own routes

	go func() {
		log.Fatal(http.ListenAndServe(":7778", mux))
	}()

	log.Fatal(s.ListenAndServe())
}
