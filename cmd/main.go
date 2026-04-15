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
	mux.Handle("/smp/", http.StripPrefix("/smp", s.Handler()))
	go func() {
		log.Fatal(http.ListenAndServe(":7778", mux))
	}()

	log.Fatal(s.ListenAndServe())
}
