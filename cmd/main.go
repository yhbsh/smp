package main

import (
	"log"
	"smp"
)

func main() {
	s := smp.New(smp.Config{
		Addr:      ":7777",
		APIAddr:   ":7778",
		RecordDir: "recordings",
		LogLevel:  smp.InfoLevel,
		AWS: smp.AWSConfig{
			Bucket:    awsBucket,
			Region:    awsRegion,
			AccessKey: awsAccessKeyID,
			SecretKey: awsSecretKey,
		},
	})
	log.Fatal(s.ListenAndServe())
}
