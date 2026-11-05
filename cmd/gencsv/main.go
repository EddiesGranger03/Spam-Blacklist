package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
)

func main() {
	n := flag.Int("n", 1000000, "số dòng")
	out := flag.String("out", "data.csv", "file đầu ra")
	urlRatio := flag.Float64("url", 0.3, "tỉ lệ dòng URL (còn lại là SĐT)")
	seed := flag.Int64("seed", 1, "seed ngẫu nhiên")
	flag.Parse()

	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()

	rng := rand.New(rand.NewSource(*seed))
	cats := []string{"spam", "scam", "phishing", "malware", "telemarketing"}
	fmt.Fprintln(w, "type,value,match_type,category,risk_score,source,note")

	for i := 0; i < *n; i++ {
		cat, risk := cats[rng.Intn(len(cats))], 30+rng.Intn(70)

		if rng.Float64() < *urlRatio {
			fmt.Fprintf(w, "url,host-%d.example-spam.com,domain,%s,%d,gencsv,\n", i, cat, risk)
		} else {
			fmt.Fprintf(w, "phone,09%08d,,%s,%d,gencsv,\n", rng.Intn(100000000), cat, risk)
		}
	}

	log.Printf("đã ghi %d dòng vào %s", *n, *out)
}
