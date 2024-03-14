package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const converterBin = "/opt/overlaybd/snapshotter/convertor"

type Body struct {
	Repo   string `json:"repo"`
	Input  string `json:"input"`
	Output string `json:"output"`
	Creds  string `json:"creds"`
}

func overlaybdImageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body Body
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		log.Infof("exec: %s -r %s -i %s -o %s -u <hidden>", converterBin, body.Repo, body.Input, body.Output)

		cmd := exec.Command(converterBin, "-r", body.Repo, "-i", body.Input, "-o", body.Output, "-u", body.Creds)

		var output bytes.Buffer
		cmd.Stdout = io.MultiWriter(os.Stdout, &output)
		cmd.Stderr = io.MultiWriter(os.Stderr, &output)
		if err := cmd.Run(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write(output.Bytes())
			return
		}

		outStr := strings.TrimSpace(output.String())
		lines := strings.Split(outStr, "\n")
		log.Info(lines)
		hashLine := lines[len(lines)-2]
		log.Info(hashLine)

		hashRegex := regexp.MustCompile(`sha256:[a-f0-9]{64}`)
		hash := hashRegex.FindString(hashLine)

		if hash == "" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("could not find image hash"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(hash))
	}
}
