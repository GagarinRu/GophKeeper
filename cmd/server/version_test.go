package main

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrintBuildInfo(t *testing.T) {
	buildVersion = "0.1.0"
	buildDate = "2026-08-16"
	buildCommit = "abc123"
	defer func() {
		buildVersion = ""
		buildDate = ""
		buildCommit = ""
	}()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	printBuildInfo()

	require.NoError(t, w.Close())
	os.Stdout = old

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	require.Contains(t, buf.String(), "Build version: 0.1.0")
	require.Contains(t, buf.String(), "Build date: 2026-08-16")
	require.Contains(t, buf.String(), "Build commit: abc123")
}

func TestValueOrNA(t *testing.T) {
	require.Equal(t, "N/A", valueOrNA(""))
	require.Equal(t, "v1", valueOrNA("v1"))
}
