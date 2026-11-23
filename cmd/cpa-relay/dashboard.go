package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"strings"
)

// These exact bytes are embedded in the document and hashed for its HTTP policy.
//
//go:embed dashboard/dashboard.html
var dashboardTemplate string

//go:embed dashboard/dashboard.css
var dashboardCSS string

//go:embed dashboard/dashboard.js
var dashboardJS string

var dashboardHTML = []byte(strings.NewReplacer(
	"__DASHBOARD_CSS__", dashboardCSS,
	"__DASHBOARD_JS__", dashboardJS,
).Replace(dashboardTemplate))

func dashboardHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
}

var dashboardCSP = "default-src 'none'; script-src " + dashboardHash(dashboardJS) +
	"; script-src-attr 'none'; style-src " + dashboardHash(dashboardCSS) +
	"; style-src-attr 'none'; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'; object-src 'none'"
