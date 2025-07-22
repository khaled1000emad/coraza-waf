package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

func main() {
	// Initialize Coraza WAF
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(func(rule types.MatchedRule) {
				fmt.Printf("WAF Triggered: Rule ID %d, Message: %s, Data: %s, URI: %s\n",
					rule.Rule().ID(), rule.Message(), rule.Data(), rule.URI())
			}).
			// First, load the CRS setup file
			WithDirectivesFromFile("/app/ruleset/crs-setup.conf").
			// Then, load all the individual CRS rule files
			WithDirectivesFromFile("/app/rules/REQUEST-901-INITIALIZATION.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-905-COMMON-EXCEPTIONS.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-921-PROTOCOL-ATTACK.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf").
			WithDirectivesFromFile("/app/rules/REQUEST-949-BLOCKING-EVALUATION.conf").
			WithDirectivesFromFile("/app/rules/RESPONSE-950-DATA-LEAKAGES.conf").
			WithDirectivesFromFile("/app/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf").
			WithDirectivesFromFile("/app/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf").
			WithDirectivesFromFile("/app/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf").
			WithDirectivesFromFile("/app/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf").
			WithDirectivesFromFile("/app/rules/RESPONSE-959-BLOCKING-EVALUATION.conf").
			WithDirectivesFromFile("/app/rules/RESPONSE-980-CORRELATION.conf").
			// Finally, load your custom coraza.conf to apply rule removals or custom rules
			WithDirectivesFromFile("coraza.conf"), // <-- Move this line to the END of the chain
	)
	if err != nil {
		fmt.Printf("Failed to initialize WAF: %v\n", err)
		return
	}

	// Set up reverse proxy to Juice Shop
	juiceShopURL, err := url.Parse(os.Getenv("JUICE_SHOP_URL"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse JUICE_SHOP_URL: %v\n", err)
		os.Exit(1)
	}
	proxy := httputil.NewSingleHostReverseProxy(juiceShopURL)

	// Create HTTP handler with Coraza middleware
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tx := waf.NewTransaction()
		defer tx.Close()

		// Process URI (Phase 1)
		tx.ProcessURI(r.URL.String(), r.Method, r.Proto)

		// Process request headers (Phase 2)
		for k, values := range r.Header {
			for _, v := range values {
				tx.AddRequestHeader(k, v)
			}
		}
		if err := tx.ProcessRequestHeaders(); err != nil {
			http.Error(w, "403 Forbidden - Attack Detected: Malicious headers", http.StatusForbidden)
			fmt.Printf("Request blocked (headers): %v\n", err)
			return
		}

		// Process request body (Phase 3) - THIS IS THE KEY FIX
		if r.Body != nil {
			// Read the body
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "400 Bad Request - Unable to read body", http.StatusBadRequest)
				fmt.Printf("Error reading request body: %v\n", err)
				return
			}

			// Restore the body for the proxy to use
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			// Write body data to transaction for analysis
			if len(bodyBytes) > 0 {
				_, _, err = tx.WriteRequestBody(bodyBytes)
				if err != nil {
					http.Error(w, "403 Forbidden - Attack Detected: Malicious content", http.StatusForbidden)
					fmt.Printf("Request blocked (body write): %v\n", err)
					return
				}
			}

			// Process the request body
			_, err = tx.ProcessRequestBody()
			if err != nil {
				http.Error(w, "403 Forbidden - Attack Detected: Malicious content", http.StatusForbidden)
				fmt.Printf("Request blocked (body process): %v\n", err)
				return
			}
		}

		// Check if any critical rule was triggered
		matchedRules := tx.MatchedRules()
		blocked := false
		
		for _, rule := range matchedRules {
			severity := rule.Rule().Severity()
			ruleID := rule.Rule().ID()
			
			// Only log rules with severity >= 2 (WARNING and above) to reduce noise
			if severity >= 2 {
				fmt.Printf("Rule triggered: ID=%d, Severity=%d, Message=%s, Data=%s\n", 
					ruleID, severity, rule.Message(), rule.Data())
			}
			
			// Block for security rules with severity >= 2 (WARNING and above)
			// This includes SQLi, XSS, LFI, RFI, RCE, etc.
			if severity >= 2 {
				blocked = true
				fmt.Printf("Request BLOCKED: Rule %d (severity %d) triggered: %s\n", 
					ruleID, severity, rule.Message())
			}
		}
		
		if blocked {
			http.Error(w, "403 Forbidden - Attack Detected: Security rule violation", http.StatusForbidden)
			return
		}

		// Forward request to Juice Shop if not blocked
		proxy.ServeHTTP(w, r)
	})

	// Start the server
	fmt.Println("Starting WAF server on :8080")
	fmt.Println("Proxying to Juice Shop at http://127.0.0.1:3000")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		fmt.Printf("Server failed: %v\n", err)
	}
}
// package main

// import (
// 	"fmt"
// 	"net/http"
// 	"net/http/httputil"
// 	"net/url"

// 	"github.com/corazawaf/coraza/v3"
// 	"github.com/corazawaf/coraza/v3/types"
// )

// func main() {
// 	// Initialize Coraza WAF
// 	waf, err := coraza.NewWAF(
// 		coraza.NewWAFConfig().
// 			WithErrorCallback(func(rule types.MatchedRule) {
// 				fmt.Printf("WAF Triggered: Rule ID %d, Message: %s, Data: %s, URI: %s\n",
// 					rule.Rule().ID(), rule.Message(), rule.Data(), rule.URI())
// 			}).
// 			// First, load the CRS setup file
// 			WithDirectivesFromFile("ruleset/crs-setup.conf").
// 			// Then, load all the individual CRS rule files
// 			WithDirectivesFromFile("/app/rules/REQUEST-901-INITIALIZATION.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-905-COMMON-EXCEPTIONS.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-921-PROTOCOL-ATTACK.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf").
// 			WithDirectivesFromFile("/app/rules/REQUEST-949-BLOCKING-EVALUATION.conf").
// 			WithDirectivesFromFile("/app/rules/RESPONSE-950-DATA-LEAKAGES.conf").
// 			WithDirectivesFromFile("/app/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf").
// 			WithDirectivesFromFile("/app/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf").
// 			WithDirectivesFromFile("/app/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf").
// 			WithDirectivesFromFile("/app/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf").
// 			WithDirectivesFromFile("/app/rules/RESPONSE-959-BLOCKING-EVALUATION.conf").
// 			WithDirectivesFromFile("/app/rules/RESPONSE-980-CORRELATION.conf").
// 			// Finally, load your custom coraza.conf to apply rule removals or custom rules
// 			WithDirectivesFromFile("coraza.conf"), // <-- Move this line to the END of the chain
// 	)
// 	if err != nil {
// 		fmt.Printf("Failed to initialize WAF: %v\n", err)
// 		return
// 	}

// 	// Set up reverse proxy to Juice Shop
// 	juiceShopURL, err := url.Parse("http://127.0.0.1:3000")
// 	if err != nil {
// 		fmt.Printf("Failed to parse Juice Shop URL: %v\n", err)
// 		return
// 	}
// 	proxy := httputil.NewSingleHostReverseProxy(juiceShopURL)

// 	// Create HTTP handler with Coraza middleware
// 	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		tx := waf.NewTransaction()
// 		defer tx.Close()

// 		// Process URI (Phase 1)
// 		tx.ProcessURI(r.URL.String(), r.Method, r.Proto)

// 		// Process request headers (Phase 2)
// 		for k, values := range r.Header {
// 			for _, v := range values {
// 				tx.AddRequestHeader(k, v)
// 			}
// 		}
// 		if err := tx.ProcessRequestHeaders(); err != nil {
// 			http.Error(w, "403 Forbidden - Attack Detected: Malicious headers", http.StatusForbidden)
// 			fmt.Printf("Request blocked (headers): %v\n", err)
// 			return
// 		}

// 		// Process request body (Phase 3)
// 		if r.Body != nil {
// 			_, err := tx.ProcessRequestBody()
// 			if err != nil {
// 				http.Error(w, "403 Forbidden - Attack Detected: Malicious content", http.StatusForbidden)
// 				fmt.Printf("Request blocked (body): %v\n", err)
// 				return
// 			}
// 		}

// 		// Check if any critical rule was triggered
// 		matchedRules := tx.MatchedRules()
// 		for _, rule := range matchedRules {
// 			// Block only for high-severity rules (e.g., LFI, SQLi, XSS)
// 			switch rule.Rule().ID() {
// 			case 930100, 931100, 932100, 941100, 942100, 943100: // LFI, RFI, RCE, XSS, SQLi, Session Fixation
// 				http.Error(w, "403 Forbidden - Attack Detected: Critical rule violation", http.StatusForbidden)
// 				fmt.Printf("Request blocked: Critical rule %d triggered: %s\n", rule.Rule().ID(), rule.Message())
// 				return
// 			}
// 		}

// 		// Forward request to Juice Shop if not blocked
// 		proxy.ServeHTTP(w, r)
// 	})

// 	// Start the server
// 	fmt.Println("Starting WAF server on :8080")
// 	if err := http.ListenAndServe(":8080", handler); err != nil {
// 		fmt.Printf("Server failed: %v\n", err)
// 	}
// }
