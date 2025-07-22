# Use official Go image for building
FROM golang:1.23 AS builder

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code, rules, ruleset, and coraza.conf
COPY main.go ./
COPY coraza.conf ./
COPY rules/ ./rules/
COPY ruleset/ ./ruleset/

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o coraza-waf main.go

# Use a minimal base image for the final stage
FROM alpine:latest

# Install ca-certificates for HTTPS support
RUN apk --no-cache add ca-certificates

# Set working directory
WORKDIR /app

# Copy the binary, rules, ruleset, and coraza.conf from the builder stage
COPY --from=builder /app/coraza-waf .
COPY --from=builder /app/coraza.conf .
COPY --from=builder /app/rules/ ./rules/
COPY --from=builder /app/ruleset/ ./ruleset/

# Expose port 8080
EXPOSE 8080

# Command to run the WAF
CMD ["./coraza-waf"]