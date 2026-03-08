FROM golang:alpine

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum* ./
RUN go mod tidy
RUN go mod download || true

COPY . .

EXPOSE 8080

CMD ["go", "run", "main.go"]
