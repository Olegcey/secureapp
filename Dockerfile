FROM golang:latest AS builder
RUN mkdir /app 
ADD . /app/ 
WORKDIR /app 
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM scratch
COPY --from=builder /app/. /app/.
WORKDIR /app
CMD ["/app/main"]
