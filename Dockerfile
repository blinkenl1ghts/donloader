FROM golang:1.17

WORKDIR /go/src/donloader
COPY . .

RUN apt update
RUN apt install -y upx
RUN go install mvdan.cc/garble@latest
RUN GO111MODULE=off go get -u golang.org/x/sys/...
RUN GOOS=windows GO111MODULE=on go get -u github.com/C-Sto/BananaPhone
RUN GOOS=windows GO111MODULE=on go get -u github.com/Binject/debug
RUN GOOS=windows GO111MODULE=off go get -u github.com/C-Sto/BananaPhone; exit 0
RUN GOOS=windows GO111MODULE=off go get -u github.com/Binject/debug; exit 0
RUN GO111MODULE=off go get -u github.com/awgh/rawreader
RUN go install .

WORKDIR /data
ENTRYPOINT ["donloader"]
