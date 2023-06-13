test: check

check: lint
	go test -v

lint:
	gofmt  -w=true -s=true -l=true ./
	golint ./...
	go vet ./...



