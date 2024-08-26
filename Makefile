all:

format:
	@gofmt -w .
	@gosimports -w -local github.com/anchore .
	@go mod tidy

lint-fix: format
