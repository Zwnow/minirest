.PHONY: test
test:
	env $$(cat .env | xargs) go test -v -race ./app/handlers
