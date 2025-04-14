.PHONY: test
test:
	env $$(cat .env | xargs) go test -v -race ./app/handlers

.PHONY: bench
bench:
	hey -n 100000 -c 200 -m POST -d '{"email":"test@mail.com", "password":"password123"}' -H "Content-Type: application/json" http://localhost:8080/register
