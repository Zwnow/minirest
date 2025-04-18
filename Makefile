.PHONY: test
test:
	env $$(cat .env | xargs) go test -v -race ./app/handlers

.PHONY: test_registration
test_registration:
	env $$(cat .env | xargs) go test -run=TestRegisterHandler ./...

.PHONY: bench
bench:
	hey -n 100000 -c 200 -m POST -d '{"email":"test@mail.com", "password":"password123"}' -H "Content-Type: application/json" http://localhost:8080/register

.PHONY: cleanup_docker
cleanup_docker:
	docker rm -v -f $$(docker ps -qa)
