all:
	go build -o traffic-anonymization -tags=pfring cmd/traffic-anonymization/traffic-anonymization.go 

docker:
	docker image build --tag traffuc-anonymization:linux-amd64 -f build/package/Dockerfile .

clean:
	rm traffic-anonymization