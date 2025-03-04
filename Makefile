all:
	go build -o traffic-anonymization cmd/traffic-anonymization/traffic-anonymization.go 

ring:
	go build -o traffic-anonymization -tags=pfring cmd/traffic-anonymization/traffic-anonymization.go 

docker:
	docker image build --tag traffic-anonymization:linux-amd64 -f build/package/Dockerfile .

decapsulate:
	go build -o decapsulate cmd/decapsulate/decapsulate.go 

clean:
	rm traffic-anonymization