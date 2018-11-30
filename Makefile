PROJECT = libdecaf
PROJECT_DESCRIPTION = libdecaf NIF for ECDH (X25519, X448), EdDSA (Ed25519, Ed25519ph, Ed448, Ed448ph), curve25519, curve448, spongerng
PROJECT_VERSION = 0.0.4

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-test

DOCKER_OTP_VERSION ?= 21.1.3

docker-build::
	$(gen_verbose) docker build \
		-t docker-otp-${DOCKER_OTP_VERSION} \
		-f priv/Dockerfile \
		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
		priv

docker-load::
	$(gen_verbose) docker load \
		-i "docker-otp-${DOCKER_OTP_VERSION}/image.tar"

docker-save::
	$(verbose) mkdir -p "docker-otp-${DOCKER_OTP_VERSION}"
	$(gen_verbose) docker save \
		-o "docker-otp-${DOCKER_OTP_VERSION}/image.tar" \
		docker-otp-${DOCKER_OTP_VERSION}

docker-setup::
	$(verbose) if [ -f "docker-otp-${DOCKER_OTP_VERSION}/image.tar" ]; then \
		$(MAKE) docker-load; \
	else \
		$(MAKE) docker-build; \
		$(MAKE) docker-save; \
	fi

docker-test::
	$(gen_verbose) docker run \
		-v "$(shell pwd)":"/build/libdecaf" "docker-otp-${DOCKER_OTP_VERSION}" \
		sh -c 'cd libdecaf && make tests'
