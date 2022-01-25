PROJECT = libdecaf
PROJECT_DESCRIPTION = libdecaf NIF for ECDH (X25519, X448), EdDSA (Ed25519, Ed25519ctx, Ed25519ph, Ed448, Ed448ph), curve25519, curve448, spongerng
PROJECT_VERSION = 2.0.0

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-shell docker-test

DOCKER_OTP_VERSION ?= 24.2.1-alpine-3.15.0

docker-build::
	$(gen_verbose) docker build \
		--tag ${PROJECT}-${DOCKER_OTP_VERSION} \
		--file test/Dockerfile \
		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
		test

docker-load::
	$(gen_verbose) docker load \
		-i "${PROJECT}-${DOCKER_OTP_VERSION}/image.tar"

docker-save::
	$(verbose) mkdir -p "${PROJECT}-${DOCKER_OTP_VERSION}"
	$(gen_verbose) docker save \
		-o "${PROJECT}-${DOCKER_OTP_VERSION}/image.tar" \
		${PROJECT}-${DOCKER_OTP_VERSION}

docker-setup::
	$(verbose) if [ -f "${PROJECT}-${DOCKER_OTP_VERSION}/image.tar" ]; then \
		$(MAKE) docker-load; \
	else \
		$(MAKE) docker-build; \
		$(MAKE) docker-save; \
	fi

docker-shell::
	$(verbose) docker run \
		-v "$(shell pwd)":"/build/${PROJECT}" --rm -it "${PROJECT}-${DOCKER_OTP_VERSION}" \
		/bin/bash -l

docker-test::
	$(gen_verbose) docker run \
		-v "$(shell pwd)":"/build/${PROJECT}" "${PROJECT}-${DOCKER_OTP_VERSION}" \
		/bin/bash -c 'cd ${PROJECT} && make ct'
