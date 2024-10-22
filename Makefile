REMOTE_PATH := /tmp/main
SSH_ARGS := -p 222
BUILD_DIR := build

check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1$(if $2, ($2))))

build: export CGO_ENABLED=0
build: export GOOS=linux
build:
	mkdir -p $(BUILD_DIR)
	go build -ldflags '-s -w' -trimpath -o $(BUILD_DIR)/main .

sync: build
	$(call check_defined,REMOTE)
	rsync -avz -e "ssh $(SSH_ARGS)" --delete $(BUILD_DIR)/main $(REMOTE):$(REMOTE_PATH)

run: sync
	$(call check_defined,REMOTE)
	ssh $(SSH_ARGS) $(REMOTE) $(REMOTE_PATH)