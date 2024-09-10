alias ll="ls -al"

export LD_LIBRARY_PATH=/usr/local/lib
export CONFIG_PATH=/etc/config/config.yaml
export ENV_PATH=/etc/env/config.yaml
export DATA_PATH=/nbroutes/share
export RUST_LOG=debug
export RUST_BACKTRACE=1

service redis-server start