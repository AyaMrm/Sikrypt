#!/bin/sh
set -eu

config_file=/etc/nginx/conf.d/default.conf

replace_placeholder() {
  placeholder="$1"
  value="$2"
  escaped_value=$(printf '%s' "$value" | sed 's/[\/&]/\\&/g')
  sed -i "s/${placeholder}/${escaped_value}/g" "$config_file"
}

replace_placeholder "__SIKRYPT_API_KEY__" "${SIKRYPT_API_KEY:-changeme}"
replace_placeholder "__SIKRYPT_WS_API_KEY__" "${SIKRYPT_WS_API_KEY:-}"
