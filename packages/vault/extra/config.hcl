disable_mlock = true

backend "zookeeper" {
  address = "127.0.0.1:2181"
  advertise_addr = "VAULT_ADVERTISE_ADDR"
  path = "dcos/vault/default"
  znode_owner = "VAULT_ZNODE_OWNER"
  auth_info = "VAULT_AUTH_INFO"
}

listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = 1
}
