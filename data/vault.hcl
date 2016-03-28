backend "inmem" {
}

disable_mlock = true

listener "tcp" {
  address = "127.0.0.1:8201"
  tls_disable = 1
}

