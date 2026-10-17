# Excerpt of an OpenBao server config that registers the Kanidm plugin at
# startup. Merge it into your existing config.

plugin_directory = "/openbao/plugins"

plugin "secret" "kanidm" {
  command   = "openbao-plugin-secrets-kanidm"
  version   = "v0.1.0"
  sha256sum = "<sha256 of the binary>"
}
