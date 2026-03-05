# docker-bake.hcl
# Build configuration for op-rbuilder Docker images

variable "REGISTRY" {
  default = "us-docker.pkg.dev"
}

variable "REPOSITORY" {
  default = "oplabs-tools-artifacts/images"
}

variable "IMAGE_TAGS" {
  default = "latest"
}

variable "GIT_COMMIT" {
  default = "unknown"
}

variable "GIT_DATE" {
  default = "0"
}

variable "GIT_VERSION" {
  default = "untagged"
}

variable "PLATFORMS" {
  default = "linux/amd64"
}

# Helper function to generate all tag combinations
function "tags" {
  params = [name]
  result = [for tag in split(",", IMAGE_TAGS) : "${REGISTRY}/${REPOSITORY}/${name}:${tag}"]
}

# op-rbuilder standard runtime target
target "op-rbuilder" {
  context    = "."
  dockerfile = "Dockerfile"
  target     = "rbuilder-runtime"
  tags       = tags("op-rbuilder")
  platforms  = split(",", PLATFORMS)
  args = {
    GIT_COMMIT   = GIT_COMMIT
    GIT_DATE     = GIT_DATE
    GIT_VERSION  = GIT_VERSION
    RBUILDER_BIN = "op-rbuilder"
  }
  labels = {
    "org.opencontainers.image.source"   = "https://github.com/flashbots/op-rbuilder"
    "org.opencontainers.image.revision" = GIT_COMMIT
    "org.opencontainers.image.version"  = GIT_VERSION
  }
}

# tdx-quote-provider target
target "tdx-quote-provider" {
  context    = "."
  dockerfile = "crates/tdx-quote-provider/Dockerfile"
  tags       = tags("tdx-quote-provider")
  platforms  = split(",", PLATFORMS)
  args = {
    BINARY = "tdx-quote-provider"
  }
  labels = {
    "org.opencontainers.image.source"   = "https://github.com/flashbots/op-rbuilder"
    "org.opencontainers.image.revision" = GIT_COMMIT
    "org.opencontainers.image.version"  = GIT_VERSION
  }
}

# Group for building all targets
group "default" {
  targets = ["op-rbuilder", "tdx-quote-provider"]
}
