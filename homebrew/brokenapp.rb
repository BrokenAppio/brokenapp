# This formula is auto-updated by the release workflow.
# It is release-only until PLACEHOLDER checksums are replaced.
class Brokenapp < Formula
  desc "Map of what your web app actually does, per login role, traced to source"
  homepage "https://github.com/BrokenAppio/brokenapp"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/BrokenAppio/brokenapp/releases/download/v#{version}/brokenapp-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/BrokenAppio/brokenapp/releases/download/v#{version}/brokenapp-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/BrokenAppio/brokenapp/releases/download/v#{version}/brokenapp-v#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER"
    else
      url "https://github.com/BrokenAppio/brokenapp/releases/download/v#{version}/brokenapp-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER"
    end
  end

  def install
    bin_path = Dir["brokenapp", "*/brokenapp"].find { |p| File.file?(p) }
    raise "brokenapp binary not found in archive" unless bin_path
    bin.install bin_path => "brokenapp"
  end

  test do
    assert_match "brokenapp", shell_output("#{bin}/brokenapp --version")
  end
end
