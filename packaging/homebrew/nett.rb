# 由 gotry-io/nett 的发布工作流按 packaging/homebrew/nett.rb 生成（design/release.md 第 3、4 节），填入版本号与
# 两个压缩包的 sha256，推送到 gotry-io/homebrew-tap。改配方只改 nett 仓库中的模板，不在 tap 中手改。
class Nett < Formula
  desc "Self-hosted mesh network for your own machines"
  homepage "https://github.com/gotry-io/nett"
  version "@VERSION@"
  license any_of: ["MIT", "Apache-2.0"]

  on_arm do
    url "https://github.com/gotry-io/nett/releases/download/v@VERSION@/nett-@VERSION@-aarch64-apple-darwin.tar.gz"
    sha256 "@SHA256_AARCH64@"
  end
  on_intel do
    url "https://github.com/gotry-io/nett/releases/download/v@VERSION@/nett-@VERSION@-x86_64-apple-darwin.tar.gz"
    sha256 "@SHA256_X86_64@"
  end

  depends_on :macos

  def install
    bin.install "nett"
  end

  # 只用英文，与 nett 命令的输出一致（architecture.md 第 14.3 节）
  def caveats
    <<~EOS
      To join the mesh as a native member (root is needed for the utun interface):
        sudo nett install                          # prints this machine's keys
        nett site add <name> --keys "<that line>"  # in the site, ~/.config/nett by default
        sudo nett install                          # finds this machine's desired state and starts the service
      Run `sudo nett install` again after the site changes and after `brew upgrade nett`.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/nett --version")
  end
end
