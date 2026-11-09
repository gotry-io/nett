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

  def caveats
    <<~EOS
      To join the mesh as a native member (root is needed for the utun interface):
        sudo nett mesh keys --dir "/Library/Application Support/nett"
        # add the printed line to the site description, and put this node's desired.json there
        sudo nett mesh install
      After every `brew upgrade nett`, run `sudo nett mesh install` again: the service runs a root-only copy.

      以原生成员加入组网（创建 utun 需要 root）：运行上面的命令；把输出的一行写进站点描述，把这个节点的
      desired.json 放进同一个目录。每次 `brew upgrade nett` 之后再运行一次 `sudo nett mesh install`：
      服务运行的是只有 root 能改的副本。
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/nett --version")
  end
end
