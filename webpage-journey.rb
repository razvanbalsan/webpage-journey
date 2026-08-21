class WebpageJourney < Formula
  include Language::Python::Virtualenv

  desc "Trace a webpage request end to end and map it onto the OSI model"
  homepage "https://github.com/razvanbalsan/webpage-journey"
  url "https://github.com/razvanbalsan/webpage-journey/archive/refs/tags/v2.2.0.tar.gz"
  sha256 "21f26d30af7a98b396271ca942ef92478fa79a50fa26fb3b0003a7381cea5e43"

  # No LICENSE file exists in this repository at the time this formula was
  # written, so no `license` field is declared here rather than guessing one.

  depends_on "openssl@3"
  depends_on "python@3.13"

  # cryptography (and cffi/pycparser, which exist only to build it) is
  # deliberately not bundled here: it is an optional extra
  # (`pip install webpage-journey[certs]`) that upgrades certificate summaries
  # with key type/bits, signature algorithm, SCT count and CA flag, plus
  # parsing beyond the leaf certificate. Building it from source pulls a
  # Rust toolchain and ~2 GB of build-only dependencies for four fields most
  # installs never look at -- see wj/collect/tls.py. Every other field
  # (subject, issuer, validity, SANs, OCSP) is measured by the stdlib `ssl`
  # module alone.

  resource "dnspython" do
    url "https://files.pythonhosted.org/packages/8c/8b/57666417c0f90f08bcafa776861060426765fdb422eb10212086fb811d26/dnspython-2.8.0.tar.gz"
    sha256 "181d3c6996452cb1189c4046c61599b84a5a86e099562ffde77d26984ff26d0f"
  end

  resource "markdown-it-py" do
    url "https://files.pythonhosted.org/packages/06/ff/7841249c247aa650a76b9ee4bbaeae59370dc8bfd2f6c01f3630c35eb134/markdown_it_py-4.2.0.tar.gz"
    sha256 "04a21681d6fbb623de53f6f364d352309d4094dd4194040a10fd51833e418d49"
  end

  resource "mdurl" do
    url "https://files.pythonhosted.org/packages/d6/54/cfe61301667036ec958cb99bd3efefba235e65cdeb9c84d24a8293ba1d90/mdurl-0.1.2.tar.gz"
    sha256 "bb413d29f5eea38f31dd4754dd7377d4465116fb207585f97bf925588687c1ba"
  end

  resource "pygments" do
    url "https://files.pythonhosted.org/packages/49/2e/ced460408999b33da6b31b0021b0f37d329e202d4169aeb164493778f25b/pygments-2.21.0.tar.gz"
    sha256 "610ca751c9bc2492b38eb9a38a7fbc93edbbb2d7182edaf34e66ae493dee5c8c"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/c0/8f/0722ca900cc807c13a6a0c696dacf35430f72e0ec571c4275d2371fca3e9/rich-15.0.0.tar.gz"
    sha256 "edd07a4824c6b40189fb7ac9bc4c52536e9780fbbfbddf6f1e2502c31b068c36"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    # --osi prints the OSI reference table and exits 0 without touching the
    # network, so it is safe to run in Homebrew's offline test sandbox.
    output = shell_output("#{bin}/webpage-journey --osi")
    assert_match "OSI model", output
    assert_match "Application", output
  end
end
