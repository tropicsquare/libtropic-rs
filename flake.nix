{
  description = "Rust development environment for libtropic-rs";

  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1";
    rust-overlay.url = "https://flakehub.com/f/oxalica/rust-overlay/*";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      overlays = [
        (import rust-overlay)
        (final: prev: {
          rustToolchain = prev.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default);
        })
      ];

      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems =
        f:
        nixpkgs.lib.genAttrs allSystems (
          system:
          f {
            pkgs = import nixpkgs { inherit overlays system; };
          }
        );
    in
    {
      devShells = forAllSystems (
        { pkgs }:
        {
          default = pkgs.mkShell {
            packages =
              (with pkgs; [
                rustToolchain
                pkg-config
                openssl
              ])
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux (with pkgs; [ systemd.dev ])
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin (with pkgs; [ libiconv ]);

            shellHook = ''
              echo "libtropic-rs dev shell"
            '';
          };
        }
      );
    };
}
