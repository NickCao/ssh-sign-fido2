{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let pkgs = import nixpkgs { inherit system; }; in
      with pkgs; {
        devShell = mkShell {
          nativeBuildInputs = [
            cargo
            rustc
            rust-analyzer
            rustfmt
            clippy
            pkg-config
            rustPlatform.bindgenHook
          ];
          buildInputs = [
            udev
            openssl
          ];
        };
      });
}
