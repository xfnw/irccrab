{
  inputs = {
    naersk.url = "github:nix-community/naersk";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, naersk, nixpkgs }: let
    forEachSystem = nixpkgs.lib.genAttrs [
      "aarch64-darwin"
      "aarch64-linux"
      "i686-linux"
      "riscv64-linux"
      "x86_64-linux"
    ];
  in {
    packages = forEachSystem (system: {
      irccrab = let
        naersk' = nixpkgs.legacyPackages.${system}.callPackage naersk { };
      in naersk'.buildPackage {
        src = ./.;
      };
      default = self.packages.${system}.irccrab;
    });

    devShells = forEachSystem (system: {
      default = nixpkgs.legacyPackages.${system}.mkShell {
        packages = with nixpkgs.legacyPackages.${system}; [
          cargo
          clippy
          rustc
          rustfmt
        ];
      };
    });
  };
}
