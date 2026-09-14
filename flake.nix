# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{
  description = "Clock-independent log sealing for Ghaf";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      eachSystem = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
      mkPackage = pkgs: pkgs.callPackage ./package.nix { };
    in
    {
      lib.mkPackage = { pkgs }: mkPackage pkgs;
      overlays.default = final: _prev: { logseald = mkPackage final; };
      packages = eachSystem (
        system:
        let
          package = mkPackage (pkgsFor system);
        in
        {
          default = package;
          logseald = package;
        }
      );
      checks = eachSystem (system: {
        logseald = self.packages.${system}.logseald;
      });
      devShells = eachSystem (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.reuse
              pkgs.nixfmt-rfc-style
              pkgs.treefmt
              pkgs.git
            ];
            GOMAXPROCS = "2";
            GOMEMLIMIT = "512MiB";
          };
        }
      );
      formatter = eachSystem (
        system:
        let
          pkgs = pkgsFor system;
        in
        pkgs.writeShellApplication {
          name = "logseald-format";
          runtimeInputs = [
            pkgs.treefmt
            pkgs.nixfmt-rfc-style
            pkgs.go
          ];
          text = ''exec treefmt "$@"'';
        }
      );
    };
}
