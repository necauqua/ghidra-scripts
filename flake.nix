{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  outputs = { self, nixpkgs }:
    let
      # meh
      supportedSystems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forEachSupportedSystem = f: nixpkgs.lib.genAttrs supportedSystems (system: f {
        pkgs = import nixpkgs { inherit system; };
      });
    in
    {
      devShells = forEachSupportedSystem ({ pkgs }: {
        default = pkgs.mkShell {
          packages =
            let
              python = pkgs.python311;
              pname = "ghidra-stubs";
              version = "11.2.1.0.4";
              ghidra-stubs = python.pkgs.buildPythonPackage {
                inherit pname version;
                src = pkgs.fetchPypi {
                  inherit pname version;
                  sha256 = "sha256-yS0Aj2AhruiXk+3+HN4HrKOt8lkwiroK8SKXNBKl/WE=";
                };
                doCheck = false;
              };
            in
            [ python ghidra-stubs ];
        };
      });
    };
}
