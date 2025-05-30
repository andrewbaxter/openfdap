{ pkgs, lib }:
let
  naersk =
    pkgs.callPackage
      (fetchTarball "https://github.com/nix-community/naersk/archive/378614f37a6bee5a3f2ef4f825a73d948d3ae921.zip")
      { };
  stageWorkspace =
    name: files:
    let
      linkLines = lib.strings.concatStringsSep "\n" (
        map (f: ''
          filename=$(${pkgs.coreutils}/bin/basename ${f} | ${pkgs.gnused}/bin/sed -e 's/[^-]*-//')
          ${pkgs.coreutils}/bin/cp -r ${f} $filename
        '') files
      );
    in
    pkgs.runCommand "stage-rust-workspace-${name}" { } ''
      set -xeu -o pipefail
      ${pkgs.coreutils}/bin/mkdir $out
      cd $out
      ${linkLines}
    '';
  ws = stageWorkspace "openfdap" [
    ./fdap
    ./openfdap
    ./openfdap/Cargo.lock
    ./nixbuild/Cargo.toml
  ];
in
naersk.buildPackage {
  src = ws;
}
