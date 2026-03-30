{ lib, pkgs, stdenv, callPackage, testPlatform ? "asterinas", }:
let
  scripts = lib.fileset.toSource {
    root = ./../../src/apps/scripts;
    fileset =
      lib.fileset.fileFilter (file: file.hasExt "sh") ./../../src/apps/scripts;
  };

  commonArgs = { inherit testPlatform; };
  commonBuild = dir: callPackage ./common.nix (commonArgs // { inherit dir; });

  subDirs =
    [ "device" "fs" "hello_world" "io" "ipc" "memory" "process" "security" ];

  tdxAttest = callPackage ./tdx-attest.nix { };

  tpm2Tools = stdenv.mkDerivation {
    pname = "tpm2_tools_app";
    version = "0.1.0";

    dontUnpack = true;

    buildInputs = [ pkgs.tpm2-tools ];

    buildCommand = ''
      mkdir -p $out/tpm2_tools/bin

      ln -s ${pkgs.tpm2-tools}/bin/* $out/tpm2_tools/bin/

      if [ -d ${pkgs.tpm2-tools}/share ]; then
        mkdir -p $out/tpm2_tools/share
        cp -r ${pkgs.tpm2-tools}/share/* $out/tpm2_tools/share/ || true
      fi
    '';
  };

  allPkgs = lib.genAttrs subDirs commonBuild // {
    network = callPackage ./common.nix (commonArgs // {
      dir = "network";
      extraAttrs = { C_FLAGS = "-I${pkgs.libnl.dev}/include/libnl3"; };
      extraBuildInputs = [ pkgs.libnl ];
    });

    tpm2_tools = tpm2Tools;
  } // lib.optionalAttrs (pkgs.hostPlatform.system == "x86_64-linux") {
    intel_tdx = callPackage ./common.nix (commonArgs // {
      dir = "intel_tdx";
      extraAttrs = { TDX_ATTEST_DIR = "${tdxAttest}/QuoteGeneration"; };
    });
  };
in {
  package = stdenv.mkDerivation {
    pname = "apps";
    version = "0.1.0";
    buildCommand = ''
      mkdir -p $out
      cp ${scripts}/* $out

      ${lib.concatMapStringsSep "\n" (name: ''
        ln -sT "${allPkgs.${name}}/${name}" "$out/${name}"
      '') (lib.attrNames allPkgs)}
    '';
  };
}