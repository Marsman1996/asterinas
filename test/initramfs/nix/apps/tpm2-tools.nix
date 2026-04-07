{ lib, symlinkJoin, tpm2-tools }:

symlinkJoin {
  name = "tpm2-tools-app";
  paths = [ tpm2-tools ];
}