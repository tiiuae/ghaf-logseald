# SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
{
  buildGoModule,
  lib,
  systemd,
}:
buildGoModule {
  pname = "logseald";
  version = "0.1.0";

  src = ./.;
  vendorHash = null;

  nativeCheckInputs = [ systemd ];

  meta = {
    description = "Clock-independent producer and sealer for Ghaf journal logs";
    license = lib.licenses.asl20;
    mainProgram = "logseald";
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
    ];
  };
}
