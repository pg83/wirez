{
  description = "wirez: transparent SOCKS5/HTTP proxifier for Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      inherit (nixpkgs) lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = lib.genAttrs systems;

      nixpkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      # Everything ./build and the end-to-end tests need: the toolchain, the
      # build runner's Python, and the real programs the tests drive through a
      # wirez container (curl with HTTP/3, an HTTP/3 server, sshd, git, real
      # SOCKS5 and HTTP proxies, iperf3, dig, a static busybox).
      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              # hypercorn serves the HTTP/2 streaming test application
              (python3.withPackages (ps: [ ps.hypercorn ]))

              iproute2
              util-linux

              curl
              caddy
              nghttp2
              openssh
              rsync
              git
              iperf3
              dig
              websocat
              socat
              openssl
              pkgsStatic.busybox
              microsocks
              _3proxy
              tinyproxy
              nss_wrapper
            ];

            # Go in the module cache, never a vendor directory.
            GOTOOLCHAIN = "local";
            GOFLAGS = "-buildvcs=false";

            # Lets nix-built sshd and ssh look up the current user on hosts
            # whose users come from NSS modules nix's libc cannot load.
            NSS_WRAPPER_LIB = "${pkgs.nss_wrapper}/lib/libnss_wrapper.so";

            # A statically linked program for the test that shows wirez does
            # not depend on the dynamic loader the way LD_PRELOAD tools do.
            WIREZ_STATIC_BUSYBOX = "${pkgs.pkgsStatic.busybox}/bin/busybox";
          };
        }
      );
    };
}
